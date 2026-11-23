// Package fault injects delays, aborts, and connection resets into a
// share of a route's requests, for resilience testing. Rules come from a
// route's fault_injection config or from the admin API; a Registry holds
// the ones in force, and for each request the router asks it for a
// Decision that the proxy then applies to the request's backend
// attempts. See docs/adr/0011-fault-injection.md for the safety design.
package fault

import (
	"context"
	"math/rand/v2"
	"strings"
	"time"

	"gatekeeper/internal/config"
)

// Fault types, as they appear in metrics labels, logs, and traces.
const (
	TypeDelay = "delay"
	TypeAbort = "abort"
	TypeReset = "reset"
)

// Rule sources: a route's config, or the admin API.
const (
	SourceConfig  = "config"
	SourceRuntime = "runtime"
)

// Rule is one compiled fault rule for one route.
type Rule struct {
	// ID identifies the rule in the admin API, logs, and traces.
	ID string
	// Route is the label of the route the rule applies to.
	Route string
	// Source is SourceConfig or SourceRuntime.
	Source string
	// Config is the rule as written, for the admin API and to tell
	// whether a reload changed it.
	Config config.RouteFaultConfig
	// Start is when the rule came into force; Expires, when it stops (the
	// zero time when it never does).
	Start, Expires time.Time

	match *matcher
}

// NewRule compiles cfg, already validated, into a rule for route that
// came into force at start.
func NewRule(id, route, source string, cfg config.RouteFaultConfig, start time.Time) *Rule {
	r := &Rule{ID: id, Route: route, Source: source, Config: cfg, Start: start, match: newMatcher(cfg.Match)}
	if d := cfg.MaxDuration.Duration; d > 0 {
		r.Expires = start.Add(d)
	}
	return r
}

// Sampler returns a uniformly random number in [0, 1). Tests substitute
// a predictable one.
type Sampler func() float64

// DefaultSampler is math/rand's, safe for concurrent use.
func DefaultSampler() float64 { return rand.Float64() }

// hit reports whether a request falls in the percentage pct of requests.
func hit(sample Sampler, pct float64) bool {
	return pct > 0 && sample()*100 < pct
}

// Matches reports whether req meets the rule's request-level targeting.
func (r *Rule) Matches(req Request) bool { return r.match.matches(req) }

// decide rolls each of the rule's faults for one request, independently
// of one another, and returns what to inject; ok is false when nothing
// is. A connection reset takes precedence over an abort; a delay is
// applied before either.
func (r *Rule) decide(sample Sampler) (d Decision, ok bool) {
	cfg := r.Config
	d = Decision{
		Rule: r.ID, Route: r.Route, CountsAsBackendFailure: cfg.CountsAsBackendFailure(),
		backends: r.match.backends,
	}
	if dl := cfg.Delay; dl != nil && hit(sample, dl.Percentage) {
		d.Delay = delayFor(dl, sample)
	}
	if rs := cfg.ConnectionReset; rs != nil && hit(sample, rs.Percentage) {
		d.Reset = true
	} else if ab := cfg.Abort; ab != nil && hit(sample, ab.Percentage) {
		d.AbortStatus = ab.Status
	}
	return d, !d.Empty()
}

// delayFor is a delay for one request: the fixed one, or a random one
// between min and max.
func delayFor(dl *config.FaultDelay, sample Sampler) time.Duration {
	if dl.Fixed.Duration > 0 {
		return dl.Fixed.Duration
	}
	lo, hi := dl.Min.Duration, dl.Max.Duration
	return lo + time.Duration(sample()*float64(hi-lo))
}

// Decision is what to inject into one request: for each of its backend
// attempts, a delay, then an abort or a connection reset.
type Decision struct {
	// Rule is the ID of the rule that decided it, and Route its route.
	Rule, Route string
	// Delay holds each attempt back this long (0: no delay).
	Delay time.Duration
	// AbortStatus answers each attempt with this status (0: no abort).
	AbortStatus int
	// Reset fails each attempt and finally resets the client connection.
	Reset bool
	// CountsAsBackendFailure makes the faults count against the backend:
	// retried, and reported to its circuit breaker and passive health.
	CountsAsBackendFailure bool

	// backends limits the decision to attempts on these backends, by
	// lb.Label; nil means every backend.
	backends map[string]bool
}

// AppliesTo reports whether the decision applies to an attempt on the
// backend labelled backend (see lb.Backend.Label). A retry that lands on
// a backend the rule doesn't target goes through untouched.
func (d Decision) AppliesTo(backend string) bool {
	return d.backends == nil || d.backends[backend]
}

// Empty reports whether the decision injects nothing.
func (d Decision) Empty() bool {
	return d.Delay <= 0 && d.AbortStatus == 0 && !d.Reset
}

// Types lists the faults the decision injects, in the order they're
// applied: "delay", then "abort" or "reset".
func (d Decision) Types() []string {
	var out []string
	if d.Delay > 0 {
		out = append(out, TypeDelay)
	}
	switch {
	case d.Reset:
		out = append(out, TypeReset)
	case d.AbortStatus != 0:
		out = append(out, TypeAbort)
	}
	return out
}

// Label is Types joined with commas ("delay", "abort", "delay,reset"),
// for log lines and trace attributes.
func (d Decision) Label() string { return strings.Join(d.Types(), ",") }

type decisionKey struct{}

// WithDecision returns ctx carrying d, for the proxy's retry transport to
// apply to each backend attempt.
func WithDecision(ctx context.Context, d Decision) context.Context {
	return context.WithValue(ctx, decisionKey{}, d)
}

// FromContext returns the decision ctx carries, if any.
func FromContext(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(decisionKey{}).(Decision)
	return d, ok
}
