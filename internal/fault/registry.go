package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/config"
)

// Registry holds the fault rules in force and decides, per request,
// whether to inject anything. It outlives config reloads, so a config
// rule left unchanged by a reload keeps its start time (and so its
// max_duration countdown).
//
// Nothing is ever injected while the kill switch
// (fault_injection.global_enabled) is off. While it's off, or no rule is
// in force, Decide costs one atomic load.
type Registry struct {
	sample Sampler
	now    func() time.Time
	events func(Event)

	mu      sync.Mutex
	enabled bool
	config  map[string]*Rule // config rules, by route label
	exempt  exemptions

	// expiry fires when the next rule in force expires; reported holds
	// the rules whose expiry has been reported, so each is reported once.
	expiry   *time.Timer
	reported map[*Rule]bool

	// snap is what Decide reads; nil whenever nothing can be injected.
	snap atomic.Pointer[snapshot]
}

// EventKind says what happened to a rule.
type EventKind string

// Event kinds.
const (
	// EventExpired: the rule's max_duration (or TTL) ran out.
	EventExpired EventKind = "expired"
)

// Event reports a change to a rule that happened on its own, for the
// gateway to log.
type Event struct {
	Kind EventKind
	Rule *Rule
}

// snapshot is the rules in force, by route label, in the order they're
// tried, and the requests that are never faulted.
type snapshot struct {
	byRoute map[string][]*Rule
	exempt  exemptions
}

// Option customises a Registry.
type Option func(*Registry)

// WithSampler makes the registry roll its percentages with s instead of
// math/rand.
func WithSampler(s Sampler) Option { return func(g *Registry) { g.sample = s } }

// WithClock makes the registry tell the time with now.
func WithClock(now func() time.Time) Option { return func(g *Registry) { g.now = now } }

// WithEvents has the registry report rules expiring to fn. It's called
// without the registry's lock held.
func WithEvents(fn func(Event)) Option { return func(g *Registry) { g.events = fn } }

// NewRegistry returns a registry with no rules and the kill switch off.
func NewRegistry(opts ...Option) *Registry {
	g := &Registry{sample: DefaultSampler, now: time.Now, config: map[string]*Rule{}, reported: map[*Rule]bool{}}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// ConfigRuleID is the ID of the config rule on the route labelled label:
// "config-" and the first 12 hex characters of the label's SHA-256, the
// same route ID the admin API uses. Stable, and URL-safe unlike "/api".
func ConfigRuleID(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "config-" + hex.EncodeToString(sum[:])[:12]
}

// Configure applies a config: the kill switch, the exempt paths, and
// every route's enabled fault_injection section as a config rule. A rule
// a reload leaves unchanged keeps its start time; a changed one starts
// over.
func (g *Registry) Configure(cfg *config.Config) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.enabled = cfg.FaultInjection.GlobalEnabled
	g.exempt = newExemptions(cfg.Metrics.Path, cfg.FaultInjection.ExemptPaths)
	now := g.now()
	rules := map[string]*Rule{}
	for _, rt := range cfg.Routes {
		f := rt.FaultInjection
		if f == nil || !f.Enabled {
			continue
		}
		label := rt.Label()
		start := now
		if prev, ok := g.config[label]; ok && reflect.DeepEqual(prev.Config, *f) {
			start = prev.Start
		}
		rules[label] = NewRule(ConfigRuleID(label), label, SourceConfig, *f, start)
	}
	g.config = rules
	g.rebuild()
	g.forget()
}

// rebuild recomputes the snapshot Decide reads, leaving out expired
// rules, and sets the timer for the next expiry. Called with mu held.
func (g *Registry) rebuild() {
	if g.expiry != nil {
		g.expiry.Stop()
		g.expiry = nil
	}
	now := g.now()
	s := &snapshot{byRoute: map[string][]*Rule{}, exempt: g.exempt}
	var next time.Time
	for _, r := range g.all() {
		if r.ExpiredAt(now) {
			continue
		}
		s.byRoute[r.Route] = append(s.byRoute[r.Route], r)
		if !r.Expires.IsZero() && (next.IsZero() || r.Expires.Before(next)) {
			next = r.Expires
		}
	}
	if !g.enabled || len(s.byRoute) == 0 {
		g.snap.Store(nil)
	} else {
		g.snap.Store(s)
	}
	if !next.IsZero() {
		g.expiry = time.AfterFunc(next.Sub(now), g.ExpireDue)
	}
}

// all returns every rule held, in the order they're tried on a route.
// Called with mu held.
func (g *Registry) all() []*Rule {
	out := make([]*Rule, 0, len(g.config))
	for _, r := range g.config {
		out = append(out, r)
	}
	return out
}

// ExpireDue takes rules whose max_duration (or TTL) has run out out of
// force, reporting each once. It runs on its own when the next rule
// expires; tests with a fake clock call it directly.
func (g *Registry) ExpireDue() {
	g.mu.Lock()
	now := g.now()
	var expired []*Rule
	for _, r := range g.all() {
		if r.ExpiredAt(now) && !g.reported[r] {
			g.reported[r] = true
			expired = append(expired, r)
		}
	}
	g.rebuild()
	g.forget()
	g.mu.Unlock()
	if g.events != nil {
		for _, r := range expired {
			g.events(Event{Kind: EventExpired, Rule: r})
		}
	}
}

// forget drops reported expiries of rules no longer held. Called with mu
// held.
func (g *Registry) forget() {
	held := map[*Rule]bool{}
	for _, r := range g.all() {
		held[r] = true
	}
	for r := range g.reported {
		if !held[r] {
			delete(g.reported, r)
		}
	}
}

// Close stops the expiry timer.
func (g *Registry) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.expiry != nil {
		g.expiry.Stop()
		g.expiry = nil
	}
}

// Enabled reports whether the kill switch is on.
func (g *Registry) Enabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.enabled
}

// Decide returns what to inject into req on the route labelled route:
// the first of the route's rules in force whose targeting matches
// decides, by rolling its percentages. ok is false when nothing is
// injected — always for the metrics and health check paths and for
// health check probes (see BuiltinExemptPaths).
func (g *Registry) Decide(route string, req Request) (d Decision, ok bool) {
	s := g.snap.Load()
	if s == nil {
		return Decision{}, false
	}
	rules := s.byRoute[route]
	if len(rules) == 0 || s.exempt.exempt(req.HTTP) {
		return Decision{}, false
	}
	now := g.now()
	for _, r := range rules {
		if r.ExpiredAt(now) || !r.Matches(req) {
			continue
		}
		return r.decide(g.sample)
	}
	return Decision{}, false
}

// ExpiredAt reports whether the rule's max_duration (or TTL) is up at now.
func (r *Rule) ExpiredAt(now time.Time) bool {
	return !r.Expires.IsZero() && !now.Before(r.Expires)
}

// Rules returns every rule the registry holds, in force or not (expired,
// or held back by the kill switch), sorted by route then ID.
func (g *Registry) Rules() []*Rule {
	g.mu.Lock()
	out := g.all()
	g.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Active returns the rules in force right now: the kill switch is on and
// they haven't expired.
func (g *Registry) Active() []*Rule {
	if !g.Enabled() {
		return nil
	}
	now := g.now()
	var out []*Rule
	for _, r := range g.Rules() {
		if !r.ExpiredAt(now) {
			out = append(out, r)
		}
	}
	return out
}
