package split

import (
	"fmt"
	"time"

	"gatekeeper/internal/config"
)

// Rollback triggers, reported in Event.Trigger.
const (
	TriggerErrorRate = "error_rate"
	TriggerLatency   = "latency"
	TriggerManual    = "manual"
)

// evalInterval is the least time between two guardrail evaluations of a
// route: often enough to react within a second, rarely enough that the
// check costs nothing next to the requests it judges.
const evalInterval = time.Second

// guard is one variant's auto_rollback guardrails, with the windows its
// decisions are based on: the variant's own requests, and the
// baseline's over the same length of time.
type guard struct {
	variant  int
	cfg      config.AutoRollbackConfig
	own      *window
	baseline *window
}

func newGuards(cfg config.TrafficSplitConfig) []*guard {
	var gs []*guard
	for i, v := range cfg.Variants {
		if v.AutoRollback == nil {
			continue
		}
		ar := *v.AutoRollback
		gs = append(gs, &guard{variant: i, cfg: ar, own: newWindow(ar.Window.Duration), baseline: newWindow(ar.Window.Duration)})
	}
	return gs
}

// verdict judges the variant against the baseline at now. It returns a
// trigger and a reason when the variant should lose its traffic.
//
// A variant isn't judged before it has served min_requests in the
// window, so a handful of unlucky requests can't roll it back. The
// latency check also needs min_requests on the baseline, since a p95
// from a few requests says nothing; the error check compares with
// whatever error rate the baseline has (none at all counts as 0%), which
// errs towards rolling back.
func (g *guard) verdict(now time.Time) (trigger, reason string) {
	v := g.own.sample(now)
	if v.Requests < uint64(g.cfg.MinRequests) {
		return "", ""
	}
	b := g.baseline.sample(now)
	if limit := g.cfg.MaxErrorRateIncrease; limit > 0 && v.ErrorRate()-b.ErrorRate() > limit {
		return TriggerErrorRate, fmt.Sprintf("5xx rate %.1f%% over %d requests vs baseline %.1f%% (limit +%.1f points)",
			100*v.ErrorRate(), v.Requests, 100*b.ErrorRate(), 100*limit)
	}
	if ratio := g.cfg.MaxP95LatencyRatio; ratio > 0 && b.Requests >= uint64(g.cfg.MinRequests) && b.P95 > 0 &&
		float64(v.P95) > ratio*float64(b.P95) {
		return TriggerLatency, fmt.Sprintf("p95 latency %s vs baseline %s (limit %.2gx)",
			v.P95.Round(time.Millisecond), b.P95.Round(time.Millisecond), ratio)
	}
	return "", ""
}

func (g *guard) reset() {
	g.own.reset()
	g.baseline.reset()
}

// Record counts one finished request served by variant i: its latency
// and whether it failed with a 5xx. It feeds the guardrails, and at most
// once a second evaluates them, rolling back a variant that crossed one.
func (r *Route) Record(i int, latency time.Duration, status int) {
	if len(r.guards) == 0 {
		return
	}
	now := r.now()
	isError := status >= 500
	for _, g := range r.guards {
		switch i {
		case g.variant:
			g.own.record(now, latency, isError)
		case r.baseline:
			g.baseline.record(now, latency, isError)
		}
	}
	last := r.lastEval.Load()
	if now.UnixNano()-last < int64(evalInterval) || !r.lastEval.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	r.evaluate(now)
}

// evaluate rolls back every guarded variant that still has traffic and
// has crossed a guardrail. It's fail-safe: a bug here is swallowed
// rather than allowed to break the request that triggered it.
func (r *Route) evaluate(now time.Time) {
	defer func() { _ = recover() }()
	w := r.Weights()
	for _, g := range r.guards {
		if w[g.variant] == 0 {
			continue
		}
		trigger, reason := g.verdict(now)
		if trigger == "" {
			continue
		}
		r.rollback(g.variant, trigger, reason, true)
		// Start the next judgement from scratch: what got this variant
		// rolled back mustn't count against it if it's given traffic
		// again.
		g.reset()
	}
}

// guardFor returns variant i's guardrails, or nil.
func (r *Route) guardFor(i int) *guard {
	for _, g := range r.guards {
		if g.variant == i {
			return g
		}
	}
	return nil
}
