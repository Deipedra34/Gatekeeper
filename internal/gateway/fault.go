package gateway

import (
	"sort"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/fault"
	"gatekeeper/internal/metrics"
)

// Faults returns the fault injection registry, shared by every config.
func (g *Gateway) Faults() *fault.Registry { return g.faults }

// configureFaults applies cfg's fault injection settings to the
// registry, logging runtime rules dropped with their route, and warns
// about whatever is now in force — at startup and on every reload, so
// fault injection left on can't go unnoticed in the logs.
func (g *Gateway) configureFaults(cfg *config.Config) {
	for _, r := range g.faults.Configure(cfg) {
		g.logger.Printf("fault_injection: runtime rule %s dropped: route %s is no longer configured", r.ID, r.Route)
	}
	g.logFaultInjection(cfg)
}

// logFaultInjection logs what fault injection the registry has in force.
func (g *Gateway) logFaultInjection(cfg *config.Config) {
	configured := 0
	for _, rt := range cfg.Routes {
		if f := rt.FaultInjection; f != nil && f.Enabled {
			configured++
		}
	}
	if !g.faults.Enabled() {
		if configured > 0 {
			g.logger.Printf("fault_injection: %d route(s) enable fault injection, but fault_injection.global_enabled is false: nothing is injected", configured)
		}
		return
	}
	active := g.faults.Active()
	if len(active) == 0 {
		g.logger.Printf("fault_injection: global_enabled is true (environment %s), no rule in force", cfg.FaultInjection.Environment)
		return
	}
	g.logger.Printf("fault_injection: WARNING: fault injection is ACTIVE (environment %s): %d rule(s) in force; requests on these routes will be delayed, aborted, or reset on purpose", cfg.FaultInjection.Environment, len(active))
	now := time.Now()
	for _, r := range active {
		g.logger.Printf("fault_injection: WARNING: route %s: rule %s (%s): %s; %s", r.Route, r.ID, r.Source, r.Summary(), expiresIn(r, now))
	}
}

// onFaultEvent logs a rule's expiry.
func (g *Gateway) onFaultEvent(e fault.Event) {
	if e.Kind == fault.EventExpired {
		g.logger.Printf("fault_injection: route %s: rule %s (%s) expired after %s; no longer injected", e.Rule.Route, e.Rule.ID, e.Rule.Source, e.Rule.Expires.Sub(e.Rule.Start))
	}
}

// faultRoutes is the /metrics source for the rules in force, per route.
func (g *Gateway) faultRoutes() []metrics.FaultRoute {
	counts := map[string]int{}
	for _, r := range g.faults.Active() {
		counts[r.Route]++
	}
	out := make([]metrics.FaultRoute, 0, len(counts))
	for route, n := range counts {
		out = append(out, metrics.FaultRoute{Route: route, Rules: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })
	return out
}

func expiresIn(r *fault.Rule, now time.Time) string {
	left := r.Remaining(now)
	if left < 0 {
		return "no max_duration: in force until removed"
	}
	return "expires in " + left.Round(time.Second).String()
}
