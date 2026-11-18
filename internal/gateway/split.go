package gateway

import (
	"fmt"
	"sort"
	"strings"

	"gatekeeper/internal/metrics"
	"gatekeeper/internal/split"
)

// TrafficSplit returns the live traffic split of the route labelled
// label, if that route is split.
func (g *Gateway) TrafficSplit(label string) (*split.Route, bool) { return g.splits.Get(label) }

// TrafficSplits returns every live split route, by label.
func (g *Gateway) TrafficSplits() []*split.Route { return g.splits.Routes() }

// variantWeights reports every split route's current weights for
// /metrics.
func (g *Gateway) variantWeights() []metrics.VariantWeight {
	var out []metrics.VariantWeight
	for _, r := range g.splits.Routes() {
		w := r.Weights()
		for i, name := range r.Names() {
			out = append(out, metrics.VariantWeight{Route: r.Label(), Variant: name, Weight: w[i]})
		}
	}
	return out
}

// onSplitEvent logs a change to a split route's weights and counts
// rollbacks.
func (g *Gateway) onSplitEvent(e split.Event) {
	weights := formatWeights(e.Weights)
	switch e.Kind {
	case split.EventRollback:
		how := "by an operator"
		if e.Auto {
			how = "automatically (" + e.Trigger + ")"
		}
		g.logger.Printf("split: route %s: variant %s rolled back %s: %s; weights now %s", e.Route, e.Variant, how, e.Reason, weights)
		if g.metrics != nil {
			g.metrics.VariantRollbacks.WithLabelValues(e.Route, e.Variant, e.Trigger).Inc()
		}
	case split.EventRolloutStep:
		g.logger.Printf("split: route %s: rollout of %s stepped up; weights now %s", e.Route, e.Variant, weights)
	default:
		g.logger.Printf("split: route %s: %s; weights now %s", e.Route, e.Kind, weights)
	}
}

// formatWeights renders weights as "canary=10 stable=90", sorted by name.
func formatWeights(w map[string]int) string {
	names := make([]string, 0, len(w))
	for n := range w {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s=%d", n, w[n])
	}
	return strings.Join(parts, " ")
}

// logTrafficSplits notes split routes whose sticky cookies are signed
// with a secret generated at startup.
func (g *Gateway) logTrafficSplits(routes []*split.Route) {
	for _, r := range routes {
		if r.RandomCookieSecret() {
			g.logger.Printf("split: route %s: sticky cookies are signed with a secret generated at startup, so they don't survive a restart or carry over to other instances; set traffic_split.sticky.cookie.secret_env to keep them", r.Label())
		}
	}
}
