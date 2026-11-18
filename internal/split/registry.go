package split

import (
	"sort"
	"sync"

	"gatekeeper/internal/config"
)

// Registry holds the split routes currently serving, so the routes a
// config reload builds can adopt their live state (see Route.Adopt), and
// so the admin API can find them. It outlives reloads.
type Registry struct {
	opts []Option

	mu     sync.RWMutex
	routes map[string]*Route
}

// NewRegistry returns an empty registry whose routes are all built with
// opts.
func NewRegistry(opts ...Option) *Registry {
	return &Registry{opts: opts, routes: map[string]*Route{}}
}

// Build compiles cfg for the route labelled label, sharing the live
// state of the route by that label now serving when it's configured
// alike. The new route isn't served (or returned by Get) until Commit.
func (g *Registry) Build(label string, cfg config.TrafficSplitConfig) (*Route, error) {
	r, err := NewRoute(label, cfg, g.opts...)
	if err != nil {
		return nil, err
	}
	g.mu.RLock()
	prev := g.routes[label]
	g.mu.RUnlock()
	r.Adopt(prev)
	return r, nil
}

// Commit makes routes the ones serving, forgetting any others (routes a
// reload removed, or that are no longer split).
func (g *Registry) Commit(routes []*Route) {
	m := make(map[string]*Route, len(routes))
	for _, r := range routes {
		m[r.label] = r
	}
	g.mu.Lock()
	g.routes = m
	g.mu.Unlock()
}

// Get returns the serving split route labelled label.
func (g *Registry) Get(label string) (*Route, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	r, ok := g.routes[label]
	return r, ok
}

// Routes returns every serving split route, by label.
func (g *Registry) Routes() []*Route {
	g.mu.RLock()
	out := make([]*Route, 0, len(g.routes))
	for _, r := range g.routes {
		out = append(out, r)
	}
	g.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out
}
