package lb

import (
	"log"
	"net/url"
	"sync"
)

// Set is the backends one router uses, across all its routes. Building a
// Set from the previous router's reuses every backend whose route and
// target are unchanged — keeping its health, circuit breaker, and
// in-flight count — with its new settings staged until Activate, so a
// reload that fails part-way leaves the live backends untouched.
type Set struct {
	registry *Registry
	logger   *log.Logger

	prev    map[string]*Backend // the previous set's backends: reuse candidates
	byKey   map[string]*Backend // this set's backends
	created map[*Backend]bool   // backends this set created (vs reused)
	pools   []*Pool

	mu     sync.Mutex
	active bool
}

func backendKey(route string, target *url.URL) string {
	return route + "\x00" + target.String()
}

// NewSet starts a Set; prev (may be nil) is the set it will replace.
func NewSet(reg *Registry, prev *Set, logger *log.Logger) *Set {
	if logger == nil {
		logger = log.Default()
	}
	s := &Set{registry: reg, logger: logger, prev: map[string]*Backend{}, byKey: map[string]*Backend{}, created: map[*Backend]bool{}}
	if prev != nil {
		for k, b := range prev.byKey {
			s.prev[k] = b
		}
	}
	return s
}

// Backend returns the backend for target on route, reusing the previous
// set's when there is one. build receives the reused backend's current
// settings (nil for a new backend) and returns the settings to use.
func (s *Set) Backend(route string, target *url.URL, build func(prev *Settings) (Settings, error)) (*Backend, error) {
	k := backendKey(route, target)
	if b, ok := s.byKey[k]; ok {
		return b, nil // the same route and target listed twice
	}
	if b, ok := s.prev[k]; ok && !b.Draining() {
		settings, err := build(b.Settings())
		if err != nil {
			return nil, err
		}
		b.stage(settings)
		s.byKey[k] = b
		return b, nil
	}
	settings, err := build(nil)
	if err != nil {
		return nil, err
	}
	b := NewBackend(route, target, settings)
	s.byKey[k] = b
	s.created[b] = true
	s.registry.add(b)
	return b, nil
}

// AddPool records a pool built over this set's backends.
func (s *Set) AddPool(p *Pool) { s.pools = append(s.pools, p) }

// Activate commits staged settings and starts health checking. Call it
// once the router using the set is about to serve traffic.
func (s *Set) Activate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return
	}
	s.active = true
	for _, b := range s.byKey {
		if !s.created[b] {
			b.commit()
		}
	}
	for _, p := range s.pools {
		p.Start()
	}
}

// Discard abandons a set that never went live (a reload that failed):
// reused backends keep their current settings, new ones are forgotten.
func (s *Set) Discard() {
	for _, b := range s.byKey {
		if s.created[b] {
			s.registry.remove(b)
			b.cancel()
		} else {
			b.discardStaged()
		}
	}
}

// Retire takes this set out of service in favour of next: health checks
// stop, and every backend next doesn't reuse drains — no new traffic,
// in-flight work given its drain timeout — and is then forgotten.
func (s *Set) Retire(next *Set) {
	for _, p := range s.pools {
		p.Stop()
	}
	keep := map[*Backend]bool{}
	if next != nil {
		for _, b := range next.byKey {
			keep[b] = true
		}
	}
	for _, b := range s.byKey {
		if keep[b] {
			continue
		}
		// Marked before returning, so the moment the reload completes
		// the backend reads as draining everywhere (including /metrics).
		b.draining.Store(true)
		go s.drain(b)
	}
}

func (s *Set) drain(b *Backend) {
	timeout := b.Settings().DrainTimeout
	s.logger.Printf("lb: route %s: backend %s removed from config, draining (up to %s)", b.Route(), b.Label(), timeout)
	if forced := b.Drain(timeout); forced {
		s.logger.Printf("lb: route %s: backend %s did not drain within %s, cancelled its remaining requests", b.Route(), b.Label(), timeout)
	} else {
		s.logger.Printf("lb: route %s: backend %s drained", b.Route(), b.Label())
	}
	s.registry.remove(b)
}

// Close stops health checking and forgets every backend (shutdown).
func (s *Set) Close() {
	for _, p := range s.pools {
		p.Stop()
	}
	for _, b := range s.byKey {
		s.registry.remove(b)
	}
}
