package lb

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/metrics"
)

// healthChecker probes every backend of a pool on an interval. A backend
// leaves rotation after UnhealthyThreshold consecutive failed probes and
// returns after HealthyThreshold consecutive passing ones.
type healthChecker struct {
	pool   *Pool
	cancel context.CancelFunc
	done   chan struct{}
}

func startHealthChecker(p *Pool) *healthChecker {
	ctx, cancel := context.WithCancel(context.Background())
	hc := &healthChecker{pool: p, cancel: cancel, done: make(chan struct{})}
	go hc.run(ctx)
	return hc
}

func (hc *healthChecker) stop() {
	hc.cancel()
	<-hc.done
}

func (hc *healthChecker) run(ctx context.Context) {
	defer close(hc.done)
	cfg := hc.pool.cfg.HealthCheck
	ticker := time.NewTicker(cfg.Interval.Duration)
	defer ticker.Stop()
	for {
		hc.probeAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (hc *healthChecker) probeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, b := range hc.pool.backends {
		if b.Draining() {
			continue
		}
		wg.Add(1)
		go func(b *Backend) {
			defer wg.Done()
			hc.record(b, hc.probe(ctx, b))
		}(b)
	}
	wg.Wait()
}

// probe sends one health check request through the backend's own
// transport, so its TLS settings (custom CA, client certificate) apply.
func (hc *healthChecker) probe(ctx context.Context, b *Backend) bool {
	cfg := hc.pool.cfg.HealthCheck
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout.Duration)
	defer cancel()

	u := *b.Target()
	u.Path = strings.TrimSuffix(u.Path, "/") + cfg.Path
	u.RawPath = ""
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "gatekeeper-health-check")
	resp, err := b.Settings().Transport.RoundTrip(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return statusExpected(resp.StatusCode, cfg.ExpectedStatus)
}

func statusExpected(status int, expected []int) bool {
	if len(expected) == 0 {
		return status >= 200 && status < 400
	}
	for _, s := range expected {
		if s == status {
			return true
		}
	}
	return false
}

func (hc *healthChecker) record(b *Backend, ok bool) {
	p := hc.pool
	cfg := p.cfg.HealthCheck
	if p.metrics != nil {
		result := "failure"
		if ok {
			result = "success"
		}
		p.metrics.HealthChecks.WithLabelValues(p.cfg.Route, b.Label(), result).Inc()
	}

	b.probeMu.Lock()
	defer b.probeMu.Unlock()
	if ok {
		b.probeOK++
		b.probeFail = 0
		if !b.activeHealthy.Load() && b.probeOK >= cfg.HealthyThreshold {
			b.activeHealthy.Store(true)
			p.logger.Printf("lb: route %s: backend %s is healthy again, back in rotation", p.cfg.Route, b.Label())
		}
		return
	}
	b.probeFail++
	b.probeOK = 0
	if b.activeHealthy.Load() && b.probeFail >= cfg.UnhealthyThreshold {
		b.activeHealthy.Store(false)
		p.logger.Printf("lb: route %s: backend %s failed %d health checks, out of rotation", p.cfg.Route, b.Label(), b.probeFail)
	}
}

// Registry tracks every live backend so /metrics can report their state
// at scrape time. A gateway keeps one across reloads.
type Registry struct {
	mu       sync.Mutex
	backends map[*Backend]struct{}
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{backends: map[*Backend]struct{}{}}
}

func (r *Registry) add(b *Backend) {
	r.mu.Lock()
	r.backends[b] = struct{}{}
	r.mu.Unlock()
}

func (r *Registry) remove(b *Backend) {
	r.mu.Lock()
	delete(r.backends, b)
	r.mu.Unlock()
}

// Snapshot reports every registered backend's state. Two entries for the
// same route and target (a removed backend still draining next to its
// replacement) are merged: in-flight counts add up, and health comes
// from the one in rotation.
func (r *Registry) Snapshot() []metrics.BackendState {
	r.mu.Lock()
	defer r.mu.Unlock()
	type key struct{ route, backend string }
	merged := map[key]*metrics.BackendState{}
	var order []key
	for b := range r.backends {
		k := key{b.Route(), b.Label()}
		breaker := -1
		if cb := b.Breaker(); cb != nil {
			breaker = int(cb.State())
		}
		s := metrics.BackendState{
			Route: b.Route(), Backend: b.Label(), Healthy: b.Healthy(),
			InRotation: b.Available(), Draining: b.Draining(), InFlight: b.InFlight(), BreakerState: breaker,
		}
		prev, ok := merged[k]
		if !ok {
			merged[k] = &s
			order = append(order, k)
			continue
		}
		prev.InFlight += s.InFlight
		if prev.Draining && !s.Draining {
			s.InFlight = prev.InFlight
			*prev = s
		}
	}
	out := make([]metrics.BackendState, 0, len(order))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	return out
}
