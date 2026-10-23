// Package lb implements Gatekeeper's load balancing: a pool of backends
// per route, the strategies that pick one per request, active (probe)
// and passive (real-traffic) health checking, and draining of backends a
// config reload removes.
//
// A Backend outlives config reloads when its route and target don't
// change, so its health, circuit breaker, and in-flight count carry
// over; its settings (weight, transport, TLS) are swapped in atomically
// once the reload has fully succeeded.
package lb

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/circuitbreaker"
)

// Settings are the parts of a Backend a config reload may change.
type Settings struct {
	// Weight is the backend's relative share of traffic; >= 1.
	Weight int
	// Transport makes HTTP requests to this backend (with its TLS
	// settings applied).
	Transport http.RoundTripper
	// TLSConfig is the backend TLS client config for raw dials (WebSocket
	// upgrades); nil means Go's defaults.
	TLSConfig *tls.Config
	// Breaker is the backend's circuit breaker; nil when disabled.
	Breaker *circuitbreaker.CircuitBreaker
	// BreakerKey identifies Breaker's configuration, so a reload that
	// doesn't change it can keep the breaker (and its state).
	BreakerKey string
	// DrainTimeout bounds draining when a reload removes the backend.
	DrainTimeout time.Duration
}

// Backend is one upstream server of a route.
type Backend struct {
	route  string
	label  string
	target *url.URL

	settings atomic.Pointer[Settings]
	staged   atomic.Pointer[Settings]

	inflight atomic.Int64

	// Active health (probes): healthy until probes say otherwise.
	activeHealthy atomic.Bool
	probeMu       sync.Mutex
	probeOK       int
	probeFail     int

	// Passive health (real traffic).
	passiveFailures atomic.Int64
	ejectedUntil    atomic.Int64 // unix nanos; 0 = not ejected

	draining atomic.Bool
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewBackend creates a healthy backend for target on route.
func NewBackend(route string, target *url.URL, s Settings) *Backend {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Backend{route: route, label: Label(target), target: target, ctx: ctx, cancel: cancel}
	if s.Weight < 1 {
		s.Weight = 1
	}
	b.settings.Store(&s)
	b.activeHealthy.Store(true)
	return b
}

// Label renders target for metrics, logs, and spans: the URL without any
// userinfo, so credentials embedded in a target never leak.
func Label(target *url.URL) string {
	u := *target
	u.User = nil
	return u.String()
}

// Route returns the label of the route the backend belongs to.
func (b *Backend) Route() string { return b.route }

// Label returns the backend's display label (its target, sans userinfo).
func (b *Backend) Label() string { return b.label }

// Target returns the backend's base URL.
func (b *Backend) Target() *url.URL { return b.target }

// Settings returns the backend's current settings.
func (b *Backend) Settings() *Settings { return b.settings.Load() }

// Breaker returns the backend's circuit breaker, or nil.
func (b *Backend) Breaker() *circuitbreaker.CircuitBreaker { return b.settings.Load().Breaker }

// stage records settings to apply on commit.
func (b *Backend) stage(s Settings) {
	if s.Weight < 1 {
		s.Weight = 1
	}
	b.staged.Store(&s)
}

// commit applies staged settings, if any.
func (b *Backend) commit() {
	if s := b.staged.Swap(nil); s != nil {
		old := b.settings.Swap(s)
		if t, ok := old.Transport.(*http.Transport); ok && old.Transport != s.Transport && t != http.DefaultTransport {
			t.CloseIdleConnections()
		}
	}
}

// discardStaged drops staged settings (a reload that failed).
func (b *Backend) discardStaged() { b.staged.Store(nil) }

// Acquire counts one more in-flight request or connection on b and
// returns the function that releases it. Release is idempotent.
func (b *Backend) Acquire() (release func()) {
	b.inflight.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() { b.inflight.Add(-1) })
	}
}

// InFlight returns the number of requests and connections in flight.
func (b *Backend) InFlight() int64 { return b.inflight.Load() }

// Healthy reports whether the backend passes active probes and isn't
// passively ejected.
func (b *Backend) Healthy() bool {
	if !b.activeHealthy.Load() {
		return false
	}
	until := b.ejectedUntil.Load()
	return until == 0 || time.Now().UnixNano() >= until
}

// Draining reports whether a reload removed the backend.
func (b *Backend) Draining() bool { return b.draining.Load() }

// Available reports whether the backend may receive new traffic.
func (b *Backend) Available() bool { return !b.draining.Load() && b.Healthy() }

// Context is cancelled when a drain times out; work in flight on the
// backend should stop when it's done.
func (b *Backend) Context() context.Context { return b.ctx }

// Drain stops new traffic to the backend, waits up to timeout for what's
// in flight to finish, then cancels anything still running. It blocks;
// callers run it in a goroutine.
func (b *Backend) Drain(timeout time.Duration) (forced bool) {
	b.draining.Store(true)
	deadline := time.Now().Add(timeout)
	for b.inflight.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	forced = b.inflight.Load() > 0
	b.cancel()
	if t, ok := b.settings.Load().Transport.(*http.Transport); ok && t != http.DefaultTransport {
		t.CloseIdleConnections()
	}
	return forced
}
