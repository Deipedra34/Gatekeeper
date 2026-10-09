package websocket

import (
	"context"
	"errors"
	"sync"
	"time"

	"gatekeeper/internal/metrics"
)

var (
	// ErrRouteFull is returned by Hub.Reserve when the route is already
	// at its ws_max_connections limit.
	ErrRouteFull = errors.New("websocket: route connection limit reached")
	// ErrClientFull is returned by Hub.Reserve when the client is already
	// at the route's ws_max_connections_per_client limit.
	ErrClientFull = errors.New("websocket: per-client connection limit reached")
	// ErrShuttingDown is returned by Hub.Reserve once Shutdown has begun.
	ErrShuttingDown = errors.New("websocket: gateway is shutting down")
)

// defaultShutdownGrace is how long Shutdown lets connections finish the
// closing handshake when its context carries no deadline.
const defaultShutdownGrace = 5 * time.Second

// Limits are the concurrent-connection caps for one route. Zero means no
// cap.
type Limits struct {
	MaxConnections          int
	MaxConnectionsPerClient int
}

// Hub tracks every proxied WebSocket connection. It's created once per
// process and shared across config reloads, so connection counts — and
// the limits enforced against them — carry over when routes are rebuilt,
// and Shutdown can reach every connection regardless of which config it
// was opened under.
type Hub struct {
	metrics *metrics.Metrics

	mu          sync.Mutex
	perRoute    map[string]int
	perClient   map[routeClient]int
	tunnels     map[*tunnel]struct{}
	closing     bool
	drained     chan struct{} // closed when the last tunnel exits after Shutdown began
	drainedOnce sync.Once
}

type routeClient struct {
	route, client string
}

// NewHub creates an empty Hub. m may be nil.
func NewHub(m *metrics.Metrics) *Hub {
	return &Hub{
		metrics:   m,
		perRoute:  make(map[string]int),
		perClient: make(map[routeClient]int),
		tunnels:   make(map[*tunnel]struct{}),
	}
}

// Slot is a reserved connection slot. It must be released exactly once,
// either by passing it to Serve or by calling Release directly if the
// handshake fails before the connection is established.
type Slot struct {
	hub           *Hub
	route, client string
	once          sync.Once
}

// Reserve claims a connection slot for client on route, or reports which
// limit stopped it.
func (h *Hub) Reserve(route, client string, lim Limits) (*Slot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closing {
		return nil, ErrShuttingDown
	}
	key := routeClient{route, client}
	if lim.MaxConnections > 0 && h.perRoute[route] >= lim.MaxConnections {
		return nil, ErrRouteFull
	}
	if lim.MaxConnectionsPerClient > 0 && h.perClient[key] >= lim.MaxConnectionsPerClient {
		return nil, ErrClientFull
	}
	h.perRoute[route]++
	h.perClient[key]++
	return &Slot{hub: h, route: route, client: client}, nil
}

// Release gives the slot back. Safe to call more than once.
func (s *Slot) Release() {
	s.once.Do(func() {
		h := s.hub
		h.mu.Lock()
		defer h.mu.Unlock()
		key := routeClient{s.route, s.client}
		if h.perRoute[s.route]--; h.perRoute[s.route] <= 0 {
			delete(h.perRoute, s.route)
		}
		if h.perClient[key]--; h.perClient[key] <= 0 {
			delete(h.perClient, key)
		}
	})
}

// Serve relays frames between client and backend until the connection
// closes, then releases slot and closes both connections. It blocks for
// the lifetime of the connection. idleTimeout <= 0 disables the idle
// timeout.
func (h *Hub) Serve(slot *Slot, client, backend Endpoint, idleTimeout time.Duration) {
	defer slot.Release()

	t := newTunnel(slot.route, client, backend, idleTimeout)

	h.mu.Lock()
	h.tunnels[t] = struct{}{}
	lateArrival := h.closing
	h.mu.Unlock()

	if h.metrics != nil {
		h.metrics.WebSocketOpened.WithLabelValues(t.route).Inc()
		h.metrics.WebSocketActive.WithLabelValues(t.route).Inc()
	}
	if lateArrival {
		// The handshake raced Shutdown; close straight away rather than
		// leave a connection running past the point Shutdown waited for.
		t.close(closeGoingAway, "server shutting down", CloseReasonShutdown, closeWriteTimeout)
	}

	reason := t.run()
	// Free the slot before the metrics say the connection is gone, so
	// nobody observing the gauge can race a new handshake into a limit
	// that's about to be lifted.
	slot.Release()

	if h.metrics != nil {
		h.metrics.WebSocketActive.WithLabelValues(t.route).Dec()
		h.metrics.WebSocketClosed.WithLabelValues(t.route, reason).Inc()
		h.metrics.WebSocketDuration.WithLabelValues(t.route).Observe(time.Since(t.opened).Seconds())
	}

	h.mu.Lock()
	delete(h.tunnels, t)
	if h.closing && len(h.tunnels) == 0 && h.drained != nil {
		h.drainedOnce.Do(func() { close(h.drained) })
	}
	h.mu.Unlock()
}

// Active returns the number of currently open connections.
func (h *Hub) Active() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.tunnels)
}

// Shutdown stops new connections from being reserved and closes every
// open one gracefully: each side is sent a Close frame (1001, going away)
// and given until ctx's deadline to complete the closing handshake. Any
// connection still open when ctx is done is torn down forcibly, and
// ctx's error is returned.
func (h *Hub) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closing = true
	if len(h.tunnels) == 0 {
		h.mu.Unlock()
		return nil
	}
	if h.drained == nil {
		h.drained = make(chan struct{})
	}
	drained := h.drained
	open := h.snapshotLocked()
	h.mu.Unlock()

	grace := defaultShutdownGrace
	if deadline, ok := ctx.Deadline(); ok {
		grace = time.Until(deadline)
	}
	for _, t := range open {
		t.close(closeGoingAway, "server shutting down", CloseReasonShutdown, grace)
	}

	select {
	case <-drained:
		return nil
	case <-ctx.Done():
	}

	h.mu.Lock()
	open = h.snapshotLocked()
	h.mu.Unlock()
	for _, t := range open {
		t.teardown()
	}
	// Teardown unblocks every relay immediately; wait briefly so the
	// metrics reflect the closed connections before returning.
	select {
	case <-drained:
	case <-time.After(time.Second):
	}
	return ctx.Err()
}

func (h *Hub) snapshotLocked() []*tunnel {
	out := make([]*tunnel, 0, len(h.tunnels))
	for t := range h.tunnels {
		out = append(out, t)
	}
	return out
}
