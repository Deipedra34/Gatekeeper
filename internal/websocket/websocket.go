// Package websocket implements Gatekeeper's WebSocket proxying support:
// recognising upgrade requests, relaying frames between an upgraded
// client connection and its backend, and tracking every open connection
// so per-route/per-client limits, idle timeouts, metrics, and graceful
// shutdown can be applied to them.
//
// The relay is frame-aware rather than a blind byte copy. Frames are
// forwarded unmodified (masking, extensions, and fragmentation pass
// through untouched), but knowing where each frame starts and ends lets
// the gateway inject a proper Close frame — on idle timeout, shutdown,
// or one side disappearing — without ever splicing it into the middle
// of a frame that's already in flight.
package websocket

import (
	"context"
	"net/http"
	"strings"

	"gatekeeper/internal/metrics"
)

// Handshake rejection reasons, used as the "reason" label of
// metrics.WebSocketRejections.
const (
	RejectAuth           = "auth"
	RejectRateLimit      = "rate_limit"
	RejectOrigin         = "origin"
	RejectMaxConnections = "max_connections"
	RejectDisabled       = "disabled"
	RejectCircuitOpen    = "circuit_open"
	RejectShuttingDown   = "shutting_down"
	RejectBackend        = "backend"
)

// IsUpgrade reports whether r asks to be upgraded to the WebSocket
// protocol: a GET carrying "Connection: upgrade" and "Upgrade: websocket"
// (both matched as case-insensitive tokens, as RFC 6455 requires).
// Upgrades to any other protocol are not WebSocket requests and keep
// going through the ordinary HTTP proxy path.
func IsUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		headerHasToken(r.Header, "Connection", "upgrade") &&
		headerHasToken(r.Header, "Upgrade", "websocket")
}

// headerHasToken reports whether any comma-separated element of any value
// of header name equals token, case-insensitively.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// Handshake carries what the middleware chain learns about a WebSocket
// upgrade request on its way to the router: which route it targets (so
// rejections can be attributed per route) and which client the rate
// limiter identified it as (so per-client connection limits key on the
// same identity the rate limit does). It's attached to the request
// context by Annotate and filled in as the request moves down the chain.
type Handshake struct {
	// Route is the metrics label of the route the request matched.
	Route string

	client    string
	hasClient bool
}

// SetClient records the client identity the rate limiter resolved.
func (h *Handshake) SetClient(client string) {
	h.client = client
	h.hasClient = true
}

// Client returns the identity recorded by SetClient, if any.
func (h *Handshake) Client() (string, bool) {
	return h.client, h.hasClient
}

type handshakeKey struct{}

// Annotate returns r with a fresh Handshake for route attached.
func Annotate(r *http.Request, route string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), handshakeKey{}, &Handshake{Route: route}))
}

// HandshakeFrom returns the Handshake attached by Annotate, if r is a
// WebSocket upgrade that was annotated.
func HandshakeFrom(ctx context.Context) (*Handshake, bool) {
	h, ok := ctx.Value(handshakeKey{}).(*Handshake)
	return h, ok
}

// RecordRejection counts one refused handshake against route. m may be
// nil.
func RecordRejection(m *metrics.Metrics, route, reason string) {
	if m == nil {
		return
	}
	m.WebSocketRejections.WithLabelValues(route, reason).Inc()
}

// RecordRejectionFor counts a refused handshake for r if — and only if —
// r is an annotated WebSocket upgrade request; it's a no-op for ordinary
// HTTP requests. It's what the auth and rate-limit middleware call when
// they turn a request away.
func RecordRejectionFor(r *http.Request, m *metrics.Metrics, reason string) {
	if hs, ok := HandshakeFrom(r.Context()); ok {
		RecordRejection(m, hs.Route, reason)
	}
}
