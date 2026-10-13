// Package metrics exposes Gatekeeper's Prometheus-compatible admin
// endpoint: counts of allowed/rejected requests per client and tier,
// the rate limiter's current remaining allowance per client, request
// latency, authentication successes/failures by method, WebSocket
// connection activity per route, and TLS handshake/certificate state.
package metrics

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every collector Gatekeeper reports, plus the private
// registry they're registered against. Keeping our own registry instead
// of using Prometheus's global default one means the process's metrics
// stay self-contained — which matters once tests start spinning up more
// than one instance in the same process.
type Metrics struct {
	registry *prometheus.Registry

	RequestsAllowed  *prometheus.CounterVec
	RequestsRejected *prometheus.CounterVec
	LimiterRemaining *prometheus.GaugeVec
	RequestDuration  *prometheus.HistogramVec

	// ProxyRetries counts retry attempts made against backend services,
	// by route. It does not include each request's initial attempt, so
	// it stays independent of RequestsAllowed and a retried request is
	// never double-counted against a client's rate limit.
	ProxyRetries *prometheus.CounterVec

	// ProxyOutcomes counts the final outcome of each proxied request —
	// "success" or "failure" — after any retries, by route. It's
	// incremented exactly once per incoming request regardless of how
	// many backend attempts it took.
	ProxyOutcomes *prometheus.CounterVec

	// CacheHits and CacheMisses count GET requests served from the
	// response cache versus forwarded to the backend, by route. Neither
	// is incremented for a route with caching disabled, a non-GET
	// request, or a request carrying the cache-bypass header.
	CacheHits   *prometheus.CounterVec
	CacheMisses *prometheus.CounterVec

	// CircuitBreakerState reports each route's current circuit breaker
	// state as a number: 0 (closed), 1 (open), 2 (half-open) — see
	// circuitbreaker.State. A route with circuit breaking disabled never
	// gets a series here.
	CircuitBreakerState *prometheus.GaugeVec

	// CircuitBreakerRejections counts requests that were failed fast
	// because a route's circuit breaker was open (or its Half-Open trial
	// slots were full), by route. These never reach the backend and are
	// not reflected in ProxyOutcomes.
	CircuitBreakerRejections *prometheus.CounterVec

	// AuthRequests counts authentication decisions by method ("api_key"
	// or "jwt") and result ("success" or "failure"). Each request that
	// reaches the auth middleware with auth enabled is counted exactly
	// once. A rejected request is attributed to "jwt" if it carried a
	// bearer token and to "api_key" otherwise, except on a jwt-only route,
	// where it's always "jwt".
	AuthRequests *prometheus.CounterVec

	// WebSocketActive is the number of currently open proxied WebSocket
	// connections, by route.
	WebSocketActive *prometheus.GaugeVec

	// WebSocketOpened and WebSocketClosed count proxied WebSocket
	// connections that completed the upgrade handshake, and those that
	// have since closed, by route. WebSocketClosed is further split by
	// reason: "client" or "backend" (that side closed or disconnected),
	// "idle_timeout", or "shutdown".
	WebSocketOpened *prometheus.CounterVec
	WebSocketClosed *prometheus.CounterVec

	// WebSocketRejections counts upgrade requests refused before a
	// connection was established, by route and reason: "auth",
	// "rate_limit", "origin", "max_connections", "disabled",
	// "circuit_open", "shutting_down", or "backend" (the backend was
	// unreachable or answered something other than 101).
	WebSocketRejections *prometheus.CounterVec

	// WebSocketDuration is how long each proxied WebSocket connection
	// stayed open, from the 101 response to teardown, by route.
	WebSocketDuration *prometheus.HistogramVec

	// TLSHandshakes counts completed TLS handshakes on the gateway's
	// listener, by negotiated protocol version ("TLS 1.2", "TLS 1.3").
	TLSHandshakes *prometheus.CounterVec

	// TLSHandshakeErrors counts failed TLS handshakes, by reason:
	// "protocol_version", "cipher_suite", "client_certificate", or "other".
	TLSHandshakeErrors *prometheus.CounterVec

	// MTLSVerifications counts client certificate verification outcomes
	// during the handshake, by result ("success" or "failure") and reason
	// ("verified" on success; "no_certificate", "unknown_authority",
	// "expired", or "invalid" on failure).
	MTLSVerifications *prometheus.CounterVec

	// TLSCertificateReloads counts attempts to (re)load the server
	// certificate, by result ("success" or "failure").
	TLSCertificateReloads *prometheus.CounterVec

	certExpiry *certExpiryCollector
}

// certExpiryCollector reports seconds until the server certificate
// expires, computed at scrape time so it keeps counting down between
// reloads. It reports nothing until a certificate has been loaded.
type certExpiryCollector struct {
	desc     *prometheus.Desc
	notAfter atomic.Int64 // unix nanoseconds; 0 = no certificate loaded
}

func (c *certExpiryCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *certExpiryCollector) Collect(ch chan<- prometheus.Metric) {
	na := c.notAfter.Load()
	if na == 0 {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, time.Until(time.Unix(0, na)).Seconds())
}

// SetServerCertificateExpiry records the NotAfter time of the server
// certificate currently in use.
func (m *Metrics) SetServerCertificateExpiry(notAfter time.Time) {
	m.certExpiry.notAfter.Store(notAfter.UnixNano())
}

// ServerCertificateExpiry is the collector behind
// gatekeeper_tls_certificate_expiry_seconds, exposed for tests.
func (m *Metrics) ServerCertificateExpiry() prometheus.Collector {
	return m.certExpiry
}

// New creates and registers all of Gatekeeper's collectors.
func New() *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		registry: registry,
		RequestsAllowed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_requests_allowed_total",
			Help: "Total number of requests allowed by the rate limiter, by client and tier.",
		}, []string{"client", "tier"}),
		RequestsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_requests_rejected_total",
			Help: "Total number of requests rejected by the rate limiter, by client and tier.",
		}, []string{"client", "tier"}),
		LimiterRemaining: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gatekeeper_limiter_remaining",
			Help: "Requests remaining in the client's current bucket/window, as of the last check.",
		}, []string{"client", "tier"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gatekeeper_request_duration_seconds",
			Help:    "End-to-end latency of requests handled by the gateway, including the proxied backend call.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "status"}),
		ProxyRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_proxy_retries_total",
			Help: "Total number of retry attempts made against backend services, by route. Excludes each request's initial attempt.",
		}, []string{"route"}),
		ProxyOutcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_proxy_request_outcomes_total",
			Help: "Final outcome of each proxied request after any retries, by route and outcome (success or failure). Counted once per request regardless of attempt count.",
		}, []string{"route", "outcome"}),
		CacheHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_cache_hits_total",
			Help: "Total number of GET requests served from the response cache without reaching the backend, by route.",
		}, []string{"route"}),
		CacheMisses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_cache_misses_total",
			Help: "Total number of cache-eligible GET requests that were not found in the response cache and were forwarded to the backend, by route.",
		}, []string{"route"}),
		CircuitBreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gatekeeper_circuit_breaker_state",
			Help: "Current circuit breaker state per route: 0=closed, 1=open, 2=half-open.",
		}, []string{"route"}),
		CircuitBreakerRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_circuit_breaker_rejections_total",
			Help: "Total number of requests failed fast because a route's circuit breaker was open, by route.",
		}, []string{"route"}),
		AuthRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_auth_requests_total",
			Help: "Total number of authentication decisions, by method (api_key or jwt) and result (success or failure).",
		}, []string{"method", "result"}),
		WebSocketActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gatekeeper_websocket_active_connections",
			Help: "Number of currently open proxied WebSocket connections, by route.",
		}, []string{"route"}),
		WebSocketOpened: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_websocket_connections_opened_total",
			Help: "Total number of WebSocket connections that completed the upgrade handshake, by route.",
		}, []string{"route"}),
		WebSocketClosed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_websocket_connections_closed_total",
			Help: "Total number of proxied WebSocket connections that have closed, by route and reason (client, backend, idle_timeout, shutdown).",
		}, []string{"route", "reason"}),
		WebSocketRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_websocket_handshake_rejections_total",
			Help: "Total number of WebSocket upgrade requests refused before a connection was established, by route and reason.",
		}, []string{"route", "reason"}),
		WebSocketDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gatekeeper_websocket_connection_duration_seconds",
			Help:    "How long proxied WebSocket connections stayed open, by route.",
			Buckets: []float64{0.1, 1, 5, 15, 30, 60, 300, 900, 1800, 3600, 7200, 14400},
		}, []string{"route"}),
		TLSHandshakes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_tls_handshakes_total",
			Help: "Total number of completed TLS handshakes on the gateway listener, by protocol version.",
		}, []string{"version"}),
		TLSHandshakeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_tls_handshake_errors_total",
			Help: "Total number of failed TLS handshakes on the gateway listener, by reason.",
		}, []string{"reason"}),
		MTLSVerifications: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_mtls_verifications_total",
			Help: "Total number of client certificate verifications during the TLS handshake, by result and reason.",
		}, []string{"result", "reason"}),
		TLSCertificateReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekeeper_tls_certificate_reloads_total",
			Help: "Total number of server certificate load attempts, by result (success or failure).",
		}, []string{"result"}),
		certExpiry: &certExpiryCollector{
			desc: prometheus.NewDesc("gatekeeper_tls_certificate_expiry_seconds",
				"Seconds until the server certificate currently in use expires (negative once expired).", nil, nil),
		},
	}

	registry.MustRegister(
		m.RequestsAllowed,
		m.RequestsRejected,
		m.LimiterRemaining,
		m.RequestDuration,
		m.ProxyRetries,
		m.ProxyOutcomes,
		m.CacheHits,
		m.CacheMisses,
		m.CircuitBreakerState,
		m.CircuitBreakerRejections,
		m.AuthRequests,
		m.WebSocketActive,
		m.WebSocketOpened,
		m.WebSocketClosed,
		m.WebSocketRejections,
		m.WebSocketDuration,
		m.TLSHandshakes,
		m.TLSHandshakeErrors,
		m.MTLSVerifications,
		m.TLSCertificateReloads,
		m.certExpiry,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	return m
}

// Handler returns the http.Handler that should be mounted at the
// configured metrics path (default /metrics).
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
