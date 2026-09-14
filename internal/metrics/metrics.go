// Package metrics exposes Gatekeeper's Prometheus-compatible admin
// endpoint: counts of allowed/rejected requests per client and tier,
// the rate limiter's current remaining allowance per client, and
// request latency.
package metrics

import (
	"net/http"

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
	}

	registry.MustRegister(
		m.RequestsAllowed,
		m.RequestsRejected,
		m.LimiterRemaining,
		m.RequestDuration,
		m.ProxyRetries,
		m.ProxyOutcomes,
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
