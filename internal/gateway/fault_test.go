package gateway_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/tracing"
)

// faultYAML is a gateway with API key auth (key "tester"), per-key rate
// limiting with burst, and one route on "/" to target with the fault
// injection settings rule (indented under the route's fault_injection,
// left out when empty) and global (under the top-level fault_injection).
func faultYAML(target string, burst int, global, rule string) string {
	return faultYAMLWithRoutes(target, burst, global, rule, "")
}

// faultYAMLWithRoutes is faultYAML with more routes after the first.
func faultYAMLWithRoutes(target string, burst int, global, rule, routes string) string {
	section := ""
	if rule != "" {
		section = "    fault_injection:\n" + rule + "\n"
	}
	return fmt.Sprintf(`
rate_limit:
  scope: api_key
  tiers:
    default: {requests_per_second: 0.0001, burst: %d}
auth:
  enabled: true
  api_keys: [tester]
routes:
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
%s%s
fault_injection:
%s
`, burst, target, section, routes, global)
}

const (
	faultsOnInTest = "  global_enabled: true\n  environment: test"
	faultsOff      = "  global_enabled: false\n  environment: test"
	headerAbort    = `      enabled: true
      abort: {percentage: 100, status: 503}
      count_as_backend_failure: false
      match:
        header: {name: X-Gatekeeper-Fault, value: "true"}`
)

const testerKey = "X-Api-Key"

func scrapeMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func TestGatewayFault_HeaderTriggeredAbortEndToEnd(t *testing.T) {
	b := newSplitBackend(t, "b")
	h := newSplitHarness(t, faultYAML(b.srv.URL, 1000, faultsOnInTest, headerAbort))

	rec := h.get("/orders", "10.0.0.1:1", testerKey, "tester", "X-Gatekeeper-Fault", "true")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "abort", rec.Header().Get("X-Gatekeeper-Fault"))
	assert.Zero(t, b.hits(), "the backend never saw it")
	assert.Contains(t, h.logs.String(), "GET /orders 503", "logged with the injected status")
	assert.Contains(t, h.logs.String(), "fault=abort", "and the fault")

	assert.Equal(t, http.StatusOK, h.get("/orders", "10.0.0.1:1", testerKey, "tester").Code, "no header, no fault")
	assert.Equal(t, http.StatusOK, h.get("/orders", "10.0.0.1:1", testerKey, "tester", "X-Gatekeeper-Fault", "false").Code)

	assert.Equal(t, 1.0, testutil.ToFloat64(h.m.FaultsInjected.WithLabelValues("/", "abort")))
	text := scrapeMetrics(t, h.m)
	assert.Contains(t, text, "gatekeeper_fault_injection_active 1")
	assert.Contains(t, text, `gatekeeper_fault_injection_rules{route="/"} 1`)
}

func TestGatewayFault_AuthAndRateLimitRunFirst(t *testing.T) {
	b := newSplitBackend(t, "b")
	h := newSplitHarness(t, faultYAML(b.srv.URL, 2, faultsOnInTest, headerAbort))

	assert.Equal(t, http.StatusUnauthorized, h.get("/x", "10.0.0.1:1", "X-Gatekeeper-Fault", "true").Code,
		"an unauthenticated request is refused before any fault")
	for i := 0; i < 2; i++ {
		assert.Equal(t, http.StatusServiceUnavailable, h.get("/x", "10.0.0.1:1", testerKey, "tester", "X-Gatekeeper-Fault", "true").Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, h.get("/x", "10.0.0.1:1", testerKey, "tester", "X-Gatekeeper-Fault", "true").Code,
		"faulted requests still spend rate limit budget")
	assert.Equal(t, 2.0, testutil.ToFloat64(h.m.FaultsInjected.WithLabelValues("/", "abort")))
}

func TestGatewayFault_HealthChecksAndMetricsPathNeverFaulted(t *testing.T) {
	b := newSplitBackend(t, "b")
	rule := `      enabled: true
      abort: {percentage: 100, status: 500}
      count_as_backend_failure: false`
	h := newSplitHarness(t, faultYAML(b.srv.URL, 1000, faultsOnInTest, rule))

	assert.Equal(t, http.StatusInternalServerError, h.get("/x", "10.0.0.1:1", testerKey, "tester").Code)
	for _, path := range []string{"/metrics", "/healthz", "/readyz", "/livez", "/health"} {
		assert.Equal(t, http.StatusOK, h.get(path, "10.0.0.1:1", testerKey, "tester").Code, path)
	}
	assert.Equal(t, http.StatusOK, h.get("/x", "10.0.0.1:1", testerKey, "tester", "User-Agent", "kube-probe/1.30").Code)
}

func TestGatewayFault_KillSwitchAndReloadWarnings(t *testing.T) {
	b := newSplitBackend(t, "b")
	rule := `      enabled: true
      max_duration: 1h
      delay: {percentage: 10, fixed: 500ms}
      abort: {percentage: 100, status: 503}
      count_as_backend_failure: false`
	h := newSplitHarness(t, faultYAML(b.srv.URL, 1000, faultsOff, rule))

	assert.Contains(t, h.logs.String(), "1 route(s) enable fault injection, but fault_injection.global_enabled is false: nothing is injected")
	assert.NotContains(t, h.logs.String(), "ACTIVE")
	assert.Equal(t, http.StatusOK, h.get("/x", "10.0.0.1:1", testerKey, "tester").Code, "the kill switch is off")
	assert.Contains(t, scrapeMetrics(t, h.m), "gatekeeper_fault_injection_active 0")

	h.rewrite(t, faultYAML(b.srv.URL, 1000, faultsOnInTest, rule))
	require.NoError(t, h.gw.Reload())
	logs := h.logs.String()
	assert.Contains(t, logs, "WARNING: fault injection is ACTIVE (environment test): 1 rule(s) in force")
	assert.Contains(t, logs, "route /: rule config-")
	assert.Contains(t, logs, "delay 10% 500ms, abort 100% 503; every request; not counted as backend failures; expires in 1h0m0s")
	assert.Equal(t, http.StatusServiceUnavailable, h.get("/y", "10.0.0.1:1", testerKey, "tester").Code)

	// Every reload warns again while it's active.
	require.NoError(t, h.gw.Reload())
	assert.Equal(t, 2, strings.Count(h.logs.String(), "fault injection is ACTIVE"))

	h.rewrite(t, faultYAML(b.srv.URL, 1000, faultsOff, rule))
	require.NoError(t, h.gw.Reload())
	assert.Equal(t, http.StatusOK, h.get("/z", "10.0.0.1:1", testerKey, "tester").Code, "turned off by a reload")
	assert.Contains(t, scrapeMetrics(t, h.m), "gatekeeper_fault_injection_active 0")
}

func TestGatewayFault_MaxDurationExpiresTheRule(t *testing.T) {
	b := newSplitBackend(t, "b")
	rule := `      enabled: true
      max_duration: 150ms
      abort: {percentage: 100, status: 503}
      count_as_backend_failure: false`
	h := newSplitHarness(t, faultYAML(b.srv.URL, 1000, faultsOnInTest, rule))

	assert.Equal(t, http.StatusServiceUnavailable, h.get("/a", "10.0.0.1:1", testerKey, "tester").Code)
	require.Eventually(t, func() bool {
		return strings.Contains(h.logs.String(), "expired after 150ms; no longer injected")
	}, 5*time.Second, 10*time.Millisecond, "the expiry is logged")
	assert.Equal(t, http.StatusOK, h.get("/b", "10.0.0.1:1", testerKey, "tester").Code)
	assert.Contains(t, scrapeMetrics(t, h.m), "gatekeeper_fault_injection_active 0")

	// A reload that leaves the rule as it was doesn't revive it.
	require.NoError(t, h.gw.Reload())
	assert.Equal(t, http.StatusOK, h.get("/c", "10.0.0.1:1", testerKey, "tester").Code)
}

func TestGatewayFault_RuntimeRuleDroppedWithItsRoute(t *testing.T) {
	b := newSplitBackend(t, "b")
	extra := fmt.Sprintf("  - path_prefix: \"/extra\"\n    target: %q\n    cache: {enabled: false}\n", b.srv.URL)
	h := newSplitHarness(t, faultYAMLWithRoutes(b.srv.URL, 1000, faultsOnInTest, "", extra))

	h.gw.Faults().Put("chaos", "/extra", config.RouteFaultConfig{
		Abort:                 &config.FaultAbort{Percentage: 100, Status: 500},
		CountAsBackendFailure: new(bool),
	}, time.Hour)
	assert.Equal(t, http.StatusInternalServerError, h.get("/extra/x", "10.0.0.1:1", testerKey, "tester").Code)

	h.rewrite(t, faultYAML(b.srv.URL, 1000, faultsOnInTest, ""))
	require.NoError(t, h.gw.Reload())
	assert.Contains(t, h.logs.String(), "runtime rule chaos dropped: route /extra is no longer configured")
	_, ok := h.gw.Faults().Get("chaos")
	assert.False(t, ok)
}

func TestGatewayFault_SpanAttributes(t *testing.T) {
	backend := newBackendRecorder(t, func(int) int { return http.StatusOK })
	route := `    fault_injection:
      enabled: true
      abort: {percentage: 100, status: 503}`
	global := tracingOn + `
fault_injection:
  global_enabled: true
  environment: test
`
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, global, route))

	require.Equal(t, http.StatusServiceUnavailable, tr.get("/api/faulted", withKey()).Code)
	spans := spansByName(tr.rec)
	server := spans["GET /api"][0]
	assert.Equal(t, "abort", mustAttr(t, server, "fault.injected"))
	assert.Contains(t, mustAttr(t, server, "gatekeeper.fault.rule"), "config-")
	attempts := spans[tracing.SpanBackendAttempt]
	require.Len(t, attempts, 4, "retried like a real 503")
	for _, a := range attempts {
		assert.Equal(t, "abort", mustAttr(t, a, "fault.injected"))
		assert.Equal(t, int64(503), mustAttr(t, a, "http.response.status_code"))
	}
	assert.Zero(t, backend.calls.Load())
}
