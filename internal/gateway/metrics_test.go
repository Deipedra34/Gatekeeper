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

	"gatekeeper/internal/middleware"
	"gatekeeper/internal/websocket/wstest"
)

// metricsYAML: API key auth with api_key-scoped limits (burst 2), one
// plain route and one WebSocket route.
func metricsYAML(httpBackend, wsBackend string, burst int) string {
	return fmt.Sprintf(`
storage: {backend: memory}
rate_limit:
  algorithm: fixed_window
  scope: api_key
  tiers:
    default: {requests_per_second: 1, burst: %d}
auth:
  enabled: true
  api_keys: ["sk-live-0123456789abcdef"]
routes:
  - path_prefix: "/ws"
    target: %q
  - path_prefix: "/api"
    target: %q
`, burst, wsBackend, httpBackend)
}

func TestMetrics_RequestDurationIsRecordedByRouteAndStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	ws := httptest.NewServer(wstest.EchoHandler())
	t.Cleanup(ws.Close)
	g := newLBGateway(t, metricsYAML(backend.URL, ws.URL, 3))

	// An established WebSocket connection is not a "request latency"
	// (it uses one of the 3 tokens).
	srv := httptest.NewServer(g.gw)
	t.Cleanup(srv.Close)
	c, _, err := wstest.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", http.Header{"X-Api-Key": {"sk-live-0123456789abcdef"}})
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	c.Close()

	key := http.Header{"X-Api-Key": {"sk-live-0123456789abcdef"}}
	send := func(path string, h http.Header) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range h {
			req.Header[k] = v
		}
		rec := httptest.NewRecorder()
		g.gw.ServeHTTP(rec, req)
		return rec.Code
	}
	require.Equal(t, http.StatusOK, send("/api/a", key))
	require.Equal(t, http.StatusOK, send("/api/b", key))
	require.Equal(t, http.StatusTooManyRequests, send("/api/c", key))
	require.Equal(t, http.StatusUnauthorized, send("/api/d", nil))

	hist := g.m.RequestDuration
	assert.Equal(t, 3, testutil.CollectAndCount(hist), "one series per route+status seen: 200, 429, 401 on /api")
	body := g.metrics(t)
	assert.Contains(t, body, `gatekeeper_request_duration_seconds_count{route="/api",status="200"} 2`)
	assert.Contains(t, body, `gatekeeper_request_duration_seconds_count{route="/api",status="429"} 1`)
	assert.Contains(t, body, `gatekeeper_request_duration_seconds_count{route="/api",status="401"} 1`)
	assert.NotContains(t, body, `gatekeeper_request_duration_seconds_count{route="/ws"`, "the 101 isn't timed")
}

func TestMetrics_APIKeysNeverAppearInLabels(t *testing.T) {
	const apiKey = "sk-live-0123456789abcdef"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	g := newLBGateway(t, metricsYAML(backend.URL, backend.URL, 2))

	for i := 0; i < 3; i++ { // 2 allowed, 1 rejected
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		req.Header.Set("X-Api-Key", apiKey)
		g.gw.ServeHTTP(httptest.NewRecorder(), req)
	}

	body := g.metrics(t)
	assert.NotContains(t, body, apiKey, "the raw key is nowhere in /metrics")
	fp := middleware.APIKeyFingerprint(apiKey)
	assert.Equal(t, "key:8598adc12a31", fp, "matches: printf %%s \"$KEY\" | sha256sum | cut -c1-12")
	assert.Contains(t, body, fmt.Sprintf(`gatekeeper_requests_allowed_total{client=%q,tier="default"} 2`, fp))
	assert.Contains(t, body, fmt.Sprintf(`gatekeeper_requests_rejected_total{client=%q,tier="default"} 1`, fp))
	assert.Contains(t, body, fmt.Sprintf(`gatekeeper_limiter_remaining{client=%q,tier="default"} 0`, fp))
}
