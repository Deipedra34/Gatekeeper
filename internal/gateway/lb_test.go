package gateway_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/tracing"
)

// lbBackend answers with its name; if gate is set, requests for /slow
// wait on it (or on the request being cancelled).
type lbBackend struct {
	name      string
	srv       *httptest.Server
	gate      chan struct{}
	cancelled atomic.Int32
	hits      atomic.Int32
	failing   atomic.Bool
}

func newLBBackend(t *testing.T, name string) *lbBackend {
	t.Helper()
	b := &lbBackend{name: name, gate: make(chan struct{})}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		if r.URL.Path == "/slow" {
			select {
			case <-b.gate:
			case <-r.Context().Done():
				b.cancelled.Add(1)
				return
			}
		}
		if b.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = io.WriteString(w, b.name)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func lbConfig(drain string, retries int, extra string, backends ...*lbBackend) string {
	var list strings.Builder
	for _, b := range backends {
		fmt.Fprintf(&list, "      - target: %q\n", b.srv.URL)
	}
	return fmt.Sprintf(`
storage: {backend: memory}
rate_limit:
  algorithm: fixed_window
  scope: ip
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
auth: {enabled: false}
routes:
  - path_prefix: "/"
    drain_timeout: %s
    cache: {enabled: false}
%s    backends:
%s
proxy:
  timeout: 5s
  retry: {max_retries: %d, base_backoff: 1ms, max_backoff: 2ms}
`, drain, extra, list.String(), retries)
}

type lbGateway struct {
	gw   *gateway.Gateway
	m    *metrics.Metrics
	path string
}

func newLBGateway(t *testing.T, cfgYAML string) *lbGateway {
	t.Helper()
	path := writeConfig(t, t.TempDir(), "config.yaml", cfgYAML)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	g, err := gateway.New(cfg, path, st, m, log.New(io.Discard, "", 0))
	require.NoError(t, err)
	t.Cleanup(g.Close)
	return &lbGateway{gw: g, m: m, path: path}
}

func (g *lbGateway) get(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	g.gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func (g *lbGateway) reload(t *testing.T, cfgYAML string) error {
	t.Helper()
	require.NoError(t, os.WriteFile(g.path, []byte(cfgYAML), 0o644))
	return g.gw.Reload()
}

func (g *lbGateway) metrics(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	g.m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func TestGateway_ReloadAddsRemovesAndDrainsBackends(t *testing.T) {
	a, b, c := newLBBackend(t, "a"), newLBBackend(t, "b"), newLBBackend(t, "c")
	g := newLBGateway(t, lbConfig("10s", 0, "", a, b))

	// Round robin: the first request goes to a, the second — which hangs
	// until released — to b.
	require.Equal(t, "a", g.get("/fast").Body.String())
	inflight := make(chan *httptest.ResponseRecorder, 1)
	go func() { inflight <- g.get("/slow") }()
	require.Eventually(t, func() bool { return b.hits.Load() == 1 }, 2*time.Second, 5*time.Millisecond)

	// Reload: b removed, c added.
	require.NoError(t, g.reload(t, lbConfig("10s", 0, "", a, c)))

	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		seen[g.get("/fast").Body.String()]++
	}
	assert.Equal(t, map[string]int{"a": 5, "c": 5}, seen, "new requests go only to the current backends")
	assert.Equal(t, int32(1), b.hits.Load(), "the removed backend gets nothing new")
	assert.Contains(t, g.metrics(t), fmt.Sprintf(`gatekeeper_backend_draining{backend=%q,route="/"} 1`, b.srv.URL))

	// The request already on b finishes normally.
	close(b.gate)
	select {
	case rec := <-inflight:
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "b", rec.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request to the removed backend never finished")
	}
	assert.Zero(t, b.cancelled.Load())

	// Once drained, b's live-state gauges disappear from /metrics (its
	// request counter, being a counter, stays).
	bUp := fmt.Sprintf(`gatekeeper_backend_up{backend=%q`, b.srv.URL)
	require.Eventually(t, func() bool { return !strings.Contains(g.metrics(t), bUp) }, 5*time.Second, 10*time.Millisecond)
	assert.Contains(t, g.metrics(t), `gatekeeper_route_backends_in_rotation{route="/"} 2`)
}

func TestGateway_ReloadDrainTimeoutCancelsAndRetriesElsewhere(t *testing.T) {
	a, b := newLBBackend(t, "a"), newLBBackend(t, "b")
	g := newLBGateway(t, lbConfig("200ms", 1, "", a, b))

	require.Equal(t, "a", g.get("/fast").Body.String())
	start := time.Now()
	inflight := make(chan *httptest.ResponseRecorder, 1)
	go func() { inflight <- g.get("/slow") }() // to b, which never answers
	require.Eventually(t, func() bool { return b.hits.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	close(a.gate) // a answers /slow immediately

	require.NoError(t, g.reload(t, lbConfig("200ms", 1, "", a)))
	select {
	case rec := <-inflight:
		assert.Equal(t, http.StatusOK, rec.Code, "the cancelled attempt is retried on a remaining backend")
		assert.Equal(t, "a", rec.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("drain timeout did not cancel the straggler")
	}
	assert.Less(t, time.Since(start), 3*time.Second)
	require.Eventually(t, func() bool { return b.cancelled.Load() == 1 }, 2*time.Second, 5*time.Millisecond,
		"the removed backend's request was cancelled at the drain timeout")
}

func TestGateway_ReloadKeepsStateOfUnchangedBackends(t *testing.T) {
	a, b, c := newLBBackend(t, "a"), newLBBackend(t, "b"), newLBBackend(t, "c")
	a.failing.Store(true)
	passive := "    passive_health_check: {consecutive_failures: 1, ejection_duration: 1m}\n"
	g := newLBGateway(t, lbConfig("1s", 0, passive, a, b))
	g.get("/x") // a fails once and is ejected for a minute
	require.Contains(t, g.metrics(t), fmt.Sprintf(`gatekeeper_backend_up{backend=%q,route="/"} 0`, a.srv.URL))

	require.NoError(t, g.reload(t, lbConfig("1s", 0, passive, a, b, c)))
	before := a.hits.Load()
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusOK, g.get("/x").Code)
	}
	assert.Equal(t, before, a.hits.Load(), "a is still ejected after the reload: its state carried over")
	assert.Contains(t, g.metrics(t), `gatekeeper_route_backends_in_rotation{route="/"} 2`)
}

func TestGateway_FailedReloadLeavesBackendsUntouched(t *testing.T) {
	a, b := newLBBackend(t, "a"), newLBBackend(t, "b")
	g := newLBGateway(t, lbConfig("1s", 0, "", a, b))

	bad := strings.Replace(lbConfig("1s", 0, "", a, b), "    backends:\n",
		"    backend_tls: {enabled: true, ca_file: /nonexistent/ca.pem}\n    backends:\n", 1)
	bad = strings.ReplaceAll(bad, "http://", "https://")
	require.Error(t, g.reload(t, bad))

	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		rec := g.get("/x")
		require.Equal(t, http.StatusOK, rec.Code)
		seen[rec.Body.String()]++
	}
	assert.Equal(t, map[string]int{"a": 2, "b": 2}, seen, "the live pool is exactly as before the failed reload")
	assert.NotContains(t, g.metrics(t), "gatekeeper_backend_draining{backend=\""+a.srv.URL+"\",route=\"/\"} 1")
}

func TestGateway_SingleTargetConfigUnchanged(t *testing.T) {
	a := newLBBackend(t, "only")
	g := newLBGateway(t, fmt.Sprintf(`
rate_limit:
  scope: ip
  tiers:
    default: {requests_per_second: 100, burst: 100}
routes:
  - path_prefix: "/"
    target: %q
`, a.srv.URL))
	for i := 0; i < 3; i++ {
		rec := g.get("/x")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "only", rec.Body.String())
	}
	body := g.metrics(t)
	assert.Contains(t, body, `gatekeeper_circuit_breaker_state{route="/"} 0`, "the route-level breaker gauge is still there")
	assert.Contains(t, body, fmt.Sprintf(`gatekeeper_backend_up{backend=%q,route="/"} 1`, a.srv.URL))
	assert.Contains(t, body, `gatekeeper_route_backends_in_rotation{route="/"} 1`)
}

func TestTracing_BackendAttributeOnAttemptSpans(t *testing.T) {
	a, b := newLBBackend(t, "a"), newLBBackend(t, "b")
	a.failing.Store(true)
	cfgYAML := lbConfig("1s", 1, "    passive_health_check: {enabled: false}\n", a, b) + tracingOn
	tr := newTraced(t, cfgYAML)

	require.Equal(t, "b", tr.get("/x", nil).Body.String()) // a fails, the retry goes to b
	attempts := spansByName(tr.rec)[tracing.SpanBackendAttempt]
	require.Len(t, attempts, 2)
	assert.Equal(t, a.srv.URL, mustAttr(t, attempts[0], "gatekeeper.backend"))
	assert.Equal(t, b.srv.URL, mustAttr(t, attempts[1], "gatekeeper.backend"), "the retry went to a different backend")
}
