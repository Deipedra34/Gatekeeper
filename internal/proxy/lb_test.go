package proxy

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/websocket/wstest"
)

// named is a backend that answers with its name (and the path it saw),
// or with a configurable failure.
type named struct {
	name   string
	srv    *httptest.Server
	hits   atomic.Int32
	status atomic.Int32 // 0 = 200
	delay  atomic.Int64 // nanoseconds
	health atomic.Int32 // health endpoint status; 0 = 200
}

func newNamed(t *testing.T, name string) *named {
	t.Helper()
	n := &named{name: name}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			if s := n.health.Load(); s != 0 {
				w.WriteHeader(int(s))
				return
			}
			return
		}
		n.hits.Add(1)
		if d := n.delay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		if s := n.status.Load(); s != 0 {
			w.WriteHeader(int(s))
		}
		_, _ = io.WriteString(w, n.name+" "+r.URL.Path)
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func backendList(ns ...*named) []config.BackendConfig {
	out := make([]config.BackendConfig, len(ns))
	for i, n := range ns {
		out[i] = config.BackendConfig{Target: n.srv.URL}
	}
	return out
}

func newLBRouter(t *testing.T, rt config.Route, retries int, m *metrics.Metrics) *Router {
	t.Helper()
	cfg := noRetryProxyConfig()
	cfg.Retry.MaxRetries = retries
	router, err := NewRouter([]config.Route{rt}, cfg, m, nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	return router
}

func get(router http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestLB_SpreadsAcrossBackendsAndJoinsBasePaths(t *testing.T) {
	a, b, c := newNamed(t, "a"), newNamed(t, "b"), newNamed(t, "c")
	backends := backendList(a, b, c)
	backends[2].Target = c.srv.URL + "/v2" // a base path is joined like a single target's
	router := newLBRouter(t, config.Route{PathPrefix: "/api", Backends: backends}, 0, nil)

	bodies := map[string]int{}
	for i := 0; i < 30; i++ {
		rec := get(router, "/api/items?x=1")
		require.Equal(t, http.StatusOK, rec.Code)
		bodies[rec.Body.String()]++
	}
	assert.Equal(t, map[string]int{"a /api/items": 10, "b /api/items": 10, "c /v2/api/items": 10}, bodies)
}

func TestLB_RetryPrefersADifferentBackend(t *testing.T) {
	bad, good := newNamed(t, "bad"), newNamed(t, "good")
	bad.status.Store(http.StatusServiceUnavailable)
	off := false
	router := newLBRouter(t, config.Route{PathPrefix: "/", Backends: backendList(bad, good),
		PassiveHealthCheck: config.PassiveHealthConfig{Enabled: &off}}, 1, nil)

	for i := 0; i < 20; i++ {
		rec := get(router, "/x")
		require.Equal(t, http.StatusOK, rec.Code, "request %d: a 503 from one backend is retried on the other", i)
		assert.Equal(t, "good /x", rec.Body.String())
	}
	assert.Equal(t, int32(20), good.hits.Load())
	assert.Equal(t, int32(10), bad.hits.Load(), "the bad backend is tried only when round robin starts there, never twice per request")
}

func TestLB_CircuitBreakerIsPerBackend(t *testing.T) {
	bad, good := newNamed(t, "bad"), newNamed(t, "good")
	bad.status.Store(http.StatusInternalServerError)
	off := false
	m := metrics.New()
	router := newLBRouter(t, config.Route{PathPrefix: "/r", Backends: backendList(bad, good),
		PassiveHealthCheck: config.PassiveHealthConfig{Enabled: &off},
		CircuitBreaker: config.RouteCircuitBreaker{FailureThreshold: 2, OpenDuration: config.Duration{Duration: time.Minute},
			HalfOpenMaxRequests: 1, HalfOpenSuccessesToClose: 1, HalfOpenFailuresToReopen: 1},
	}, 0, m)

	for i := 0; i < 4; i++ {
		get(router, "/r") // alternates bad, good, bad (trips), good
	}
	pool := router.routes[0].pool
	assert.Equal(t, "open", pool.Backends()[0].Breaker().State().String())
	assert.Equal(t, "closed", pool.Backends()[1].Breaker().State().String(), "one bad backend doesn't trip its sibling")

	badHits := bad.hits.Load()
	for i := 0; i < 10; i++ {
		rec := get(router, "/r")
		require.Equal(t, http.StatusOK, rec.Code, "the route keeps serving from the healthy backend")
	}
	assert.Equal(t, badHits, bad.hits.Load(), "nothing goes to the backend whose circuit is open")

	// Per-backend breaker state is in /metrics; the route-level gauge is
	// only reported for single-target routes.
	assert.Equal(t, 0, testutil.CollectAndCount(m.CircuitBreakerState))
	body := scrape(t, m)
	assert.Contains(t, body, fmt.Sprintf(`gatekeeper_backend_circuit_breaker_state{backend=%q,route="/r"} 1`, bad.srv.URL))
	assert.Contains(t, body, fmt.Sprintf(`gatekeeper_backend_circuit_breaker_state{backend=%q,route="/r"} 0`, good.srv.URL))
}

func TestLB_AllBackendsUnhealthyFailsFastWith503(t *testing.T) {
	a, b := newNamed(t, "a"), newNamed(t, "b")
	a.health.Store(http.StatusServiceUnavailable)
	b.health.Store(http.StatusServiceUnavailable)
	m := metrics.New()
	router := newLBRouter(t, config.Route{PathPrefix: "/", Backends: backendList(a, b),
		HealthCheck: config.HealthCheckConfig{Enabled: true, Interval: config.Duration{Duration: 20 * time.Millisecond},
			Timeout: config.Duration{Duration: 10 * time.Millisecond}, UnhealthyThreshold: 1, HealthyThreshold: 1}.WithDefaults(),
	}, 3, m)

	require.Eventually(t, func() bool {
		return !router.routes[0].pool.Backends()[0].Healthy() && !router.routes[0].pool.Backends()[1].Healthy()
	}, 2*time.Second, 5*time.Millisecond)

	start := time.Now()
	rec := get(router, "/x")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "no healthy backend available\n", rec.Body.String())
	assert.Less(t, time.Since(start), 100*time.Millisecond, "fails fast instead of waiting on dead backends")
	assert.Zero(t, a.hits.Load()+b.hits.Load())
	assert.Contains(t, scrape(t, m), `gatekeeper_route_backends_in_rotation{route="/"} 0`)

	// One recovers: traffic resumes.
	b.health.Store(0)
	require.Eventually(t, func() bool { return get(router, "/x").Code == http.StatusOK }, 2*time.Second, 10*time.Millisecond)
	assert.Contains(t, scrape(t, m), `gatekeeper_route_backends_in_rotation{route="/"} 1`)
}

func TestLB_PassiveHealthEjectsAFailingBackend(t *testing.T) {
	good := newNamed(t, "good")
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // connection refused from now on

	router := newLBRouter(t, config.Route{PathPrefix: "/", Backends: []config.BackendConfig{{Target: deadURL}, {Target: good.srv.URL}},
		PassiveHealthCheck: config.PassiveHealthConfig{ConsecutiveFailures: 2, EjectionDuration: config.Duration{Duration: time.Minute}},
	}, 0, nil) // passive checking is on by default with 2+ backends

	failures := 0
	for i := 0; i < 20; i++ {
		if get(router, "/").Code != http.StatusOK {
			failures++
		}
	}
	assert.Equal(t, 2, failures, "after 2 consecutive failures the dead backend is out, without any probe")
	assert.False(t, router.routes[0].pool.Backends()[0].Healthy())
}

func TestLB_WebSocketStaysOnItsBackend(t *testing.T) {
	echoAs := func(name string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := wstest.Upgrade(w, r)
			if err != nil {
				return
			}
			defer c.Close()
			for {
				op, payload, err := c.ReadMessage()
				if err != nil || op == wstest.OpClose {
					return
				}
				_ = c.WriteText(name + ":" + string(payload))
			}
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	a, b := echoAs("a"), echoAs("b")
	router := newLBRouter(t, config.Route{PathPrefix: "/ws", Backends: []config.BackendConfig{{Target: a.URL}, {Target: b.URL}}}, 0, nil)
	gw := gatewayFor(t, router)

	perBackend := map[string]int{}
	var conns []*wstest.Conn
	for i := 0; i < 4; i++ {
		c := dialOK(t, wsURL(gw, "/ws"), nil)
		conns = append(conns, c)
		var owner string
		for j := 0; j < 5; j++ {
			require.NoError(t, c.WriteText(fmt.Sprint(j)))
			got, err := c.ReadText()
			require.NoError(t, err)
			name, _, _ := strings.Cut(got, ":")
			if owner == "" {
				owner = name
			}
			require.Equal(t, owner, name, "every frame of a connection goes to the backend chosen at handshake")
		}
		perBackend[owner]++
	}
	assert.Equal(t, map[string]int{"a": 2, "b": 2}, perBackend, "handshakes are balanced")
	for _, be := range router.routes[0].pool.Backends() {
		assert.Equal(t, int64(2), be.InFlight(), "an open WebSocket counts as an active connection")
	}
	for _, c := range conns {
		c.Close()
	}
	require.Eventually(t, func() bool {
		return router.routes[0].pool.Backends()[0].InFlight() == 0 && router.routes[0].pool.Backends()[1].InFlight() == 0
	}, 5*time.Second, 10*time.Millisecond)
}

func TestLB_PerBackendTLSSettings(t *testing.T) {
	plain := newNamed(t, "plain")
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secure "+r.URL.Path)
	}))
	t.Cleanup(secure.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw}), 0o644))

	router := newLBRouter(t, config.Route{PathPrefix: "/", Backends: []config.BackendConfig{
		{Target: plain.srv.URL},
		{Target: secure.URL, BackendTLS: &config.BackendTLSConfig{Enabled: true, CAFile: caFile}},
	}}, 0, nil)
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		rec := get(router, "/p")
		require.Equal(t, http.StatusOK, rec.Code)
		seen[rec.Body.String()] = true
	}
	assert.Equal(t, map[string]bool{"plain /p": true, "secure /p": true}, seen)
}

func TestLB_SingleTargetRouteUnchanged(t *testing.T) {
	be := newNamed(t, "only")
	be.status.Store(http.StatusServiceUnavailable)
	m := metrics.New()
	router := newLBRouter(t, config.Route{PathPrefix: "/s", Target: be.srv.URL + "/base",
		CircuitBreaker: config.RouteCircuitBreaker{FailureThreshold: 50, OpenDuration: config.Duration{Duration: time.Minute},
			HalfOpenMaxRequests: 1, HalfOpenSuccessesToClose: 1, HalfOpenFailuresToReopen: 1},
	}, 2, m)

	rec := get(router, "/s/x")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "the last attempt's 5xx is passed through, as before")
	assert.Equal(t, int32(3), be.hits.Load(), "retries go to the one backend there is")
	assert.Equal(t, be.srv.URL+"/base", router.routes[0].cacheTarget, "cache keys use the target exactly as before")
	assert.Equal(t, 1, testutil.CollectAndCount(m.CircuitBreakerState), "the route-level breaker gauge is still reported")
	assert.True(t, router.routes[0].pool.Backends()[0].Healthy(), "no passive ejection for a single target by default")

	be.status.Store(0)
	rec = get(router, "/s/x")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "only /base/s/x", rec.Body.String())
}

func TestLB_ConcurrentLoad(t *testing.T) {
	var ns []*named
	for _, n := range []string{"a", "b", "c"} {
		be := newNamed(t, n)
		be.delay.Store(int64(time.Millisecond))
		ns = append(ns, be)
	}
	m := metrics.New()
	router := newLBRouter(t, config.Route{PathPrefix: "/", LBStrategy: config.LBLeastConnections, Backends: backendList(ns...)}, 1, m)

	var wg sync.WaitGroup
	var ok atomic.Int32
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if get(router, "/load").Code == http.StatusOK {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(2000), ok.Load())
	var total int32
	for _, be := range ns {
		assert.Greater(t, be.hits.Load(), int32(400), "%s got a fair share", be.name)
		total += be.hits.Load()
	}
	assert.Equal(t, int32(2000), total)
	hitsByURL := map[string]int32{}
	for _, n := range ns {
		hitsByURL[n.srv.URL] = n.hits.Load()
	}
	for _, be := range router.routes[0].pool.Backends() {
		assert.Zero(t, be.InFlight())
		assert.Equal(t, float64(hitsByURL[be.Label()]), testutil.ToFloat64(m.BackendRequests.WithLabelValues("/", be.Label(), "success")))
	}
}

// scrape renders m as the /metrics endpoint would.
func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}
