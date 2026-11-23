package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/cache"
	"gatekeeper/internal/config"
	"gatekeeper/internal/fault"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

func faultDur(d time.Duration) config.Duration { return config.Duration{Duration: d} }

// faultRouter builds a router over routes whose fault rules are in force
// (kill switch on, a test environment), and returns it with its
// registry.
func faultRouter(t *testing.T, routes []config.Route, pc config.ProxyConfig, m *metrics.Metrics, c *cache.Cache) *Router {
	t.Helper()
	reg := fault.NewRegistry()
	t.Cleanup(reg.Close)
	reg.Configure(&config.Config{
		Routes:         routes,
		FaultInjection: config.FaultInjectionConfig{GlobalEnabled: true, Environment: config.FaultEnvTest},
	})
	router, err := NewRouter(routes, pc, m, c, WithFaultRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(router.Close)
	return router
}

// faulted is a route to target with fault rule f.
func faulted(target string, f config.RouteFaultConfig) config.Route {
	f.Enabled = true
	return config.Route{PathPrefix: "/", Target: target, FaultInjection: &f}
}

// counted is a backend that answers 200 "ok" and counts its requests.
func counted(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func injected(m *metrics.Metrics, typ string) float64 {
	return testutil.ToFloat64(m.FaultsInjected.WithLabelValues("/", typ))
}

func TestFault_FixedDelay(t *testing.T) {
	srv, calls := counted(t)
	m := metrics.New()
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 100, Fixed: faultDur(80 * time.Millisecond)},
	})}, noRetryProxyConfig(), m, nil)

	start := time.Now()
	rec := get(router, "/x")
	elapsed := time.Since(start)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String(), "a delay alone still reaches the backend")
	assert.Equal(t, int32(1), calls.Load())
	assert.GreaterOrEqual(t, elapsed, 80*time.Millisecond)
	assert.Equal(t, 1.0, injected(m, fault.TypeDelay))
}

func TestFault_DelayRange(t *testing.T) {
	srv, _ := counted(t)
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 100, Min: faultDur(20 * time.Millisecond), Max: faultDur(60 * time.Millisecond)},
	})}, noRetryProxyConfig(), nil, nil)

	for i := 0; i < 10; i++ {
		start := time.Now()
		rec := get(router, "/x")
		elapsed := time.Since(start)
		require.Equal(t, http.StatusOK, rec.Code)
		require.GreaterOrEqual(t, elapsed, 20*time.Millisecond)
		require.Less(t, elapsed, 60*time.Millisecond+500*time.Millisecond, "within the range, give or take scheduling")
	}
}

func TestFault_AbortClientError(t *testing.T) {
	srv, calls := counted(t)
	m := metrics.New()
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: http.StatusTooManyRequests},
	})}, fastRetryProxyConfig(2), m, nil)

	rec := get(router, "/x")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, fault.TypeAbort, rec.Header().Get(FaultHeader))
	assert.Contains(t, rec.Body.String(), "fault injected: 429")
	assert.Zero(t, calls.Load(), "an abort answers in the backend's place")
	assert.Equal(t, 1.0, injected(m, fault.TypeAbort), "a 4xx is never retried")
}

func TestFault_AbortIsRetriedLikeABackend5xx(t *testing.T) {
	srv, calls := counted(t)
	m := metrics.New()
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: http.StatusServiceUnavailable},
	})}, fastRetryProxyConfig(2), m, nil)

	rec := get(router, "/x")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Zero(t, calls.Load())
	assert.Equal(t, 3.0, injected(m, fault.TypeAbort), "every attempt is aborted")
	assert.Equal(t, 2.0, testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
}

func TestFault_RetryMovesToAnUnfaultedBackend(t *testing.T) {
	a, b := newNamed(t, "a"), newNamed(t, "b")
	f := config.RouteFaultConfig{
		Enabled: true,
		Abort:   &config.FaultAbort{Percentage: 100, Status: http.StatusBadGateway},
		Match:   config.FaultMatch{Backends: []string{a.srv.URL}},
	}
	rt := config.Route{PathPrefix: "/", Backends: backendList(a, b), FaultInjection: &f}
	cfg := noRetryProxyConfig()
	cfg.Retry.MaxRetries = 1
	router := faultRouter(t, []config.Route{rt}, cfg, nil, nil)

	for i := 0; i < 6; i++ {
		rec := get(router, "/x")
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "b /x", rec.Body.String(), "a's attempts are aborted, and retried on b")
	}
	assert.Zero(t, a.hits.Load(), "a never sees a request")
}

func TestFault_AbortOpensTheCircuitBreaker(t *testing.T) {
	srv, calls := counted(t)
	m := metrics.New()
	rt := faulted(srv.URL, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: http.StatusInternalServerError},
	})
	rt.CircuitBreaker = config.RouteCircuitBreaker{
		FailureThreshold: 2, OpenDuration: faultDur(time.Minute),
		HalfOpenMaxRequests: 1, HalfOpenSuccessesToClose: 1, HalfOpenFailuresToReopen: 1,
	}
	router := faultRouter(t, []config.Route{rt}, noRetryProxyConfig(), m, nil)

	for i := 0; i < 2; i++ {
		assert.Equal(t, http.StatusInternalServerError, get(router, "/x").Code)
	}
	rec := get(router, "/x")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "the breaker opened on the injected failures")
	assert.Contains(t, rec.Body.String(), "circuit breaker open")
	assert.Zero(t, calls.Load())
	assert.Equal(t, 2.0, injected(m, fault.TypeAbort), "a rejected request never gets as far as the fault")
}

func TestFault_NotCountedAsBackendFailure(t *testing.T) {
	srv, _ := counted(t)
	m := metrics.New()
	no := false
	rt := faulted(srv.URL, config.RouteFaultConfig{
		Abort:                 &config.FaultAbort{Percentage: 100, Status: http.StatusInternalServerError},
		CountAsBackendFailure: &no,
	})
	rt.CircuitBreaker = config.RouteCircuitBreaker{
		FailureThreshold: 2, OpenDuration: faultDur(time.Minute),
		HalfOpenMaxRequests: 1, HalfOpenSuccessesToClose: 1, HalfOpenFailuresToReopen: 1,
	}
	router := faultRouter(t, []config.Route{rt}, fastRetryProxyConfig(2), m, nil)

	for i := 0; i < 5; i++ {
		assert.Equal(t, http.StatusInternalServerError, get(router, "/x").Code, "the breaker never hears of it")
	}
	assert.Equal(t, 5.0, injected(m, fault.TypeAbort), "once per request")
	assert.Zero(t, testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")), "never retried")
	assert.Zero(t, testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
}

func TestFault_DelayAndPerAttemptTimeout(t *testing.T) {
	srv, calls := counted(t)
	pc := noRetryProxyConfig()
	pc.Timeout = faultDur(50 * time.Millisecond)
	delay := &config.FaultDelay{Percentage: 100, Fixed: faultDur(150 * time.Millisecond)}

	countedRouter := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{Delay: delay})}, pc, nil, nil)
	assert.Equal(t, http.StatusBadGateway, get(countedRouter, "/x").Code, "a delay past proxy.timeout fails the attempt like a slow backend")
	assert.Zero(t, calls.Load())

	no := false
	uncounted := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{Delay: delay, CountAsBackendFailure: &no})}, pc, nil, nil)
	assert.Equal(t, http.StatusOK, get(uncounted, "/x").Code, "an uncounted delay is outside the attempt's timeout")
	assert.Equal(t, int32(1), calls.Load())
}

// resetFrom sends a request through router behind a real listener,
// returning the client's error (nil if it got an answer).
func resetFrom(t *testing.T, router http.Handler, path string) error {
	t.Helper()
	front := httptest.NewServer(router)
	t.Cleanup(front.Close)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get(front.URL + path)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return err
}

func TestFault_ConnectionReset(t *testing.T) {
	srv, calls := counted(t)
	m := metrics.New()
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		ConnectionReset: &config.FaultReset{Percentage: 100},
	})}, fastRetryProxyConfig(2), m, nil)

	err := resetFrom(t, router, "/x")
	require.Error(t, err, "the client gets no answer")
	assert.Zero(t, calls.Load())
	assert.Equal(t, 3.0, injected(m, fault.TypeReset), "retried like a backend connection error")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
}

func TestFault_ConnectionResetNotCounted(t *testing.T) {
	srv, _ := counted(t)
	m := metrics.New()
	no := false
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		ConnectionReset:       &config.FaultReset{Percentage: 100},
		CountAsBackendFailure: &no,
	})}, fastRetryProxyConfig(2), m, nil)

	require.Error(t, resetFrom(t, router, "/x"))
	assert.Equal(t, 1.0, injected(m, fault.TypeReset), "never retried")
	assert.Zero(t, testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
}

func TestFault_ConnectionResetIsNeverCached(t *testing.T) {
	srv, calls := counted(t)
	respCache := cache.New(store.NewMemoryStore())
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		ConnectionReset: &config.FaultReset{Percentage: 100},
	})}, noRetryProxyConfig(), nil, respCache)

	for i := 0; i < 2; i++ {
		require.Error(t, resetFrom(t, router, "/cached"), "request %d: an empty answer was never stored", i+1)
	}
	assert.Zero(t, calls.Load())
}

func TestFault_ExemptRequests(t *testing.T) {
	srv, _ := counted(t)
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: http.StatusInternalServerError},
	})}, noRetryProxyConfig(), nil, nil)

	assert.Equal(t, http.StatusInternalServerError, get(router, "/x").Code)
	for _, path := range []string{"/healthz", "/health", "/readyz", "/livez", "/_dashboard/x"} {
		assert.Equal(t, http.StatusOK, get(router, path).Code, path)
	}
	probe := httptest.NewRequest(http.MethodGet, "/x", nil)
	probe.Header.Set("User-Agent", "kube-probe/1.30")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, probe)
	assert.Equal(t, http.StatusOK, rec.Code, "health check probes are never faulted")
}

func TestFault_ClientGoingAwayEndsTheDelay(t *testing.T) {
	srv, calls := counted(t)
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 100, Fixed: faultDur(time.Hour)},
	})}, noRetryProxyConfig(), nil, nil)

	// Settle anything the router starts once, then count.
	runtime.GC()
	before := runtime.NumGoroutine()

	const n = 50
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx))
		}()
	}
	wg.Wait()
	assert.Less(t, time.Since(start), 5*time.Second, "an hour's delay ends when the client goes away")
	assert.Zero(t, calls.Load())

	// Nothing the requests started outlives them.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "no goroutine leaked")
}

func TestFault_ServerShutdownEndsTheDelay(t *testing.T) {
	srv, _ := counted(t)
	router := faultRouter(t, []config.Route{faulted(srv.URL, config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 100, Fixed: faultDur(time.Hour)},
	})}, noRetryProxyConfig(), nil, nil)
	front := httptest.NewServer(router)

	done := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 200 * time.Millisecond}
		resp, err := client.Get(front.URL + "/x")
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	require.Error(t, <-done, "the client gives up")
	closed := make(chan struct{})
	go func() { front.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was still sleeping after its client went away")
	}
}

func TestFault_NoRegistryInjectsNothing(t *testing.T) {
	srv, calls := counted(t)
	rt := faulted(srv.URL, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: http.StatusInternalServerError},
	})
	router, err := NewRouter([]config.Route{rt}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	assert.Equal(t, http.StatusOK, get(router, "/x").Code)
	assert.Equal(t, int32(1), calls.Load())
}

func TestFault_ResetCountsAgainstTheVariant(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	rt := splitRoute(stable, canary, 100)
	rt.FaultInjection = &config.RouteFaultConfig{
		Enabled:         true,
		ConnectionReset: &config.FaultReset{Percentage: 100},
		Match:           config.FaultMatch{Variants: []string{"canary"}},
	}
	m := metrics.New()
	router := faultRouter(t, []config.Route{rt}, noRetryProxyConfig(), m, nil)

	require.Error(t, resetFrom(t, router, "/api/x"))
	assert.Zero(t, canary.hits.Load())
	assert.Equal(t, 1.0, testutil.ToFloat64(m.VariantRequests.WithLabelValues("/api", "canary")),
		"a reset connection is still a request the variant served")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.VariantErrors.WithLabelValues("/api", "canary")),
		"and a failed one, for the split's guardrails")
}
