package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/circuitbreaker"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
)

// toggleBackend starts an httptest server that fails (500) while failing
// is true and succeeds (200, "ok") once flipped to false, so a test can
// drive a backend from unhealthy to recovered.
func toggleBackend(t *testing.T) (srv *httptest.Server, calls *int32, failing *atomic.Bool) {
	t.Helper()
	calls = new(int32)
	failing = &atomic.Bool{}
	failing.Store(true)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, calls, failing
}

func cbRoute(target string, cb config.RouteCircuitBreaker) config.Route {
	return config.Route{PathPrefix: "/", Target: target, CircuitBreaker: cb}
}

func TestCircuitBreaker_TripsOpenAfterThresholdFailuresAndFailsFast(t *testing.T) {
	srv, calls, _ := toggleBackend(t)

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		cbRoute(srv.URL, config.RouteCircuitBreaker{
			FailureThreshold:         2,
			OpenDuration:             config.Duration{Duration: time.Minute},
			HalfOpenMaxRequests:      1,
			HalfOpenSuccessesToClose: 1,
			HalfOpenFailuresToReopen: 1,
		}),
	}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)

	// Two failing requests trip the breaker.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	}
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
	assert.Equal(t, float64(circuitbreaker.Open), testutil.ToFloat64(m.CircuitBreakerState.WithLabelValues("/")))

	// The breaker is now Open: further requests must fail fast (503)
	// without ever reaching the backend.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "an open circuit must not reach the backend")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CircuitBreakerRejections.WithLabelValues("/")))
}

func TestCircuitBreaker_DoesNotRetryIntoAnAlreadyOpenCircuit(t *testing.T) {
	srv, calls, _ := toggleBackend(t)

	m := metrics.New()
	proxyCfg := config.ProxyConfig{
		Timeout: config.Duration{Duration: 2 * time.Second},
		Retry: config.RetryConfig{
			MaxRetries:  5, // up to 6 attempts, if nothing stopped it early
			BaseBackoff: config.Duration{Duration: time.Millisecond},
			MaxBackoff:  config.Duration{Duration: 5 * time.Millisecond},
		},
	}
	router, err := NewRouter([]config.Route{
		cbRoute(srv.URL, config.RouteCircuitBreaker{
			FailureThreshold:         2,
			OpenDuration:             config.Duration{Duration: time.Minute},
			HalfOpenMaxRequests:      1,
			HalfOpenSuccessesToClose: 1,
			HalfOpenFailuresToReopen: 1,
		}),
	}, proxyCfg, m, nil)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "the request should end in a circuit-open rejection, not a retry-exhausted 500")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "only enough attempts to trip the breaker should reach the backend, not all 6")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")), "only one attempt should have been counted as a retry before the circuit opened")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CircuitBreakerRejections.WithLabelValues("/")))
}

func TestCircuitBreaker_TransitionsToHalfOpenAndClosesOnSuccessfulTrial(t *testing.T) {
	srv, calls, failing := toggleBackend(t)

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		cbRoute(srv.URL, config.RouteCircuitBreaker{
			FailureThreshold:         1,
			OpenDuration:             config.Duration{Duration: 30 * time.Millisecond},
			HalfOpenMaxRequests:      1,
			HalfOpenSuccessesToClose: 1,
			HalfOpenFailuresToReopen: 1,
		}),
	}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)

	// One failure trips the breaker.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, float64(circuitbreaker.Open), testutil.ToFloat64(m.CircuitBreakerState.WithLabelValues("/")))

	// Backend recovers, and the cooldown elapses.
	failing.Store(false)
	time.Sleep(60 * time.Millisecond)

	// The trial request should reach the backend and succeed, closing
	// the breaker.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "the half-open trial should have reached the backend")
	assert.Equal(t, float64(circuitbreaker.Closed), testutil.ToFloat64(m.CircuitBreakerState.WithLabelValues("/")))

	// Fully closed again: subsequent requests go straight through.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(3), atomic.LoadInt32(calls))
}

func TestCircuitBreaker_FailedTrialReopensCircuit(t *testing.T) {
	srv, calls, _ := toggleBackend(t) // stays failing throughout

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		cbRoute(srv.URL, config.RouteCircuitBreaker{
			FailureThreshold:         1,
			OpenDuration:             config.Duration{Duration: 30 * time.Millisecond},
			HalfOpenMaxRequests:      1,
			HalfOpenSuccessesToClose: 1,
			HalfOpenFailuresToReopen: 1,
		}),
	}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)

	// Trip it.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	time.Sleep(60 * time.Millisecond) // let the cooldown elapse

	// Trial request reaches the still-failing backend and re-opens it.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "the half-open trial should have reached the backend")
	assert.Equal(t, float64(circuitbreaker.Open), testutil.ToFloat64(m.CircuitBreakerState.WithLabelValues("/")))

	// Immediately re-opened: the next request fails fast again without
	// reaching the backend.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestCircuitBreaker_DisabledRouteNeverTrips(t *testing.T) {
	srv, calls, _ := toggleBackend(t) // always failing

	router, err := NewRouter([]config.Route{
		cbRoute(srv.URL, config.RouteCircuitBreaker{Enabled: boolPtr(false), FailureThreshold: 1}),
	}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "a disabled breaker must never fail fast with 503")
	}
	assert.Equal(t, int32(5), atomic.LoadInt32(calls), "every request should have reached the backend")
}
