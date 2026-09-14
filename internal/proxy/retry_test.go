package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
)

// fastRetryProxyConfig retries quickly so retry tests don't slow down
// the suite, while still exercising real exponential-backoff-with-jitter
// timing logic.
func fastRetryProxyConfig(maxRetries int) config.ProxyConfig {
	return config.ProxyConfig{
		Timeout: config.Duration{Duration: 500 * time.Millisecond},
		Retry: config.RetryConfig{
			MaxRetries:  maxRetries,
			BaseBackoff: config.Duration{Duration: time.Millisecond},
			MaxBackoff:  config.Duration{Duration: 10 * time.Millisecond},
		},
	}
}

func TestRetryTransport_SuccessfulRequestNeedsNoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: srv.URL},
	}, fastRetryProxyConfig(3), m)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "no retry should happen when the first attempt succeeds")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "success")))
	assert.Equal(t, float64(0), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
}

func TestRetryTransport_FailsOnceThenSucceedsOnRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok after retry"))
	}))
	t.Cleanup(srv.Close)

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: srv.URL},
	}, fastRetryProxyConfig(3), m)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok after retry", rec.Body.String())
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "should retry exactly once after the first failure")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "success")))
}

func TestRetryTransport_ExhaustsRetriesAndFails(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("backend always fails"))
	}))
	t.Cleanup(srv.Close)

	m := metrics.New()
	maxRetries := 3
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: srv.URL},
	}, fastRetryProxyConfig(maxRetries), m)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, int32(maxRetries+1), atomic.LoadInt32(&calls), "should attempt the initial request plus every configured retry")
	assert.Equal(t, float64(maxRetries), testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
	assert.Equal(t, float64(0), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "success")))
}

func TestRetryTransport_DoesNotRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	t.Cleanup(srv.Close)

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: srv.URL},
	}, fastRetryProxyConfig(3), m)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "a 4xx response must not be retried")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "success")), "a 4xx is a completed backend response, not a proxy failure")
}

func TestRetryTransport_RetriesOnConnectionFailure(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	down.Close() // unreachable target

	m := metrics.New()
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: down.URL},
	}, fastRetryProxyConfig(2), m)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, float64(2), testutil.ToFloat64(m.ProxyRetries.WithLabelValues("/")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ProxyOutcomes.WithLabelValues("/", "failure")))
}

func TestRetryTransport_RequestBodyIsPreservedAcrossRetries(t *testing.T) {
	var calls int32
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		lastBody = string(body)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: srv.URL},
	}, fastRetryProxyConfig(3), nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/widgets", strings.NewReader("payload"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	assert.Equal(t, "payload", lastBody, "the retried attempt should see the same request body as the first attempt")
}
