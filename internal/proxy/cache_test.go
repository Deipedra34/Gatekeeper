package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/cache"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

// countingBackend returns an httptest server that answers every request
// with an incrementing body ("resp-1", "resp-2", ...) and, optionally,
// extra response headers — so a test can tell whether a request actually
// reached the backend or was served from cache.
func countingBackend(t *testing.T, extraHeaders http.Header) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		for k, vs := range extraHeaders {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "resp-%d", n)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func boolPtr(b bool) *bool { return &b }

func TestRouter_CacheMissThenHit(t *testing.T) {
	backend, calls := countingBackend(t, nil)

	m := metrics.New()
	respCache := cache.New(store.NewMemoryStore())
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: backend.URL, Cache: config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: time.Minute}}},
	}, noRetryProxyConfig(), m, respCache)
	require.NoError(t, err)

	// First request is a miss: it reaches the backend and gets cached.
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "resp-1", rec1.Body.String())
	assert.Equal(t, "MISS", rec1.Header().Get("X-Cache"))
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	// Second identical request is served from cache: same body, no
	// second backend call.
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "resp-1", rec2.Body.String(), "second request should be served from cache, not the backend")
	assert.Equal(t, "HIT", rec2.Header().Get("X-Cache"))
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "cache hit must not reach the backend")

	assert.Equal(t, float64(1), testutil.ToFloat64(m.CacheMisses.WithLabelValues("/")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CacheHits.WithLabelValues("/")))
}

func TestRouter_CacheTTLExpires(t *testing.T) {
	backend, calls := countingBackend(t, nil)

	respCache := cache.New(store.NewMemoryStore())
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: backend.URL, Cache: config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: 50 * time.Millisecond}}},
	}, noRetryProxyConfig(), nil, respCache)
	require.NoError(t, err)

	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-1", rec1.Body.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	// Still within TTL: served from cache.
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-1", rec2.Body.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	time.Sleep(100 * time.Millisecond)

	// TTL has expired: the next request must reach the backend again.
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-2", rec3.Body.String(), "expired entry should be refreshed from the backend")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestRouter_NoStoreResponseIsNotCached(t *testing.T) {
	backend, calls := countingBackend(t, http.Header{"Cache-Control": []string{"no-store"}})

	respCache := cache.New(store.NewMemoryStore())
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: backend.URL, Cache: config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: time.Minute}}},
	}, noRetryProxyConfig(), nil, respCache)
	require.NoError(t, err)

	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-1", rec1.Body.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	// A Cache-Control: no-store response must never be served from
	// cache: every request reaches the backend.
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-2", rec2.Body.String(), "no-store response must not have been cached")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestRouter_BypassHeaderSkipsCache(t *testing.T) {
	backend, calls := countingBackend(t, nil)

	m := metrics.New()
	respCache := cache.New(store.NewMemoryStore())
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: backend.URL, Cache: config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: time.Minute}}},
	}, noRetryProxyConfig(), m, respCache)
	require.NoError(t, err)

	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-1", rec1.Body.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	// A bypass request must reach the backend even though a valid cache
	// entry exists, and must not count toward hit/miss metrics.
	bypassReq := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	bypassReq.Header.Set(cache.BypassHeader, "1")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, bypassReq)
	assert.Equal(t, "resp-2", rec2.Body.String(), "bypass header should force a fresh backend response")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))

	assert.Equal(t, float64(1), testutil.ToFloat64(m.CacheMisses.WithLabelValues("/")), "bypassed request should not be counted as a miss")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.CacheHits.WithLabelValues("/")))

	// The original cache entry (from the first, non-bypassed request)
	// must still be intact and untouched by the bypass request.
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-1", rec3.Body.String())
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

// brokenStore simulates an unreachable Redis: every operation errors.
type brokenStore struct{}

func (brokenStore) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("connection refused")
}
func (brokenStore) Load(context.Context, string) ([]byte, error) {
	return nil, errors.New("connection refused")
}
func (brokenStore) CompareAndSwap(context.Context, string, []byte, []byte, time.Duration) (bool, error) {
	return false, errors.New("connection refused")
}
func (brokenStore) Ping(context.Context) error { return errors.New("connection refused") }
func (brokenStore) Close() error               { return nil }

func TestRouter_CacheDegradesGracefullyWhenStoreIsDown(t *testing.T) {
	backend, calls := countingBackend(t, nil)

	respCache := cache.New(brokenStore{})
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: backend.URL, Cache: config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: time.Minute}}},
	}, noRetryProxyConfig(), nil, respCache)
	require.NoError(t, err)

	// Every request should still succeed via the backend — a store
	// failure must fail open (skip the cache), never crash or error out
	// the request.
	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		require.NotPanics(t, func() {
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/widgets", nil))
		})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, fmt.Sprintf("resp-%d", i), rec.Body.String())
	}
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "an always-erroring store must never serve a cache hit")
}

func TestRouter_RouteWithCachingDisabledAlwaysHitsBackend(t *testing.T) {
	backend, calls := countingBackend(t, nil)

	respCache := cache.New(store.NewMemoryStore())
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: backend.URL, Cache: config.RouteCache{Enabled: boolPtr(false)}},
	}, noRetryProxyConfig(), nil, respCache)
	require.NoError(t, err)

	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-1", rec1.Body.String())

	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/widgets", nil))
	assert.Equal(t, "resp-2", rec2.Body.String(), "a route with caching disabled must never serve a cached response")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}
