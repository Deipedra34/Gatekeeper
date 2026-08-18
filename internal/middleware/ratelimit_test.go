package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/ratelimiter/store"
)

func newLimiters(t *testing.T, algorithm string, tiers map[string]config.TierLimit) map[string]ratelimiter.Limiter {
	t.Helper()
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })

	limiters := make(map[string]ratelimiter.Limiter, len(tiers))
	for name, tier := range tiers {
		l, err := ratelimiter.New(algorithm, st, ratelimiter.Rule{Rate: tier.RequestsPerSecond, Burst: tier.Burst})
		require.NoError(t, err)
		limiters[name] = l
	}
	return limiters
}

func TestRateLimit_AllowsThenRejectsOverBurst(t *testing.T) {
	cfg := config.RateLimitConfig{Scope: "ip"}
	limiters := newLimiters(t, "token_bucket", map[string]config.TierLimit{
		"default": {RequestsPerSecond: 1, Burst: 2},
	})
	m := metrics.New()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := RateLimit(cfg, limiters, m)(next)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.5:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equalf(t, http.StatusOK, rec.Code, "request %d should be within burst", i+1)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.RequestsRejected.WithLabelValues("203.0.113.5", "default")))
}

func TestRateLimit_DifferentIPsAreIndependent(t *testing.T) {
	cfg := config.RateLimitConfig{Scope: "ip"}
	limiters := newLimiters(t, "token_bucket", map[string]config.TierLimit{
		"default": {RequestsPerSecond: 1, Burst: 1},
	})
	m := metrics.New()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := RateLimit(cfg, limiters, m)(next)

	for _, ip := range []string{"203.0.113.1:1", "203.0.113.2:1"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestRateLimit_UnknownClientFallsBackToDefaultTier(t *testing.T) {
	cfg := config.RateLimitConfig{
		Scope:   "api_key",
		Clients: map[string]string{"known-key": "premium"},
	}
	limiters := newLimiters(t, "token_bucket", map[string]config.TierLimit{
		"default": {RequestsPerSecond: 1, Burst: 1},
		"premium": {RequestsPerSecond: 100, Burst: 100},
	})
	m := metrics.New()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := RateLimit(cfg, limiters, m)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(apiKeyHeader, "unknown-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("X-RateLimit-Limit"), "unknown clients should use the default tier's burst of 1")
}

func TestRateLimit_HeaderScopeUsesConfiguredHeader(t *testing.T) {
	cfg := config.RateLimitConfig{Scope: "header", HeaderName: "X-Client-ID"}
	limiters := newLimiters(t, "token_bucket", map[string]config.TierLimit{
		"default": {RequestsPerSecond: 1, Burst: 1},
	})
	m := metrics.New()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := RateLimit(cfg, limiters, m)(next)

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Client-ID", "tenant-a")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Client-ID", "tenant-b")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code, "a different header value is a different client with its own allowance")
}
