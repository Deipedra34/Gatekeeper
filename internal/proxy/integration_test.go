package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/proxy"
	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/ratelimiter/store"
)

// TestGateway_EndToEnd builds the exact same pipeline cmd/gatekeeper
// wires up — config, storage, per-tier limiters, the full middleware
// chain, and the reverse proxy — and drives it through httptest, to
// verify the pieces integrate correctly rather than just testing each
// in isolation.
func TestGateway_EndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response for " + r.URL.Path))
	}))
	t.Cleanup(backend.Close)

	configYAML := `
storage:
  backend: memory
rate_limit:
  algorithm: token_bucket
  scope: api_key
  tiers:
    default: {requests_per_second: 1, burst: 1}
    premium: {requests_per_second: 100, burst: 100}
  clients:
    "premium-key": premium
auth:
  enabled: true
  header: "X-API-Key"
  api_keys: ["free-key", "premium-key"]
cors:
  enabled: true
  allowed_origins: ["https://app.example.com"]
  allowed_methods: ["GET"]
  allowed_headers: ["X-API-Key"]
routes:
  - path_prefix: "/api"
    target: "` + backend.URL + `"
metrics:
  enabled: true
  path: "/metrics"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(configYAML), 0o644))

	cfg, err := config.Load(path)
	require.NoError(t, err)

	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })

	limiters := make(map[string]ratelimiter.Limiter, len(cfg.RateLimit.Tiers))
	for name, tier := range cfg.RateLimit.Tiers {
		l, err := ratelimiter.New(cfg.RateLimit.Algorithm, st, ratelimiter.Rule{Rate: tier.RequestsPerSecond, Burst: tier.Burst})
		require.NoError(t, err)
		limiters[name] = l
	}

	router, err := proxy.NewRouter(cfg.Routes)
	require.NoError(t, err)

	m := metrics.New()
	handler := middleware.Chain(router,
		middleware.CORS(cfg.CORS),
		middleware.APIKeyAuth(cfg.Auth),
		middleware.RateLimit(cfg.RateLimit, limiters, m),
	)

	t.Run("unauthenticated request is rejected before it reaches the backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/widgets", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("authenticated request within limit is proxied to the backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/widgets", nil)
		req.Header.Set("X-API-Key", "free-key")
		req.Header.Set("Origin", "https://app.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "backend response for /api/widgets")
		assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("free tier's second request in the same instant is rate limited", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/widgets", nil)
		req.Header.Set("X-API-Key", "free-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})

	t.Run("premium tier client is not affected by the free tier client's limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/widgets", nil)
		req.Header.Set("X-API-Key", "premium-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("request to an unrouted path returns 404 even when authenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/unrouted", nil)
		req.Header.Set("X-API-Key", "premium-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("metrics endpoint reports allowed and rejected counts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, cfg.Metrics.Path, nil)
		rec := httptest.NewRecorder()
		m.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "gatekeeper_requests_allowed_total")
		assert.Contains(t, rec.Body.String(), "gatekeeper_requests_rejected_total")
	})
}
