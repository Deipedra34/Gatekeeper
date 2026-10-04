package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

const gatewayTestSecret = "gateway-test-secret-at-least-32-bytes!"

// TestGateway_PerRouteAuthModes loads a config mixing all three auth
// modes and checks each route enforces its own, end to end through the
// real router — including that a route with no auth_mode keeps plain
// API key behaviour.
func TestGateway_PerRouteAuthModes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	path := writeConfig(t, t.TempDir(), "config.yaml", `
rate_limit:
  algorithm: fixed_window
  scope: api_key
  tiers:
    default: {requests_per_second: 100, burst: 100}
auth:
  enabled: true
  api_keys: ["legacy-key"]
  jwt:
    algorithm: HS256
    secret: "`+gatewayTestSecret+`"
routes:
  - path_prefix: "/jwt"
    target: "`+backend.URL+`"
    auth_mode: jwt
  - path_prefix: "/either"
    target: "`+backend.URL+`"
    auth_mode: either
  - path_prefix: "/"
    target: "`+backend.URL+`"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	g, err := gateway.New(cfg, path, st, m, nil)
	require.NoError(t, err)

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(gatewayTestSecret))
	require.NoError(t, err)

	send := func(path, header, value string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if header != "" {
			req.Header.Set(header, value)
		}
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		return rec.Code
	}
	withKey := func(p string) int { return send(p, "X-API-Key", "legacy-key") }
	withJWT := func(p string) int { return send(p, "Authorization", "Bearer "+token) }

	assert.Equal(t, http.StatusOK, withJWT("/jwt/x"))
	assert.Equal(t, http.StatusUnauthorized, withKey("/jwt/x"), "jwt route must not accept an API key")

	assert.Equal(t, http.StatusOK, withJWT("/either/x"))
	assert.Equal(t, http.StatusOK, withKey("/either/x"))
	assert.Equal(t, http.StatusUnauthorized, send("/either/x", "", ""))

	assert.Equal(t, http.StatusOK, withKey("/legacy"), "default route keeps API key auth")
	assert.Equal(t, http.StatusUnauthorized, withJWT("/legacy"), "default route must not accept a JWT")

	assert.Equal(t, float64(2), testutil.ToFloat64(m.AuthRequests.WithLabelValues("jwt", "success")))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.AuthRequests.WithLabelValues("api_key", "success")))
}
