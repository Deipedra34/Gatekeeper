package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
)

const testHMACSecret = "test-secret-that-is-at-least-32-bytes-long"

// okHandler records the Identity the auth middleware attached, so tests
// can assert on what reached the next handler.
func okHandler(got *Identity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			*got, _ = IdentityFrom(r.Context())
		}
		w.WriteHeader(http.StatusOK)
	})
}

func hs256Config() config.AuthConfig {
	return config.AuthConfig{
		Enabled: true,
		Header:  "X-API-Key",
		APIKeys: []string{"good-key"},
		JWT: config.JWTConfig{
			Algorithm:     "HS256",
			Secret:        testHMACSecret,
			ClientIDClaim: "sub",
			TierClaim:     "tier",
		},
	}
}

// writeRSAPublicKey generates a fresh RSA key pair and writes the public
// half as PEM to a temp file, returning the private key and file path.
func writeRSAPublicKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "public.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))
	return key, path
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func signHS256(t *testing.T, claims jwt.MapClaims, secret string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func newAuth(t *testing.T, cfg config.AuthConfig, mode string, m *metrics.Metrics, got *Identity) http.Handler {
	t.Helper()
	mw, err := Auth(cfg, func(*http.Request) string { return mode }, m)
	require.NoError(t, err)
	return mw(okHandler(got))
}

func doAuth(h http.Handler, header, value string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		req.Header.Set(header, value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(token string) string { return "Bearer " + token }

// assertRejectedToken checks a 401 that leaks nothing about why the
// token failed, carrying the RFC 6750 invalid_token challenge.
func assertRejectedToken(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer realm="gatekeeper", error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
	assert.Equal(t, "unauthorized\n", rec.Body.String(), "body must not reveal the validation failure")
}

func TestAuth_JWT_ValidHS256TokenAccepted(t *testing.T) {
	var got Identity
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, &got)

	claims := validClaims()
	claims["tier"] = "premium"
	rec := doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret)))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, Identity{Method: config.AuthModeJWT, Client: "alice", Tier: "premium"}, got)
}

func TestAuth_JWT_ValidRS256TokenAccepted(t *testing.T) {
	key, pubPath := writeRSAPublicKey(t)
	cfg := config.AuthConfig{
		Enabled: true,
		JWT:     config.JWTConfig{Algorithm: "RS256", PublicKeyFile: pubPath, ClientIDClaim: "sub"},
	}
	var got Identity
	h := newAuth(t, cfg, config.AuthModeJWT, nil, &got)

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims()).SignedString(key)
	require.NoError(t, err)
	rec := doAuth(h, "Authorization", bearer(token))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "alice", got.Client)
}

func TestAuth_JWT_ExpiredTokenRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret))))
}

func TestAuth_JWT_TokenWithoutExpRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	claims := validClaims()
	delete(claims, "exp")
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret))))
}

func TestAuth_JWT_NotYetValidTokenRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	claims := validClaims()
	claims["nbf"] = time.Now().Add(time.Hour).Unix()
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret))))
}

func TestAuth_JWT_WrongSignatureRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	forged := signHS256(t, validClaims(), "a-completely-different-secret-of-32-bytes")
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(forged)))
}

func TestAuth_JWT_NoneAlgorithmRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(unsigned)))
}

// TestAuth_JWT_AlgorithmConfusionRejected covers the classic attack on
// RS256: an attacker signs an HS256 token using the (public) RSA key as
// the HMAC secret, hoping the server verifies it with that same key.
func TestAuth_JWT_AlgorithmConfusionRejected(t *testing.T) {
	_, pubPath := writeRSAPublicKey(t)
	cfg := config.AuthConfig{
		Enabled: true,
		JWT:     config.JWTConfig{Algorithm: "RS256", PublicKeyFile: pubPath, ClientIDClaim: "sub"},
	}
	h := newAuth(t, cfg, config.AuthModeJWT, nil, nil)

	pubPEM, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	confused := signHS256(t, validClaims(), string(pubPEM))
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(confused)))
}

func TestAuth_JWT_MissingTokenRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	for name, value := range map[string]string{
		"no header":       "",
		"wrong scheme":    "Basic dXNlcjpwYXNz",
		"empty bearer":    "Bearer ",
		"scheme no space": "Bearer",
	} {
		t.Run(name, func(t *testing.T) {
			header := "Authorization"
			if value == "" {
				header = ""
			}
			rec := doAuth(h, header, value)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, `Bearer realm="gatekeeper"`, rec.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "unauthorized\n", rec.Body.String())
		})
	}
}

func TestAuth_JWT_BearerSchemeIsCaseInsensitive(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)
	rec := doAuth(h, "Authorization", "bearer "+signHS256(t, validClaims(), testHMACSecret))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_JWT_IssuerAndAudienceEnforcedWhenConfigured(t *testing.T) {
	cfg := hs256Config()
	cfg.JWT.Issuer = "https://issuer.example"
	cfg.JWT.Audience = "gatekeeper"
	h := newAuth(t, cfg, config.AuthModeJWT, nil, nil)

	good := validClaims()
	good["iss"] = "https://issuer.example"
	good["aud"] = []string{"other-service", "gatekeeper"}
	assert.Equal(t, http.StatusOK, doAuth(h, "Authorization", bearer(signHS256(t, good, testHMACSecret))).Code)

	wrongIss := validClaims()
	wrongIss["iss"] = "https://evil.example"
	wrongIss["aud"] = "gatekeeper"
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, wrongIss, testHMACSecret))))

	wrongAud := validClaims()
	wrongAud["iss"] = "https://issuer.example"
	wrongAud["aud"] = "someone-else"
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, wrongAud, testHMACSecret))))

	noAud := validClaims()
	noAud["iss"] = "https://issuer.example"
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, noAud, testHMACSecret))))
}

func TestAuth_JWT_MissingClientClaimRejected(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)

	claims := validClaims()
	delete(claims, "sub")
	assertRejectedToken(t, doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret))))
}

func TestAuth_JWT_CustomClientIDClaim(t *testing.T) {
	cfg := hs256Config()
	cfg.JWT.ClientIDClaim = "client_id"
	var got Identity
	h := newAuth(t, cfg, config.AuthModeJWT, nil, &got)

	claims := validClaims()
	claims["client_id"] = "svc-billing"
	require.Equal(t, http.StatusOK, doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret))).Code)
	assert.Equal(t, "svc-billing", got.Client)
}

func TestAuth_JWTRouteDoesNotAcceptAPIKey(t *testing.T) {
	h := newAuth(t, hs256Config(), config.AuthModeJWT, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, doAuth(h, "X-API-Key", "good-key").Code)
}

func TestAuth_EitherModeAcceptsAPIKeyOrJWT(t *testing.T) {
	var got Identity
	h := newAuth(t, hs256Config(), config.AuthModeEither, nil, &got)

	t.Run("valid API key", func(t *testing.T) {
		rec := doAuth(h, "X-API-Key", "good-key")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, config.AuthModeAPIKey, got.Method)
	})

	t.Run("valid JWT", func(t *testing.T) {
		rec := doAuth(h, "Authorization", bearer(signHS256(t, validClaims(), testHMACSecret)))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, config.AuthModeJWT, got.Method)
		assert.Equal(t, "alice", got.Client)
	})

	t.Run("neither", func(t *testing.T) {
		rec := doAuth(h, "", "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, `Bearer realm="gatekeeper"`, rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("invalid API key", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, doAuth(h, "X-API-Key", "bad-key").Code)
	})

	t.Run("invalid JWT", func(t *testing.T) {
		forged := signHS256(t, validClaims(), "a-completely-different-secret-of-32-bytes")
		assertRejectedToken(t, doAuth(h, "Authorization", bearer(forged)))
	})
}

// TestAuth_APIKeyModeUnchanged confirms an api_key route behaves exactly
// like the pre-JWT APIKeyAuth middleware: same status codes, same body,
// no WWW-Authenticate challenge — and a JWT is no substitute for a key.
func TestAuth_APIKeyModeUnchanged(t *testing.T) {
	cfg := hs256Config()
	newMW := newAuth(t, cfg, config.AuthModeAPIKey, nil, nil)
	legacy := APIKeyAuth(cfg)(okHandler(nil))
	// modeFor nil is what a caller that doesn't do per-route modes passes.
	nilMode, err := Auth(cfg, nil, nil)
	require.NoError(t, err)

	cases := []struct{ name, header, value string }{
		{"valid key", "X-API-Key", "good-key"},
		{"missing key", "", ""},
		{"wrong key", "X-API-Key", "bad-key"},
		{"valid JWT instead of key", "Authorization", bearer(signHS256(t, validClaims(), testHMACSecret))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := doAuth(legacy, tc.header, tc.value)
			for _, h := range []http.Handler{newMW, nilMode(okHandler(nil))} {
				got := doAuth(h, tc.header, tc.value)
				assert.Equal(t, want.Code, got.Code)
				assert.Equal(t, want.Body.String(), got.Body.String())
				assert.Empty(t, got.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestAuth_DisabledAllowsAllRequestsInEveryMode(t *testing.T) {
	cfg := hs256Config()
	cfg.Enabled = false
	for _, mode := range []string{config.AuthModeAPIKey, config.AuthModeJWT, config.AuthModeEither} {
		var got Identity
		h := newAuth(t, cfg, mode, nil, &got)
		assert.Equal(t, http.StatusOK, doAuth(h, "", "").Code, mode)
		assert.Equal(t, Identity{}, got, "no identity is attached when auth is off")
	}
}

func TestAuth_RejectsUnreadablePublicKey(t *testing.T) {
	cfg := config.AuthConfig{
		Enabled: true,
		JWT:     config.JWTConfig{Algorithm: "RS256", PublicKeyFile: filepath.Join(t.TempDir(), "missing.pem")},
	}
	_, err := Auth(cfg, nil, nil)
	assert.ErrorContains(t, err, "public_key_file")
}

func TestAuth_RecordsMetricsByMethod(t *testing.T) {
	m := metrics.New()
	h := newAuth(t, hs256Config(), config.AuthModeEither, m, nil)

	doAuth(h, "X-API-Key", "good-key")
	doAuth(h, "X-API-Key", "bad-key")
	doAuth(h, "Authorization", bearer(signHS256(t, validClaims(), testHMACSecret)))
	doAuth(h, "Authorization", bearer(signHS256(t, validClaims(), "a-completely-different-secret-of-32-bytes")))
	doAuth(h, "Authorization", bearer("not-a-jwt"))

	assert.Equal(t, float64(1), testutil.ToFloat64(m.AuthRequests.WithLabelValues("api_key", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.AuthRequests.WithLabelValues("api_key", "failure")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.AuthRequests.WithLabelValues("jwt", "success")))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.AuthRequests.WithLabelValues("jwt", "failure")))
}

// TestAuth_TierMappedFromClaims runs auth and the rate limiter together
// and reads the tier that was applied back from X-RateLimit-Limit, which
// carries the chosen tier's burst.
func TestAuth_TierMappedFromClaims(t *testing.T) {
	rlCfg := config.RateLimitConfig{
		Scope: "api_key",
		// A JWT client must not be tiered via the API-key client map,
		// even when its sub happens to match a mapped key.
		Clients: map[string]string{"alice": "premium"},
	}
	limiters := newLimiters(t, "token_bucket", map[string]config.TierLimit{
		"default": {RequestsPerSecond: 1, Burst: 1},
		"free":    {RequestsPerSecond: 5, Burst: 10},
		"premium": {RequestsPerSecond: 50, Burst: 100},
	})
	m := metrics.New()

	authMW, err := Auth(hs256Config(), func(*http.Request) string { return config.AuthModeJWT }, m)
	require.NoError(t, err)
	h := Chain(okHandler(nil), authMW, RateLimit(rlCfg, limiters, m))

	cases := []struct {
		name      string
		sub       string
		tier      any // nil = claim absent
		wantLimit string
		wantTier  string
	}{
		{"premium claim", "p-user", "premium", "100", "premium"},
		{"free claim", "f-user", "free", "10", "free"},
		{"missing claim falls back to default", "alice", nil, "1", "default"},
		{"unknown tier falls back to default", "u-user", "platinum", "1", "default"},
		{"non-string claim falls back to default", "n-user", 42, "1", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			claims["sub"] = tc.sub
			if tc.tier != nil {
				claims["tier"] = tc.tier
			}
			rec := doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret)))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tc.wantLimit, rec.Header().Get("X-RateLimit-Limit"))
			assert.Equal(t, float64(1), testutil.ToFloat64(m.RequestsAllowed.WithLabelValues("jwt:"+tc.sub, tc.wantTier)),
				"client should be keyed by the namespaced sub claim")
		})
	}
}

// TestRateLimit_JWTClientsDoNotShareAPIKeyBuckets guards against a token
// whose sub equals an API key draining that key's allowance.
func TestRateLimit_JWTClientsDoNotShareAPIKeyBuckets(t *testing.T) {
	rlCfg := config.RateLimitConfig{Scope: "api_key"}
	limiters := newLimiters(t, "token_bucket", map[string]config.TierLimit{
		"default": {RequestsPerSecond: 1, Burst: 1},
	})
	authMW, err := Auth(hs256Config(), func(*http.Request) string { return config.AuthModeEither }, nil)
	require.NoError(t, err)
	h := Chain(okHandler(nil), authMW, RateLimit(rlCfg, limiters, metrics.New()))

	claims := validClaims()
	claims["sub"] = "good-key"
	require.Equal(t, http.StatusOK, doAuth(h, "Authorization", bearer(signHS256(t, claims, testHMACSecret))).Code)
	assert.Equal(t, http.StatusOK, doAuth(h, "X-API-Key", "good-key").Code,
		"the API key's single-request burst must be untouched by the JWT request")
}
