package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/certgen"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/ratelimiter/store"
)

func issueClient(t *testing.T, opts certgen.Options) *x509.Certificate {
	t.Helper()
	ca, err := certgen.NewCA("Test CA")
	require.NoError(t, err)
	opts.Client = true
	kp, err := ca.Issue(opts)
	require.NoError(t, err)
	return kp.Cert
}

// verifiedRequest is a request whose connection presented cert and had
// it verified by crypto/tls, as it would arrive from an mTLS listener.
func verifiedRequest(cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
	return r
}

func mtlsAuthConfig(mtls config.MTLSConfig) config.AuthConfig {
	cfg := hs256Config()
	cfg.MTLS = mtls
	return cfg
}

func TestCertIdentity_Fields(t *testing.T) {
	cert := issueClient(t, certgen.Options{CommonName: "billing-svc", DNSNames: []string{"billing.internal", "billing.alt"}})

	cases := map[string]string{
		config.IdentityFieldCN:     "billing-svc",
		config.IdentityFieldSANDNS: "billing.internal",
		config.IdentityFieldSerial: fmt.Sprintf("%X", cert.SerialNumber),
	}
	for field, want := range cases {
		t.Run(field, func(t *testing.T) {
			id, err := newCertIdentifier(config.MTLSConfig{IdentityField: field}).identify(cert)
			require.NoError(t, err)
			assert.Equal(t, config.AuthModeMTLS, id.Method)
			assert.Equal(t, want, id.Client)
		})
	}

	// Default field is cn.
	id, err := newCertIdentifier(config.MTLSConfig{}).identify(cert)
	require.NoError(t, err)
	assert.Equal(t, "billing-svc", id.Client)

	// A certificate missing the configured field is rejected.
	noSAN := issueClient(t, certgen.Options{CommonName: "no-san"})
	_, err = newCertIdentifier(config.MTLSConfig{IdentityField: config.IdentityFieldSANDNS}).identify(noSAN)
	assert.Error(t, err)
}

func TestCertIdentity_TierMapping(t *testing.T) {
	ci := newCertIdentifier(config.MTLSConfig{Tiers: map[string]config.MTLSTierMatch{
		"premium": {CN: []string{"vip-client"}, OU: []string{"gold"}},
		"free":    {OU: []string{"trial"}},
	}})

	cases := []struct {
		name string
		opts certgen.Options
		want string
	}{
		{"CN match", certgen.Options{CommonName: "vip-client"}, "premium"},
		{"OU match", certgen.Options{CommonName: "x", OrganizationalUnit: []string{"trial"}}, "free"},
		{"first matching OU", certgen.Options{CommonName: "x", OrganizationalUnit: []string{"unrelated", "gold", "trial"}}, "premium"},
		{"CN beats OU", certgen.Options{CommonName: "vip-client", OrganizationalUnit: []string{"trial"}}, "premium"},
		{"no match falls back to default", certgen.Options{CommonName: "nobody", OrganizationalUnit: []string{"other"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ci.identify(issueClient(t, tc.opts))
			require.NoError(t, err)
			assert.Equal(t, tc.want, id.Tier)
		})
	}
}

func TestAuth_MTLSRoute(t *testing.T) {
	cert := issueClient(t, certgen.Options{CommonName: "svc-a"})
	m := metrics.New()
	var got Identity
	h := newAuth(t, mtlsAuthConfig(config.MTLSConfig{}), config.AuthModeMTLS, m, &got)

	// No TLS at all.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// A certificate that was presented but NOT verified (client_auth
	// "request" or "require") is never trusted.
	unverified := httptest.NewRequest(http.MethodGet, "/", nil)
	unverified.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert}}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, unverified)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// An API key doesn't satisfy an mtls route.
	withKey := httptest.NewRequest(http.MethodGet, "/", nil)
	withKey.Header.Set("X-API-Key", "good-key")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, withKey)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// A verified certificate does.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, verifiedRequest(cert))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, Identity{Method: config.AuthModeMTLS, Client: "svc-a"}, got)

	assert.Equal(t, 1.0, testutil.ToFloat64(m.AuthRequests.WithLabelValues("mtls", "success")))
	assert.Equal(t, 3.0, testutil.ToFloat64(m.AuthRequests.WithLabelValues("mtls", "failure")))
}

func TestAuth_EitherAcceptsMTLS(t *testing.T) {
	cert := issueClient(t, certgen.Options{CommonName: "svc-b"})
	var got Identity
	h := newAuth(t, mtlsAuthConfig(config.MTLSConfig{}), config.AuthModeEither, nil, &got)

	// Certificate alone.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifiedRequest(cert))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, config.AuthModeMTLS, got.Method)

	// An API key takes precedence over the certificate.
	r := verifiedRequest(cert)
	r.Header.Set("X-API-Key", "good-key")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, config.AuthModeAPIKey, got.Method)

	// So does a valid JWT.
	r = verifiedRequest(cert)
	r.Header.Set("Authorization", "Bearer "+signHS256(t, validClaims(), testHMACSecret))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, config.AuthModeJWT, got.Method)

	// Nothing at all still fails with the Bearer challenge, as before.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
}

func TestAuth_ClientCertificateIdentityAvailableOnAnyRoute(t *testing.T) {
	cert := issueClient(t, certgen.Options{CommonName: "svc-c"})
	var fromCtx Identity
	var ok bool
	mw, err := Auth(config.AuthConfig{Enabled: false}, nil, nil)
	require.NoError(t, err)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fromCtx, ok = ClientCertificateFrom(r.Context())
	}))

	h.ServeHTTP(httptest.NewRecorder(), verifiedRequest(cert))
	require.True(t, ok, "available even with auth disabled")
	assert.Equal(t, "svc-c", fromCtx.Client)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.False(t, ok)
}

func TestRateLimit_KeysOnCertificateIdentityAndTier(t *testing.T) {
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	newLimiter := func(burst int64) ratelimiter.Limiter {
		l, err := ratelimiter.New("fixed_window", st, ratelimiter.Rule{Rate: 1, Burst: burst})
		require.NoError(t, err)
		return l
	}
	limiters := map[string]ratelimiter.Limiter{"default": newLimiter(1), "premium": newLimiter(3)}
	m := metrics.New()

	authMW, err := Auth(mtlsAuthConfig(config.MTLSConfig{
		Tiers: map[string]config.MTLSTierMatch{"premium": {OU: []string{"gold"}}},
	}), func(*http.Request) string { return config.AuthModeMTLS }, m)
	require.NoError(t, err)
	h := Chain(okHandler(nil), authMW, RateLimit(config.RateLimitConfig{Scope: "ip"}, limiters, m))

	gold := issueClient(t, certgen.Options{CommonName: "gold-svc", OrganizationalUnit: []string{"gold"}})
	plain := issueClient(t, certgen.Options{CommonName: "plain-svc"})

	send := func(cert *x509.Certificate) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, verifiedRequest(cert))
		return rec.Code
	}
	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusOK, send(gold), "premium tier via OU: burst 3")
	}
	assert.Equal(t, http.StatusTooManyRequests, send(gold))

	assert.Equal(t, http.StatusOK, send(plain), "default tier: burst 1, own bucket despite the shared IP")
	assert.Equal(t, http.StatusTooManyRequests, send(plain))

	assert.Equal(t, 3.0, testutil.ToFloat64(m.RequestsAllowed.WithLabelValues("mtls:gold-svc", "premium")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.RequestsAllowed.WithLabelValues("mtls:plain-svc", "default")))
}
