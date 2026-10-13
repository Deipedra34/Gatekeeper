package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/certgen"
	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

// okHandler answers every request with "ok", plus the TLS version it was
// served over.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		w.Header().Set("X-TLS-Version", tls.VersionName(r.TLS.Version))
	}
	_, _ = io.WriteString(w, "ok")
})

func newPKI(t *testing.T) *certgen.DevPKI {
	t.Helper()
	pki, err := certgen.WriteDevPKI(t.TempDir(), certgen.DevPKIOptions{})
	require.NoError(t, err)
	return pki
}

func tlsConfigFor(pki *certgen.DevPKI) config.TLSConfig {
	return config.TLSConfig{
		Enabled:        true,
		CertFile:       pki.ServerFile,
		KeyFile:        pki.ServerKeyFile,
		MinVersion:     "1.2",
		ClientAuth:     config.ClientAuthNone,
		ReloadInterval: config.Duration{Duration: time.Hour},
		HSTS:           config.HSTSConfig{MaxAge: config.DefaultHSTSMaxAge},
	}
}

// running is a started Server and how to reach it.
type running struct {
	srv      *Server
	addr     string // main listener host:port
	redirect string // redirect listener host:port, if any
	metrics  *metrics.Metrics
}

// start serves handler on loopback with cfg (whose listen address is
// filled in), returning once both listeners are accepting.
func start(t *testing.T, cfg *config.Config, handler http.Handler) *running {
	t.Helper()
	mainLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg.Server.ListenAddr = mainLn.Addr().String()

	var redirLn net.Listener
	if cfg.TLS.RedirectHTTPPort != 0 {
		redirLn, err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		cfg.TLS.RedirectHTTPPort = redirLn.Addr().(*net.TCPAddr).Port
	}

	m := metrics.New()
	srv, err := New(cfg, handler, m, log.New(io.Discard, "", 0))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(mainLn, redirLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		assert.NoError(t, <-done)
	})

	r := &running{srv: srv, addr: cfg.Server.ListenAddr, metrics: m}
	if redirLn != nil {
		r.redirect = redirLn.Addr().String()
	}
	return r
}

func baseConfig(tc config.TLSConfig) *config.Config {
	return &config.Config{Server: config.ServerConfig{
		ReadTimeout:  config.Duration{Duration: 5 * time.Second},
		WriteTimeout: config.Duration{Duration: 5 * time.Second},
		IdleTimeout:  config.Duration{Duration: 5 * time.Second},
	}, TLS: tc}
}

// client builds an HTTPS client trusting pki's CA, optionally presenting
// a client certificate. Keep-alives are off so every request is a fresh
// handshake.
func client(pki *certgen.DevPKI, clientCert *certgen.KeyPair, mutate func(*tls.Config)) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(pki.CA.Cert)
	tc := &tls.Config{RootCAs: roots}
	if clientCert != nil {
		// GetClientCertificate rather than Certificates: crypto/tls
		// silently withholds a static certificate whose issuer isn't in
		// the server's acceptable-CA list, which would turn an "untrusted
		// CA" test into a "no certificate" one.
		cert := &tls.Certificate{Certificate: [][]byte{clientCert.Cert.Raw}, PrivateKey: clientCert.Key, Leaf: clientCert.Cert}
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	if mutate != nil {
		mutate(tc)
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, error) {
	t.Helper()
	resp, err := c.Get(url)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

// servedSerial returns the serial number of the certificate the server
// presents on a fresh connection.
func servedSerial(t *testing.T, pki *certgen.DevPKI, addr string) string {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(pki.CA.Cert)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "localhost"})
	require.NoError(t, err)
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
}

func TestServer_PlainHTTPWhenTLSDisabled(t *testing.T) {
	r := start(t, baseConfig(config.TLSConfig{}), okHandler)
	assert.False(t, r.srv.TLSEnabled())

	resp, err := get(t, http.DefaultClient, "http://"+r.addr+"/")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Strict-Transport-Security"))
}

func TestServer_ServesHTTPS(t *testing.T) {
	pki := newPKI(t)
	tc := tlsConfigFor(pki)
	tc.HSTS.Enabled = true
	tc.HSTS.IncludeSubdomains = true
	r := start(t, baseConfig(tc), okHandler)

	resp, err := get(t, client(pki, nil, nil), "https://"+r.addr+"/")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "TLS 1.3", resp.Header.Get("X-TLS-Version"))
	assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))

	// Plain HTTP against the HTTPS port is refused.
	resp, err = get(t, http.DefaultClient, "http://"+r.addr+"/")
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	assert.Equal(t, 1.0, testutil.ToFloat64(r.metrics.TLSHandshakes.WithLabelValues("TLS 1.3")))
	expiry := testutil.ToFloat64(r.metrics.ServerCertificateExpiry())
	assert.InDelta(t, time.Until(pki.Server.Cert.NotAfter).Seconds(), expiry, 60)
	assert.Equal(t, 1.0, testutil.ToFloat64(r.metrics.TLSCertificateReloads.WithLabelValues("success")))
}

func TestServer_EnforcesMinVersion(t *testing.T) {
	pki := newPKI(t)

	t.Run("TLS 1.1 rejected with the default minimum", func(t *testing.T) {
		r := start(t, baseConfig(tlsConfigFor(pki)), okHandler)
		_, err := get(t, client(pki, nil, func(c *tls.Config) {
			c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
		}), "https://"+r.addr+"/")
		require.Error(t, err)

		resp, err := get(t, client(pki, nil, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }), "https://"+r.addr+"/")
		require.NoError(t, err, "TLS 1.2 is accepted by default")
		assert.Equal(t, "TLS 1.2", resp.Header.Get("X-TLS-Version"))

		require.Eventually(t, func() bool {
			return testutil.ToFloat64(r.metrics.TLSHandshakeErrors.WithLabelValues("protocol_version")) == 1
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("TLS 1.2 rejected with min_version 1.3", func(t *testing.T) {
		tc := tlsConfigFor(pki)
		tc.MinVersion = "1.3"
		r := start(t, baseConfig(tc), okHandler)
		_, err := get(t, client(pki, nil, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }), "https://"+r.addr+"/")
		require.Error(t, err)
		_, err = get(t, client(pki, nil, nil), "https://"+r.addr+"/")
		require.NoError(t, err)
	})
}

func TestServer_CipherSuitesRestrictTLS12(t *testing.T) {
	pki := newPKI(t) // ECDSA server key
	tc := tlsConfigFor(pki)
	tc.CipherSuites = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
	r := start(t, baseConfig(tc), okHandler)

	_, err := get(t, client(pki, nil, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}
	}), "https://"+r.addr+"/")
	require.Error(t, err, "a suite outside the allow-list is refused")
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(r.metrics.TLSHandshakeErrors.WithLabelValues("cipher_suite")) == 1
	}, 2*time.Second, 10*time.Millisecond)

	_, err = get(t, client(pki, nil, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }), "https://"+r.addr+"/")
	require.NoError(t, err)
}

func TestServer_MTLSRequireAndVerify(t *testing.T) {
	pki := newPKI(t)
	tc := tlsConfigFor(pki)
	tc.ClientAuth = config.ClientAuthRequireAndVerify
	tc.ClientCAFile = pki.CAFile
	r := start(t, baseConfig(tc), okHandler)
	url := "https://" + r.addr + "/"

	// No client certificate.
	_, err := get(t, client(pki, nil, nil), url)
	require.Error(t, err)

	// A certificate from a CA the gateway doesn't trust.
	rogueCA, err := certgen.NewCA("Rogue CA")
	require.NoError(t, err)
	rogue, err := rogueCA.Issue(certgen.Options{CommonName: "mallory", Client: true})
	require.NoError(t, err)
	_, err = get(t, client(pki, rogue, nil), url)
	require.Error(t, err)

	// A certificate from the trusted CA.
	resp, err := get(t, client(pki, pki.Client, nil), url)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The same certificate over TLS 1.2 too.
	_, err = get(t, client(pki, pki.Client, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }), url)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(r.metrics.MTLSVerifications.WithLabelValues("failure", "no_certificate")) == 1 &&
			testutil.ToFloat64(r.metrics.MTLSVerifications.WithLabelValues("failure", "unknown_authority")) == 1
	}, 2*time.Second, 10*time.Millisecond, "failures counted by reason")
	assert.Equal(t, 2.0, testutil.ToFloat64(r.metrics.MTLSVerifications.WithLabelValues("success", "verified")))
	assert.Equal(t, 2.0, testutil.ToFloat64(r.metrics.TLSHandshakeErrors.WithLabelValues("client_certificate")))
}

func TestServer_MTLSRejectsExpiredClientCertificate(t *testing.T) {
	pki := newPKI(t)
	tc := tlsConfigFor(pki)
	tc.ClientAuth = config.ClientAuthVerifyIfGiven
	tc.ClientCAFile = pki.CAFile
	r := start(t, baseConfig(tc), okHandler)

	expired, err := pki.CA.Issue(certgen.Options{
		CommonName: "old", Client: true,
		NotBefore: time.Now().Add(-48 * time.Hour), ValidFor: 24 * time.Hour,
	})
	require.NoError(t, err)
	_, err = get(t, client(pki, expired, nil), "https://"+r.addr+"/")
	require.Error(t, err)

	// verify_if_given: no certificate at all is fine.
	_, err = get(t, client(pki, nil, nil), "https://"+r.addr+"/")
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(r.metrics.MTLSVerifications.WithLabelValues("failure", "expired")) == 1
	}, 2*time.Second, 10*time.Millisecond)
}

func TestServer_StartupFailsOnBadTLSFiles(t *testing.T) {
	pki := newPKI(t)
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a certificate"), 0o600))

	cases := map[string]func(*config.TLSConfig){
		"missing cert": func(c *config.TLSConfig) { c.CertFile = filepath.Join(dir, "nope.pem") },
		"key mismatch": func(c *config.TLSConfig) { c.KeyFile = pki.ClientKeyFile },
		"missing client CA": func(c *config.TLSConfig) {
			c.ClientAuth, c.ClientCAFile = config.ClientAuthRequireAndVerify, filepath.Join(dir, "nope.pem")
		},
		"invalid client CA": func(c *config.TLSConfig) { c.ClientAuth, c.ClientCAFile = config.ClientAuthRequireAndVerify, garbage },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tc := tlsConfigFor(pki)
			mutate(&tc)
			_, err := New(baseConfig(tc), okHandler, nil, log.New(io.Discard, "", 0))
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "PRIVATE KEY", "errors never include key material")
		})
	}
}

func TestServer_CertificateHotReload(t *testing.T) {
	pki := newPKI(t)
	tc := tlsConfigFor(pki)
	tc.ReloadInterval = config.Duration{Duration: 50 * time.Millisecond}
	r := start(t, baseConfig(tc), okHandler)

	original := servedSerial(t, pki, r.addr)
	assert.Equal(t, pki.Server.Cert.SerialNumber.String(), original)

	// Hold a connection open across the reload: it must keep working.
	keepAlive := client(pki, nil, nil)
	keepAlive.Transport.(*http.Transport).DisableKeepAlives = false
	_, err := get(t, keepAlive, "https://"+r.addr+"/")
	require.NoError(t, err)

	// Rewrite the files; the watcher picks the new pair up.
	next, err := pki.CA.Issue(certgen.Options{CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, Server: true})
	require.NoError(t, err)
	require.NoError(t, next.WriteFiles(pki.ServerFile, pki.ServerKeyFile, 0o600))
	require.Eventually(t, func() bool {
		return servedSerial(t, pki, r.addr) == next.Cert.SerialNumber.String()
	}, 5*time.Second, 25*time.Millisecond, "watcher reloads the rewritten certificate")

	_, err = get(t, keepAlive, "https://"+r.addr+"/")
	require.NoError(t, err, "the existing connection survives the reload")

	// An explicit reload (what SIGHUP does) picks up a third certificate.
	third, err := pki.CA.Issue(certgen.Options{CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, Server: true})
	require.NoError(t, err)
	certPath, keyPath := filepath.Join(t.TempDir(), "third.pem"), filepath.Join(t.TempDir(), "third-key.pem")
	require.NoError(t, third.WriteFiles(certPath, keyPath, 0o600))
	require.NoError(t, r.srv.ReloadCertificates(certPath, keyPath))
	assert.Equal(t, third.Cert.SerialNumber.String(), servedSerial(t, pki, r.addr))
}

func TestServer_InvalidReloadKeepsOldCertificate(t *testing.T) {
	pki := newPKI(t)
	r := start(t, baseConfig(tlsConfigFor(pki)), okHandler)
	original := servedSerial(t, pki, r.addr)

	// Garbage in the certificate file.
	require.NoError(t, os.WriteFile(pki.ServerFile, []byte("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n"), 0o644))
	require.Error(t, r.srv.ReloadCertificates("", ""))
	assert.Equal(t, original, servedSerial(t, pki, r.addr))

	// A valid certificate whose key doesn't match.
	other, err := pki.CA.Issue(certgen.Options{CommonName: "localhost", DNSNames: []string{"localhost"}, Server: true})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pki.ServerFile, other.CertPEM, 0o644))
	require.Error(t, r.srv.ReloadCertificates("", ""))

	// An expired certificate.
	expired, err := pki.CA.Issue(certgen.Options{CommonName: "localhost", Server: true, NotBefore: time.Now().Add(-48 * time.Hour), ValidFor: time.Hour})
	require.NoError(t, err)
	require.NoError(t, expired.WriteFiles(pki.ServerFile, pki.ServerKeyFile, 0o600))
	err = r.srv.ReloadCertificates("", "")
	require.ErrorContains(t, err, "expired")

	// Files that don't exist (a SIGHUP config pointing somewhere wrong).
	require.Error(t, r.srv.ReloadCertificates(filepath.Join(t.TempDir(), "x.pem"), filepath.Join(t.TempDir(), "y.pem")))

	assert.Equal(t, original, servedSerial(t, pki, r.addr), "the original certificate is still served")
	assert.Equal(t, 4.0, testutil.ToFloat64(r.metrics.TLSCertificateReloads.WithLabelValues("failure")))
	assert.Equal(t, 1.0, testutil.ToFloat64(r.metrics.TLSCertificateReloads.WithLabelValues("success")))
}

func TestServer_RedirectsHTTPToHTTPS(t *testing.T) {
	pki := newPKI(t)
	tc := tlsConfigFor(pki)
	tc.RedirectHTTPPort = 1 // replaced with a free port by start
	r := start(t, baseConfig(tc), okHandler)
	_, httpsPort, _ := net.SplitHostPort(r.addr)

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, err := http.NewRequest(method, "http://"+r.redirect+"/api/ping?x=1", strings.NewReader("body"))
		require.NoError(t, err)
		req.Host = "gateway.example.com:" + strconv.Itoa(80)
		resp, err := noFollow.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusPermanentRedirect, resp.StatusCode, method)
		assert.Equal(t, "https://gateway.example.com:"+httpsPort+"/api/ping?x=1", resp.Header.Get("Location"))
	}

	// Following the redirect reaches the HTTPS listener.
	follow := client(pki, nil, nil)
	follow.CheckRedirect = nil
	resp, err := get(t, follow, "http://localhost:"+strings.Split(r.redirect, ":")[1]+"/hello")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https", resp.Request.URL.Scheme)
}

func TestRedirectToHTTPS_OmitsDefaultPort(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/a?b=c", nil)
	redirectToHTTPS("443").ServeHTTP(rec, req)
	assert.Equal(t, "https://example.com/a?b=c", rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://[::1]:8080/", nil)
	redirectToHTTPS("8443").ServeHTTP(rec, req)
	assert.Equal(t, "https://[::1]:8443/", rec.Header().Get("Location"))
}

func TestClassifyHandshakeError(t *testing.T) {
	cases := map[string][2]string{
		"tls: client didn't provide a certificate":                                                  {"client_certificate", "no_certificate"},
		"tls: failed to verify certificate: x509: certificate signed by unknown authority":          {"client_certificate", "unknown_authority"},
		"tls: failed to verify certificate: x509: certificate has expired or is not yet valid: ...": {"client_certificate", "expired"},
		"tls: failed to verify certificate: x509: certificate specifies an incompatible key usage":  {"client_certificate", "invalid"},
		"tls: client offered only unsupported versions: [302 301]":                                  {"protocol_version", ""},
		"tls: no cipher suite supported by both client and server":                                  {"cipher_suite", ""},
		"EOF": {"other", ""},
	}
	for msg, want := range cases {
		reason, mtlsReason := classifyHandshakeError(handshakeErrorPrefix + "127.0.0.1:5555: " + msg)
		assert.Equal(t, want[0], reason, msg)
		assert.Equal(t, want[1], mtlsReason, msg)
	}
}

// TestServer_MTLSRouteThroughGateway runs the real gateway behind an
// mTLS listener: an mtls route accepts only a verified certificate, an
// api_key route is unaffected, and the certificate's CN picks the client's
// rate-limit identity and tier.
func TestServer_MTLSRouteThroughGateway(t *testing.T) {
	pki := newPKI(t) // client CN "dev-client"
	backend := httptest.NewServer(okHandler)
	t.Cleanup(backend.Close)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
rate_limit:
  algorithm: fixed_window
  scope: api_key
  tiers:
    default: {requests_per_second: 1, burst: 1}
    premium: {requests_per_second: 100, burst: 3}
auth:
  enabled: true
  api_keys: ["k1"]
  mtls:
    tiers:
      premium: {cn: ["dev-client"]}
routes:
  - path_prefix: "/secure"
    target: %q
    auth_mode: mtls
  - path_prefix: "/"
    target: %q
tls:
  enabled: true
  cert_file: %q
  key_file: %q
  client_auth: verify_if_given
  client_ca_file: %q
`, backend.URL, backend.URL, pki.ServerFile, pki.ServerKeyFile, pki.CAFile)), 0o600))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)

	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	gw, err := gateway.New(cfg, cfgPath, st, m, log.New(io.Discard, "", 0))
	require.NoError(t, err)
	r := start(t, cfg, gw)
	base := "https://" + r.addr

	withCert := client(pki, pki.Client, nil)
	withoutCert := client(pki, nil, nil)

	resp, err := get(t, withoutCert, base+"/secure/x")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "mtls route without a certificate")

	resp, err = get(t, withCert, base+"/secure/x")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "3", resp.Header.Get("X-Ratelimit-Limit"), "CN dev-client is mapped to the premium tier")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.RequestsAllowed.WithLabelValues("mtls:dev-client", "premium")))

	// The api_key route still wants an API key, certificate or not.
	resp, err = get(t, withCert, base+"/plain")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	assert.Equal(t, 1.0, testutil.ToFloat64(m.AuthRequests.WithLabelValues("mtls", "success")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.AuthRequests.WithLabelValues("mtls", "failure")))
}
