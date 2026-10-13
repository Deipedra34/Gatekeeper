package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/certgen"
	"gatekeeper/internal/config"
	"gatekeeper/internal/websocket/wstest"
)

// backendPKI is a private CA with a backend server certificate and a
// gateway client certificate, written to disk for backend_tls to load.
type backendPKI struct {
	ca                        *certgen.KeyPair
	caFile                    string
	server                    *certgen.KeyPair
	clientFile, clientKeyFile string
}

func newBackendPKI(t *testing.T, serverOpts certgen.Options) *backendPKI {
	t.Helper()
	dir := t.TempDir()
	ca, err := certgen.NewCA("Backend CA")
	require.NoError(t, err)
	serverOpts.Server = true
	server, err := ca.Issue(serverOpts)
	require.NoError(t, err)
	client, err := ca.Issue(certgen.Options{CommonName: "gatekeeper", Client: true})
	require.NoError(t, err)

	p := &backendPKI{
		ca: ca, server: server,
		caFile:        filepath.Join(dir, "ca.pem"),
		clientFile:    filepath.Join(dir, "gw.pem"),
		clientKeyFile: filepath.Join(dir, "gw-key.pem"),
	}
	require.NoError(t, os.WriteFile(p.caFile, ca.CertPEM, 0o644))
	require.NoError(t, client.WriteFiles(p.clientFile, p.clientKeyFile, 0o600))
	return p
}

func loopbackServerOpts() certgen.Options {
	return certgen.Options{CommonName: "127.0.0.1", IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
}

// tlsBackend starts an HTTPS backend serving h with pki's server
// certificate, requiring a client certificate from pki's CA if
// requireClientCert is set.
func tlsBackend(t *testing.T, pki *backendPKI, requireClientCert bool, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.server.Cert.Raw}, PrivateKey: pki.server.Key}},
	}
	if requireClientCert {
		pool := x509.NewCertPool()
		pool.AddCert(pki.ca.Cert)
		srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		srv.TLS.ClientCAs = pool
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func serve(t *testing.T, router *Router, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

var helloHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	name := "anonymous"
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		name = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	_, _ = io.WriteString(w, "hello "+name)
})

func TestBackendTLS_CustomCA(t *testing.T) {
	pki := newBackendPKI(t, loopbackServerOpts())
	backend := tlsBackend(t, pki, false, helloHandler)

	// Without backend_tls, the private CA isn't trusted: 502.
	router, err := NewRouter([]config.Route{{PathPrefix: "/", Target: backend.URL}}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, serve(t, router, "/").Code)

	// With it, the backend is reached.
	router, err = NewRouter([]config.Route{{
		PathPrefix: "/", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, CAFile: pki.caFile},
	}}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	rec := serve(t, router, "/")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello anonymous", rec.Body.String())
}

func TestBackendTLS_ServerNameOverride(t *testing.T) {
	// The backend's certificate names "orders.internal", not the IP the
	// gateway dials.
	pki := newBackendPKI(t, certgen.Options{CommonName: "orders.internal", DNSNames: []string{"orders.internal"}})
	backend := tlsBackend(t, pki, false, helloHandler)

	route := config.Route{PathPrefix: "/", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, CAFile: pki.caFile}}
	router, err := NewRouter([]config.Route{route}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, serve(t, router, "/").Code, "name mismatch is rejected")

	route.BackendTLS.ServerName = "orders.internal"
	router, err = NewRouter([]config.Route{route}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, serve(t, router, "/").Code)
}

func TestBackendTLS_MutualTLS(t *testing.T) {
	pki := newBackendPKI(t, loopbackServerOpts())
	backend := tlsBackend(t, pki, true, helloHandler)

	route := config.Route{PathPrefix: "/", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, CAFile: pki.caFile}}
	router, err := NewRouter([]config.Route{route}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, serve(t, router, "/").Code, "backend refuses a gateway without a client certificate")

	route.BackendTLS.ClientCertFile, route.BackendTLS.ClientKeyFile = pki.clientFile, pki.clientKeyFile
	router, err = NewRouter([]config.Route{route}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	rec := serve(t, router, "/")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello gatekeeper", rec.Body.String(), "backend saw the gateway's client certificate")
}

func TestBackendTLS_InsecureSkipVerify(t *testing.T) {
	pki := newBackendPKI(t, loopbackServerOpts())
	backend := tlsBackend(t, pki, false, helloHandler)
	router, err := NewRouter([]config.Route{{PathPrefix: "/", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, InsecureSkipVerify: true}}}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, serve(t, router, "/").Code)
}

func TestBackendTLS_InvalidFilesFailRouterBuild(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("nope"), 0o600))
	for name, bt := range map[string]config.BackendTLSConfig{
		"missing CA":          {Enabled: true, CAFile: filepath.Join(t.TempDir(), "missing.pem")},
		"invalid CA":          {Enabled: true, CAFile: garbage},
		"invalid client cert": {Enabled: true, ClientCertFile: garbage, ClientKeyFile: garbage},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewRouter([]config.Route{{PathPrefix: "/", Target: "https://127.0.0.1:1", BackendTLS: bt}}, noRetryProxyConfig(), nil, nil)
			require.Error(t, err)
		})
	}
}

func TestBackendTLS_RetriesAndCircuitBreakerStillApply(t *testing.T) {
	pki := newBackendPKI(t, loopbackServerOpts())
	var calls atomic.Int32
	backend := tlsBackend(t, pki, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))

	cfg := noRetryProxyConfig()
	cfg.Retry.MaxRetries = 2
	router, err := NewRouter([]config.Route{{
		PathPrefix: "/", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, CAFile: pki.caFile},
		CircuitBreaker: config.RouteCircuitBreaker{
			FailureThreshold: 5, HalfOpenMaxRequests: 1, HalfOpenSuccessesToClose: 1, HalfOpenFailuresToReopen: 1,
		},
	}}, cfg, nil, nil)
	require.NoError(t, err)
	_, isRetry := router.routes[0].proxy.Transport.(*retryTransport)
	require.True(t, isRetry, "the TLS transport sits inside the retry transport")
	require.NotNil(t, router.routes[0].breaker)

	rec := serve(t, router, "/")
	assert.Equal(t, http.StatusOK, rec.Code, "a 503 from the HTTPS backend is retried")
	assert.Equal(t, int32(2), calls.Load())
}

func TestBackendTLS_WebSocketOverWSS(t *testing.T) {
	pki := newBackendPKI(t, loopbackServerOpts())
	backend := tlsBackend(t, pki, true, wstest.EchoHandler()) // also requires the gateway's client cert

	router, err := NewRouter([]config.Route{{
		PathPrefix: "/ws", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, CAFile: pki.caFile, ClientCertFile: pki.clientFile, ClientKeyFile: pki.clientKeyFile},
	}}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	roundTrip(t, dialOK(t, wsURL(gw, "/ws"), nil), "over wss with mTLS to the backend")

	// Without the client certificate, the backend handshake fails: 502.
	router, err = NewRouter([]config.Route{{
		PathPrefix: "/ws", Target: backend.URL,
		BackendTLS: config.BackendTLSConfig{Enabled: true, CAFile: pki.caFile},
	}}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, dialStatus(t, wsURL(gatewayFor(t, router), "/ws"), nil))
}
