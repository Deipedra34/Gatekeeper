package admin_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"gatekeeper/internal/admin"
	"gatekeeper/internal/certgen"
	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/tracing"
)

// adminToken is a throwaway token for these tests only; the config
// holds just its SHA-256.
const adminToken = "test-only-admin-token-3f9c1b7e5a"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// adminBlock is an enabled admin section on a random local port,
// accepting adminToken, with the given extra settings indented under
// admin:.
func adminBlock(auditLog, extra string) string {
	return fmt.Sprintf(`
admin:
  enabled: true
  listen: "127.0.0.1:0"
  audit_log: %q
  tokens:
    - id: ops
      sha256: %q
%s
`, auditLog, sha256Hex(adminToken), extra)
}

type harness struct {
	t         *testing.T
	gw        *gateway.Gateway
	metrics   *metrics.Metrics
	srv       *admin.Server
	base      string
	client    *http.Client
	public    *httptest.Server
	cfgPath   string
	auditPath string
}

type harnessOptions struct {
	adminExtra string // extra admin settings
	gwOpts     []gateway.Option
	scheme     string       // "https" for an admin TLS listener
	client     *http.Client // for TLS
}

// start loads gatewayYAML plus an admin block, starts the gateway behind
// a public test server and the admin API on its own listener.
func start(t *testing.T, gatewayYAML string, o harnessOptions) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, cfgPath: filepath.Join(dir, "config.yaml"), auditPath: filepath.Join(dir, "audit.log")}
	h.writeConfig(gatewayYAML + adminBlock(h.auditPath, o.adminExtra))

	cfg, err := config.Load(h.cfgPath)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	h.metrics = metrics.New()
	quiet := log.New(io.Discard, "", 0)
	h.gw, err = gateway.New(cfg, h.cfgPath, st, h.metrics, quiet, o.gwOpts...)
	require.NoError(t, err)
	t.Cleanup(h.gw.Close)

	h.srv, err = admin.New(admin.Options{Config: cfg.Admin, Gateway: h.gw, Metrics: h.metrics, Logger: quiet})
	require.NoError(t, err)
	ln, err := h.srv.Listen()
	require.NoError(t, err)
	go func() { _ = h.srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.srv.Shutdown(ctx)
	})

	scheme := o.scheme
	if scheme == "" {
		scheme = "http"
	}
	h.base = scheme + "://" + ln.Addr().String()
	h.client = o.client
	if h.client == nil {
		h.client = &http.Client{Timeout: 5 * time.Second}
	}
	h.public = httptest.NewServer(h.gw)
	t.Cleanup(h.public.Close)
	return h
}

func (h *harness) writeConfig(yaml string) {
	h.t.Helper()
	require.NoError(h.t, os.WriteFile(h.cfgPath, []byte(yaml), 0o600))
}

type response struct {
	status int
	header http.Header
	raw    string
	json   map[string]any
}

func (r response) errorCode() string {
	e, _ := r.json["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// call makes an admin request; token "" sends no credentials.
func (h *harness) call(method, path, token, body string) response {
	h.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.base+path, rdr)
	require.NoError(h.t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	out := response{status: resp.StatusCode, header: resp.Header, raw: string(raw)}
	_ = json.Unmarshal(raw, &out.json)
	return out
}

// get makes a request through the public proxy listener.
func (h *harness) get(path string, header http.Header) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.public.URL+path, nil)
	require.NoError(h.t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(h.t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (h *harness) auditRecords() []map[string]any {
	h.t.Helper()
	f, err := os.Open(h.auditPath)
	require.NoError(h.t, err)
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		require.NoError(h.t, json.Unmarshal(sc.Bytes(), &rec), sc.Text())
		out = append(out, rec)
	}
	return out
}

// namedBackend answers every request with its name and counts them.
func namedBackend(t *testing.T, name string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// simpleYAML is a gateway with auth off, a generous limit, and one
// route to target.
func simpleYAML(target string) string {
	return fmt.Sprintf(`
rate_limit:
  algorithm: token_bucket
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
  - path_prefix: "/"
    target: %q
`, target)
}

func TestAdmin_TokenAuthentication(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{})

	missing := h.call(http.MethodGet, "/admin/v1/status", "", "")
	assert.Equal(t, http.StatusUnauthorized, missing.status)
	assert.Equal(t, "unauthorized", missing.errorCode())
	assert.Contains(t, missing.header.Get("WWW-Authenticate"), "Bearer")
	assert.Equal(t, "application/json", missing.header.Get("Content-Type"))

	wrong := h.call(http.MethodGet, "/admin/v1/status", "not-the-token", "")
	assert.Equal(t, http.StatusUnauthorized, wrong.status)

	hashAsToken := h.call(http.MethodGet, "/admin/v1/status", sha256Hex(adminToken), "")
	assert.Equal(t, http.StatusUnauthorized, hashAsToken.status, "the stored hash is not itself a credential")

	ok := h.call(http.MethodGet, "/admin/v1/status", adminToken, "")
	require.Equal(t, http.StatusOK, ok.status, ok.raw)
	assert.Equal(t, "dev", ok.json["version"])
	assert.NotEmpty(t, ok.json["go_version"])
	assert.NotEmpty(t, ok.json["config_loaded_at"])
	assert.Contains(t, ok.json, "uptime_seconds")
	assert.Equal(t, "no-store", ok.header.Get("Cache-Control"))

	assert.Equal(t, 2.0, testutil.ToFloat64(h.metrics.AdminAuthFailures.WithLabelValues("invalid_token")))
	assert.Equal(t, 1.0, testutil.ToFloat64(h.metrics.AdminAuthFailures.WithLabelValues("missing_credentials")))
	assert.Equal(t, 1.0, testutil.ToFloat64(h.metrics.AdminRequests.WithLabelValues("GET /admin/v1/status", "200")))
	assert.Equal(t, 3.0, testutil.ToFloat64(h.metrics.AdminRequests.WithLabelValues("GET /admin/v1/status", "401")))
}

func TestAdmin_UnknownPathsAndMethods(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{})

	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/admin/v1/nope", "", "").status,
		"unauthenticated callers can't tell which paths exist")

	notFound := h.call(http.MethodGet, "/admin/v1/nope", adminToken, "")
	assert.Equal(t, http.StatusNotFound, notFound.status)
	assert.Equal(t, "not_found", notFound.errorCode())

	wrongMethod := h.call(http.MethodGet, "/admin/v1/reload", adminToken, "")
	assert.Equal(t, http.StatusMethodNotAllowed, wrongMethod.status)
	assert.Equal(t, "POST", wrongMethod.header.Get("Allow"))
	assert.Equal(t, "method_not_allowed", wrongMethod.errorCode())
}

func TestAdmin_FailedAuthIsRateLimitedPerIP(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{adminExtra: `
  auth_failures: {max_failures: 3, window: 1m}`})

	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/admin/v1/status", fmt.Sprintf("guess-%d", i), "").status)
	}
	locked := h.call(http.MethodGet, "/admin/v1/status", adminToken, "")
	assert.Equal(t, http.StatusTooManyRequests, locked.status, "even the right token is refused while locked out")
	assert.Equal(t, "too_many_auth_failures", locked.errorCode())
	assert.NotEmpty(t, locked.header.Get("Retry-After"))
	assert.Equal(t, 1.0, testutil.ToFloat64(h.metrics.AdminAuthFailures.WithLabelValues("rate_limited")))
}

func TestAdmin_IPAllowlist(t *testing.T) {
	backend, _ := namedBackend(t, "b")

	denied := start(t, simpleYAML(backend.URL), harnessOptions{adminExtra: `
  allowed_cidrs: ["10.0.0.0/8"]`})
	resp := denied.call(http.MethodGet, "/admin/v1/status", adminToken, "")
	assert.Equal(t, http.StatusForbidden, resp.status)
	assert.Equal(t, "forbidden", resp.errorCode())
	assert.Equal(t, 1.0, testutil.ToFloat64(denied.metrics.AdminAuthFailures.WithLabelValues("ip_not_allowed")))

	allowed := start(t, simpleYAML(backend.URL), harnessOptions{adminExtra: `
  allowed_cidrs: ["10.0.0.0/8", "127.0.0.1", "::1/128"]`})
	assert.Equal(t, http.StatusOK, allowed.call(http.MethodGet, "/admin/v1/status", adminToken, "").status)
}

func TestAdmin_MTLSClientCertificate(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	pki, err := certgen.WriteDevPKI(t.TempDir(), certgen.DevPKIOptions{ClientCN: "ops-cert"})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(pki.CA.Cert)
	clientFor := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs},
		}}
	}
	keyPair := func(kp *certgen.KeyPair) tls.Certificate {
		c, err := tls.X509KeyPair(kp.CertPEM, kp.KeyPEM)
		require.NoError(t, err)
		return c
	}

	extra := fmt.Sprintf(`
  mtls:
    enabled: true
    allowed_cns: ["ops-cert"]
  tls:
    enabled: true
    cert_file: %q
    key_file: %q
    client_auth: verify_if_given
    client_ca_file: %q`, pki.ServerFile, pki.ServerKeyFile, pki.CAFile)
	h := start(t, simpleYAML(backend.URL), harnessOptions{adminExtra: extra, scheme: "https", client: clientFor(keyPair(pki.Client))})

	ok := h.call(http.MethodGet, "/admin/v1/status", "", "")
	require.Equal(t, http.StatusOK, ok.status, ok.raw)
	assert.Equal(t, true, ok.json["admin_tls_enabled"])

	h.client = clientFor()
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/admin/v1/status", "", "").status,
		"no certificate, no token")
	assert.Equal(t, http.StatusOK, h.call(http.MethodGet, "/admin/v1/status", adminToken, "").status,
		"a token still works without a certificate")

	intruder, err := pki.CA.Issue(certgen.Options{CommonName: "intruder", Client: true})
	require.NoError(t, err)
	h.client = clientFor(keyPair(intruder))
	notAllowed := h.call(http.MethodGet, "/admin/v1/status", "", "")
	assert.Equal(t, http.StatusUnauthorized, notAllowed.status, "a valid certificate whose CN isn't allowed")
	assert.Equal(t, 1.0, testutil.ToFloat64(h.metrics.AdminAuthFailures.WithLabelValues("certificate_not_allowed")))

	otherCA, err := certgen.NewCA("Some Other CA")
	require.NoError(t, err)
	stranger, err := otherCA.Issue(certgen.Options{CommonName: "ops-cert", Client: true})
	require.NoError(t, err)
	// Go's client won't offer a certificate the server's CA list doesn't
	// cover, so force it to, as a hostile client would.
	strangerCert := keyPair(stranger)
	h.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &strangerCert, nil
		},
	}}}
	resp, err := h.client.Get(h.base + "/admin/v1/status")
	if err == nil {
		resp.Body.Close()
	}
	assert.Error(t, err, "a certificate from an untrusted CA fails the handshake, even with an allowed CN")

	var identities []string
	for _, rec := range h.auditRecords() {
		if id, ok := rec["identity"].(string); ok {
			identities = append(identities, id)
		}
	}
	assert.Contains(t, identities, "cert:ops-cert")
	assert.Contains(t, identities, "token:ops")
}

func TestAdmin_ConfigNeverLeaksSecrets(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	const (
		redisPassword = "redis-pass-SECRET-11111"
		apiKey        = "apikey-SECRET-22222-abcdef"
		jwtSecret     = "jwt-SECRET-33333-0123456789abcdefghijkl"
		targetSecret  = "target-pass-SECRET-44444"
		otelSecret    = "otel-pass-SECRET-55555"
		backendCred   = "backend-cred-SECRET-66666"
	)
	target := strings.Replace(backend.URL, "http://", "http://svc:"+targetSecret+"@", 1)
	yaml := fmt.Sprintf(`
storage:
  backend: redis
  redis: {addr: "127.0.0.1:1", password: %q}
rate_limit:
  algorithm: token_bucket
  scope: api_key
  tiers:
    default: {requests_per_second: 10, burst: 10}
    premium: {requests_per_second: 100, burst: 100}
  clients:
    %q: premium
auth:
  enabled: true
  api_keys: [%q]
  jwt:
    algorithm: HS256
    secret: %q
routes:
  - path_prefix: "/"
    target: %q
    transform:
      request:
        set_headers: {Authorization: "Bearer %s", X-Gateway: "visible"}
tracing:
  enabled: false
  endpoint: "http://collector:%s@otel.example:4318"
`, redisPassword, apiKey, apiKey, jwtSecret, target, backendCred, otelSecret)
	h := start(t, yaml, harnessOptions{})

	resp := h.call(http.MethodGet, "/admin/v1/config", adminToken, "")
	require.Equal(t, http.StatusOK, resp.status, resp.raw)
	for _, secret := range []string{redisPassword, apiKey, jwtSecret, targetSecret, otelSecret, backendCred, adminToken, sha256Hex(adminToken)} {
		assert.NotContains(t, resp.raw, secret)
	}
	fp := middleware.APIKeyFingerprint(apiKey)
	assert.Contains(t, resp.raw, fp, "API keys appear as their fingerprints, as in /metrics")
	assert.Contains(t, resp.raw, "[REDACTED]")
	assert.Contains(t, resp.raw, `"id": "ops"`, "token IDs are not secret")
	assert.Contains(t, resp.raw, `"X-Gateway": "visible"`, "ordinary transform headers are shown")

	auth := resp.json["auth"].(map[string]any)
	assert.Equal(t, []any{fp}, auth["api_keys"])
	assert.Equal(t, "[REDACTED]", auth["jwt"].(map[string]any)["secret"])
	assert.Equal(t, "premium", resp.json["rate_limit"].(map[string]any)["clients"].(map[string]any)[fp])

	routesResp := h.call(http.MethodGet, "/admin/v1/routes", adminToken, "")
	assert.NotContains(t, routesResp.raw, targetSecret)
	backendsResp := h.call(http.MethodGet, "/admin/v1/backends", adminToken, "")
	assert.NotContains(t, backendsResp.raw, targetSecret)

	live := h.gw.Config()
	assert.Equal(t, redisPassword, live.Storage.Redis.Password, "redaction works on a copy")
	assert.Equal(t, []string{apiKey}, live.Auth.APIKeys)
}

func TestAdmin_ReloadValidAndInvalid(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{})
	admin := adminBlock(h.auditPath, "")
	loadedAt := h.gw.ConfigLoadedAt()

	twoRoutes := simpleYAML(backend.URL) + fmt.Sprintf(`
  - path_prefix: "/extra"
    target: %q
`, backend.URL) + admin
	h.writeConfig(twoRoutes)

	dry := h.call(http.MethodPost, "/admin/v1/reload?dry_run=true", adminToken, "")
	require.Equal(t, http.StatusOK, dry.status, dry.raw)
	assert.Equal(t, true, dry.json["valid"])
	assert.Len(t, h.gw.Config().Routes, 1, "a dry run applies nothing")
	assert.Equal(t, loadedAt, h.gw.ConfigLoadedAt())

	ok := h.call(http.MethodPost, "/admin/v1/reload", adminToken, "")
	require.Equal(t, http.StatusOK, ok.status, ok.raw)
	assert.Equal(t, true, ok.json["reloaded"])
	assert.Len(t, h.gw.Config().Routes, 2)
	assert.True(t, h.gw.ConfigLoadedAt().After(loadedAt))

	h.writeConfig(strings.Replace(twoRoutes, "token_bucket", "not_an_algorithm", 1))
	for _, path := range []string{"/admin/v1/reload?dry_run=true", "/admin/v1/reload"} {
		bad := h.call(http.MethodPost, path, adminToken, "")
		assert.Equal(t, http.StatusUnprocessableEntity, bad.status, path)
		assert.Equal(t, "invalid_config", bad.errorCode(), path)
		assert.Contains(t, bad.raw, "rate_limit.algorithm", "the validation error is returned")
	}
	assert.Len(t, h.gw.Config().Routes, 2, "the previous config stays active")
	assert.Equal(t, "token_bucket", h.gw.Config().RateLimit.Algorithm)
}

func TestAdmin_CachePurge(t *testing.T) {
	backend, hits := namedBackend(t, "b")
	yaml := fmt.Sprintf(`
rate_limit:
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
  - path_prefix: "/api"
    target: %q
    cache: {ttl: 1m}
`, backend.URL)
	h := start(t, yaml, harnessOptions{adminExtra: `
  max_body_bytes: 64`})

	h.get("/api/items", nil)
	h.get("/api/items", nil)
	require.Equal(t, int64(1), hits.Load(), "second request is a cache hit")

	stats := h.call(http.MethodGet, "/admin/v1/cache/stats", adminToken, "")
	require.Equal(t, http.StatusOK, stats.status)
	assert.Equal(t, 1.0, stats.json["entries"])
	assert.Equal(t, 1.0, stats.json["hits"])
	assert.Equal(t, map[string]any{"/api": 1.0}, stats.json["entries_by_route"])

	assert.Equal(t, http.StatusBadRequest, h.call(http.MethodPost, "/admin/v1/cache/purge", adminToken, "").status,
		"an empty purge never wipes the cache")
	assert.Equal(t, http.StatusBadRequest, h.call(http.MethodPost, "/admin/v1/cache/purge", adminToken, `{"rout": "/api"}`).status,
		"unknown fields are rejected")
	tooBig := h.call(http.MethodPost, "/admin/v1/cache/purge", adminToken, `{"url_prefix": "`+strings.Repeat("x", 100)+`"}`)
	assert.Equal(t, http.StatusRequestEntityTooLarge, tooBig.status)
	assert.Equal(t, "body_too_large", tooBig.errorCode())

	dry := h.call(http.MethodPost, "/admin/v1/cache/purge?dry_run=true", adminToken, `{"route": "/api"}`)
	require.Equal(t, http.StatusOK, dry.status, dry.raw)
	assert.Equal(t, 1.0, dry.json["purged"])
	h.get("/api/items", nil)
	assert.Equal(t, int64(1), hits.Load(), "a dry run purges nothing")

	none := h.call(http.MethodPost, "/admin/v1/cache/purge", adminToken, `{"url_prefix": "/api/other"}`)
	assert.Equal(t, 0.0, none.json["purged"])

	purged := h.call(http.MethodPost, "/admin/v1/cache/purge", adminToken, `{"url_prefix": "/api/items"}`)
	require.Equal(t, http.StatusOK, purged.status, purged.raw)
	assert.Equal(t, 1.0, purged.json["purged"])
	h.get("/api/items", nil)
	assert.Equal(t, int64(2), hits.Load(), "the purged entry is fetched from the backend again")

	h.get("/api/items", nil)
	all := h.call(http.MethodPost, "/admin/v1/cache/purge", adminToken, `{"all": true}`)
	assert.Equal(t, 1.0, all.json["purged"])
}

func TestAdmin_RateLimitInspectAndReset(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	const apiKey = "client-key-for-reset-test-9d2f"
	yaml := fmt.Sprintf(`
rate_limit:
  algorithm: token_bucket
  scope: api_key
  tiers:
    default: {requests_per_second: 0.01, burst: 2}
auth:
  enabled: true
  api_keys: [%q]
routes:
  - path_prefix: "/"
    target: %q
`, apiKey, backend.URL)
	h := start(t, yaml, harnessOptions{})
	withKey := http.Header{"X-Api-Key": {apiKey}}
	fp := middleware.APIKeyFingerprint(apiKey)

	assert.Equal(t, http.StatusOK, h.get("/x", withKey).StatusCode)
	assert.Equal(t, http.StatusOK, h.get("/x", withKey).StatusCode)
	assert.Equal(t, http.StatusTooManyRequests, h.get("/x", withKey).StatusCode)

	state := h.call(http.MethodGet, "/admin/v1/ratelimits/"+fp, adminToken, "")
	require.Equal(t, http.StatusOK, state.status, state.raw)
	assert.Equal(t, fp, state.json["client"])
	assert.Equal(t, 0.0, state.json["remaining"])
	assert.Equal(t, false, state.json["allowed"])
	assert.Equal(t, "default", state.json["tier"])

	raw := h.call(http.MethodGet, "/admin/v1/ratelimits/"+apiKey, adminToken, "")
	assert.Equal(t, http.StatusBadRequest, raw.status, "a raw API key is refused")
	assert.Equal(t, http.StatusNotFound, h.call(http.MethodGet, "/admin/v1/ratelimits/key:000000000000", adminToken, "").status)

	dry := h.call(http.MethodPost, "/admin/v1/ratelimits/"+fp+"/reset?dry_run=true", adminToken, "")
	require.Equal(t, http.StatusOK, dry.status, dry.raw)
	assert.Equal(t, 0.0, dry.json["remaining"])
	assert.Equal(t, http.StatusTooManyRequests, h.get("/x", withKey).StatusCode, "a dry run resets nothing")

	reset := h.call(http.MethodPost, "/admin/v1/ratelimits/"+fp+"/reset", adminToken, "")
	require.Equal(t, http.StatusOK, reset.status, reset.raw)
	assert.Equal(t, 2.0, reset.json["remaining"])
	assert.Equal(t, http.StatusOK, h.get("/x", withKey).StatusCode, "the client gets through again")

	for _, rec := range h.auditRecords() {
		assert.NotContains(t, rec["path"], apiKey, "a raw key in a URL never reaches the audit log")
	}
}

func TestAdmin_BackendDrainAndEnableShiftTraffic(t *testing.T) {
	a, hitsA := namedBackend(t, "a")
	b, hitsB := namedBackend(t, "b")
	yaml := fmt.Sprintf(`
rate_limit:
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
  - path_prefix: "/"
    lb_strategy: round_robin
    cache: {enabled: false}
    backends:
      - target: %q
      - target: %q
`, a.URL, b.URL)
	h := start(t, yaml, harnessOptions{})

	list := h.call(http.MethodGet, "/admin/v1/backends", adminToken, "")
	require.Equal(t, http.StatusOK, list.status, list.raw)
	ids := map[string]string{}
	for _, item := range list.json["backends"].([]any) {
		be := item.(map[string]any)
		ids[be["target"].(string)] = be["id"].(string)
		assert.Equal(t, true, be["in_rotation"])
		assert.Equal(t, "closed", be["circuit_breaker"])
	}
	idA, idB := ids[a.URL], ids[b.URL]
	require.NotEmpty(t, idA)
	require.NotEmpty(t, idB)

	routes := h.call(http.MethodGet, "/admin/v1/routes", adminToken, "")
	assert.Contains(t, routes.raw, idA, "routes and backends agree on IDs")

	drained := h.call(http.MethodPost, "/admin/v1/backends/"+idA+"/drain", adminToken, "")
	require.Equal(t, http.StatusOK, drained.status, drained.raw)
	assert.Equal(t, false, drained.json["backend"].(map[string]any)["in_rotation"])

	hitsA.Store(0)
	hitsB.Store(0)
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusOK, h.get("/", nil).StatusCode)
	}
	assert.Equal(t, int64(0), hitsA.Load(), "a drained backend gets no new traffic")
	assert.Equal(t, int64(10), hitsB.Load())

	last := h.call(http.MethodPost, "/admin/v1/backends/"+idB+"/drain", adminToken, "")
	assert.Equal(t, http.StatusConflict, last.status, "won't drain the last backend in rotation by default")
	forcedDry := h.call(http.MethodPost, "/admin/v1/backends/"+idB+"/drain?force=true&dry_run=true", adminToken, "")
	assert.Equal(t, http.StatusOK, forcedDry.status)
	assert.Equal(t, http.StatusOK, h.get("/", nil).StatusCode, "the dry run left it in rotation")

	enabled := h.call(http.MethodPost, "/admin/v1/backends/"+idA+"/enable", adminToken, "")
	require.Equal(t, http.StatusOK, enabled.status, enabled.raw)
	hitsA.Store(0)
	hitsB.Store(0)
	for i := 0; i < 10; i++ {
		h.get("/", nil)
	}
	assert.Equal(t, int64(5), hitsA.Load(), "back in round robin")
	assert.Equal(t, int64(5), hitsB.Load())

	assert.Equal(t, http.StatusNotFound, h.call(http.MethodPost, "/admin/v1/backends/ffffffffffff/drain", adminToken, "").status)
}

func TestAdmin_CircuitBreakerReset(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)
	yaml := fmt.Sprintf(`
rate_limit:
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    circuit_breaker: {failure_threshold: 1, open_duration: 1h}
proxy:
  retry: {max_retries: 1, base_backoff: 1ms, max_backoff: 2ms}
`, backend.URL)
	h := start(t, yaml, harnessOptions{})

	h.get("/", nil)
	list := h.call(http.MethodGet, "/admin/v1/backends", adminToken, "")
	be := list.json["backends"].([]any)[0].(map[string]any)
	require.Equal(t, "open", be["circuit_breaker"])
	id := be["id"].(string)

	failing.Store(false)
	assert.Equal(t, http.StatusServiceUnavailable, h.get("/", nil).StatusCode, "open breaker fails fast")

	dry := h.call(http.MethodPost, "/admin/v1/circuit-breakers/"+id+"/reset?dry_run=true", adminToken, "")
	require.Equal(t, http.StatusOK, dry.status, dry.raw)
	assert.Equal(t, http.StatusServiceUnavailable, h.get("/", nil).StatusCode, "a dry run doesn't close it")

	reset := h.call(http.MethodPost, "/admin/v1/circuit-breakers/"+id+"/reset", adminToken, "")
	require.Equal(t, http.StatusOK, reset.status, reset.raw)
	assert.Equal(t, "open", reset.json["previous_state"])
	assert.Equal(t, "closed", reset.json["state"])
	assert.Equal(t, http.StatusOK, h.get("/", nil).StatusCode, "traffic flows again")

	assert.Equal(t, http.StatusNotFound, h.call(http.MethodPost, "/admin/v1/circuit-breakers/ffffffffffff/reset", adminToken, "").status)
}

func TestAdmin_AuditLogAndTracing(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	rec := tracetest.NewSpanRecorder()
	yaml := simpleYAML(backend.URL) + `
tracing:
  enabled: true
  exporter: stdout
`
	h := start(t, yaml, harnessOptions{gwOpts: []gateway.Option{
		gateway.WithTracingOptions(tracing.WithSpanProcessor(rec), tracing.WithStdoutWriter(io.Discard)),
	}})

	h.call(http.MethodGet, "/admin/v1/status", adminToken, "")
	h.call(http.MethodGet, "/admin/v1/status", "wrong-token-value", "")
	h.call(http.MethodPost, "/admin/v1/cache/purge?dry_run=true", adminToken, `{"all": true}`)
	h.call(http.MethodGet, "/admin/v1/ratelimits/raw-secret-looking-client", adminToken, "")

	raw, err := os.ReadFile(h.auditPath)
	require.NoError(t, err)
	for _, secret := range []string{adminToken, "wrong-token-value", sha256Hex(adminToken), "raw-secret-looking-client", `"all"`} {
		assert.NotContains(t, string(raw), secret, "the audit log holds no credentials or request bodies")
	}

	records := h.auditRecords()
	require.Len(t, records, 4)
	ok := records[0]
	assert.Equal(t, "admin_request", ok["event"])
	assert.Equal(t, "127.0.0.1", ok["source_ip"])
	assert.Equal(t, "token:ops", ok["identity"])
	assert.Equal(t, "GET", ok["method"])
	assert.Equal(t, "/admin/v1/status", ok["path"])
	assert.Equal(t, "GET /admin/v1/status", ok["endpoint"])
	assert.Equal(t, 200.0, ok["status"])
	assert.Equal(t, "success", ok["result"])
	assert.NotEmpty(t, ok["time"])
	assert.Len(t, ok["trace_id"], 32, "the trace ID is recorded when tracing is on")

	denied := records[1]
	assert.Equal(t, "denied", denied["result"])
	assert.Equal(t, "invalid_token", denied["reason"])
	assert.Nil(t, denied["identity"])

	assert.Equal(t, true, records[2]["dry_run"])
	assert.Equal(t, "/admin/v1/ratelimits/[redacted]", records[3]["path"])

	var adminSpans int
	for _, s := range rec.Ended() {
		if s.Name() == "GET /admin/v1/status" {
			adminSpans++
		}
	}
	assert.Equal(t, 2, adminSpans, "one span per admin call")
}

func TestAdmin_NeverServedOnThePublicListener(t *testing.T) {
	catchAll, _ := namedBackend(t, "from-catch-all-backend")
	adminRoute, adminHits := namedBackend(t, "from-backend-admin-route")
	yaml := fmt.Sprintf(`
rate_limit:
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
  - path_prefix: "/"
    target: %q
  - path_prefix: "/admin"
    target: %q
    cache: {enabled: false}
`, catchAll.URL, adminRoute.URL)
	h := start(t, yaml, harnessOptions{})
	loadedAt := h.gw.ConfigLoadedAt()

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, err := http.NewRequest(method, h.public.URL+"/admin/v1/reload", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equal(t, "from-backend-admin-route", string(body), "%s /admin/... on the proxy port goes to the backend", method)
	}
	assert.Equal(t, int64(2), adminHits.Load())
	assert.Equal(t, loadedAt, h.gw.ConfigLoadedAt(), "the gateway itself was never reloaded")
}

func TestAdmin_ShutdownStopsTheListener(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{})
	require.Equal(t, http.StatusOK, h.call(http.MethodGet, "/admin/v1/status", adminToken, "").status)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, h.srv.Shutdown(ctx))
	h.client.CloseIdleConnections()
	_, err := h.client.Get(h.base + "/admin/v1/status")
	assert.Error(t, err)
}
