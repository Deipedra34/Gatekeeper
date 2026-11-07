package gateway_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket/wstest"
)

// seenRequest is what a backend received.
type seenRequest struct {
	path, rawPath, query string
	header               http.Header
}

// recordingBackend records every request and answers with status and
// the given extra response headers.
type recordingBackend struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []seenRequest
	hits atomic.Int64
}

func newRecordingBackend(t *testing.T, status func(n int64) int, respHeader http.Header) *recordingBackend {
	t.Helper()
	b := &recordingBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := b.hits.Add(1)
		b.mu.Lock()
		b.seen = append(b.seen, seenRequest{path: r.URL.Path, rawPath: r.URL.RawPath, query: r.URL.RawQuery, header: r.Header.Clone()})
		b.mu.Unlock()
		for k, v := range respHeader {
			w.Header()[k] = v
		}
		code := http.StatusOK
		if status != nil {
			code = status(n)
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *recordingBackend) last(t *testing.T) seenRequest {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	require.NotEmpty(t, b.seen, "the backend received no request")
	return b.seen[len(b.seen)-1]
}

func (b *recordingBackend) all() []seenRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]seenRequest(nil), b.seen...)
}

type transformGateway struct {
	gw      *gateway.Gateway
	srv     *httptest.Server
	metrics *metrics.Metrics
	path    string
}

// startTransformGateway serves cfgYAML on a real listener, so requests
// arrive with a real peer address and go through the full proxy path.
func startTransformGateway(t *testing.T, cfgYAML string, opts ...gateway.Option) *transformGateway {
	t.Helper()
	path := writeConfig(t, t.TempDir(), "config.yaml", cfgYAML)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	gw, err := gateway.New(cfg, path, st, m, nil, opts...)
	require.NoError(t, err)
	t.Cleanup(gw.Close)
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	return &transformGateway{gw: gw, srv: srv, metrics: m, path: path}
}

func (g *transformGateway) get(t *testing.T, path string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, g.srv.URL+path, nil)
	require.NoError(t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (g *transformGateway) transforms(route, kind string) float64 {
	return testutil.ToFloat64(g.metrics.TransformsApplied.WithLabelValues(route, kind))
}

// transformYAML is a config with auth off and a generous limit; routes
// and top are spliced in as given.
func transformYAML(routes, top string) string {
	return `
rate_limit:
  algorithm: token_bucket
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
` + routes + "\n" + top
}

func TestTransform_StripPrefixAndRegexRewriteReachTheBackend(t *testing.T) {
	b := newRecordingBackend(t, nil, nil)
	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/api"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        strip_prefix: true
        rewrite: {pattern: "^/v1/(?P<resource>[a-z]+)/(\\d+)$", replacement: "/v2/${resource}/$2"}
  - path_prefix: "/plain"
    target: %q
    cache: {enabled: false}`, b.srv.URL, b.srv.URL), ""))

	g.get(t, "/api/v1/users/42?expand=1", nil)
	got := b.last(t)
	assert.Equal(t, "/v2/users/42", got.path)
	assert.Equal(t, "expand=1", got.query)

	g.get(t, "/api/health", nil)
	assert.Equal(t, "/health", b.last(t).path, "strip_prefix applies even when the rewrite doesn't match")

	g.get(t, "/plain/v1/users/42", nil)
	assert.Equal(t, "/plain/v1/users/42", b.last(t).path, "a route without transform is forwarded as is")

	assert.Equal(t, 2.0, g.transforms("/api", "path"))
	assert.Equal(t, 0.0, g.transforms("/plain", "path"))
}

func TestTransform_HeadersAndQueryOnRequestAndResponse(t *testing.T) {
	b := newRecordingBackend(t, nil, http.Header{
		"Server": {"nginx/1.25"}, "X-Powered-By": {"Express"}, "X-Backend": {"b1"},
	})
	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        add_headers: {X-Gateway: "gatekeeper", X-Keep: "default"}
        set_headers: {X-Route: "${route}", X-Client-IP: "${client_ip}"}
        remove_headers: ["X-Debug"]
        add_query_params: {source: "gw"}
        remove_query_params: ["debug"]
      response:
        set_headers: {X-Backend: "hidden"}
        add_headers: {X-Served-By: "gatekeeper"}
        remove_headers: ["Server", "X-Powered-By"]
        security_headers: {enabled: true}`, b.srv.URL), ""))

	resp := g.get(t, "/items?debug=1&page=2", http.Header{
		"X-Debug": {"on"}, "X-Keep": {"client"}, "X-Route": {"forged"},
	})
	got := b.last(t)
	assert.Equal(t, "gatekeeper", got.header.Get("X-Gateway"))
	assert.Equal(t, "client", got.header.Get("X-Keep"), "add_headers keeps the client's value")
	assert.Equal(t, []string{"/"}, got.header.Values("X-Route"), "set_headers replaces the client's value")
	assert.Equal(t, "127.0.0.1", got.header.Get("X-Client-IP"))
	assert.Empty(t, got.header.Get("X-Debug"))
	assert.Equal(t, "page=2&source=gw", got.query)

	assert.Empty(t, resp.Header.Get("Server"))
	assert.Empty(t, resp.Header.Get("X-Powered-By"))
	assert.Equal(t, "hidden", resp.Header.Get("X-Backend"))
	assert.Equal(t, "gatekeeper", resp.Header.Get("X-Served-By"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))

	for _, kind := range []string{"query", "request_headers", "response_headers"} {
		assert.Equal(t, 1.0, g.transforms("/", kind), kind)
	}
}

func TestTransform_SecurityHeadersOnGatewayErrors(t *testing.T) {
	g := startTransformGateway(t, transformYAML(`
  - path_prefix: "/"
    target: "http://127.0.0.1:1"
    cache: {enabled: false}`, `
proxy:
  retry: {max_retries: 1, base_backoff: 1ms, max_backoff: 2ms}
transform:
  security_headers: {enabled: true, referrer_policy: same-origin}`))

	resp := g.get(t, "/x", nil)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), "global security headers cover the gateway's own errors")
	assert.Equal(t, "same-origin", resp.Header.Get("Referrer-Policy"))
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestTransform_RequestIDGeneratedAndPropagated(t *testing.T) {
	b := newRecordingBackend(t, nil, http.Header{"X-Request-Id": {"backend-made-this-up"}})
	g := startTransformGateway(t, fmt.Sprintf(`
rate_limit:
  scope: api_key
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
auth:
  enabled: true
  api_keys: ["k-request-id-test"]
routes:
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        set_headers: {X-Correlation-ID: "${request_id}"}
transform:
  request_id: {enabled: true}
`, b.srv.URL))
	key := http.Header{"X-Api-Key": {"k-request-id-test"}}

	resp := g.get(t, "/x", key)
	id := resp.Header.Get("X-Request-ID")
	assert.Regexp(t, uuidV4, id, "a new ID is generated when the client sends none")
	assert.Equal(t, []string{id}, resp.Header.Values("X-Request-ID"), "the backend's own value is replaced, not added")
	got := b.last(t)
	assert.Equal(t, id, got.header.Get("X-Request-ID"), "the backend gets the same ID")
	assert.Equal(t, id, got.header.Get("X-Correlation-ID"), "${request_id} expands to it")

	own := http.Header{"X-Api-Key": key["X-Api-Key"], "X-Request-Id": {"client-trace-123"}}
	resp = g.get(t, "/x", own)
	assert.Equal(t, "client-trace-123", resp.Header.Get("X-Request-ID"), "a valid client ID is kept")
	assert.Equal(t, "client-trace-123", b.last(t).header.Get("X-Request-ID"))

	for _, bad := range []string{"has spaces in it", strings.Repeat("a", 129), `quote"d`} {
		hdr := http.Header{"X-Api-Key": key["X-Api-Key"], "X-Request-Id": {bad}}
		resp = g.get(t, "/x", hdr)
		assert.Regexp(t, uuidV4, resp.Header.Get("X-Request-ID"), "an unsafe client ID is replaced: %q", bad)
	}

	unauth := g.get(t, "/x", nil)
	assert.Equal(t, http.StatusUnauthorized, unauth.StatusCode)
	assert.Regexp(t, uuidV4, unauth.Header.Get("X-Request-ID"), "rejections carry an ID too")
}

func TestTransform_TrustForwardedHeadersOffAndOn(t *testing.T) {
	spoofed := http.Header{
		"X-Forwarded-For":   {"6.6.6.6"},
		"X-Real-Ip":         {"6.6.6.6"},
		"X-Forwarded-Host":  {"evil.example"},
		"X-Forwarded-Proto": {"https"},
		"Forwarded":         {"for=6.6.6.6"},
	}

	t.Run("off by default: set from the connection", func(t *testing.T) {
		b := newRecordingBackend(t, nil, nil)
		g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        set_headers: {X-Client-IP: "${client_ip}"}`, b.srv.URL), ""))
		g.get(t, "/x", spoofed)
		got := b.last(t).header
		assert.Equal(t, "127.0.0.1", got.Get("X-Forwarded-For"))
		assert.Equal(t, "127.0.0.1", got.Get("X-Real-IP"))
		assert.Equal(t, "http", got.Get("X-Forwarded-Proto"))
		assert.Equal(t, strings.TrimPrefix(g.srv.URL, "http://"), got.Get("X-Forwarded-Host"))
		assert.Empty(t, got.Get("Forwarded"))
		assert.Equal(t, "127.0.0.1", got.Get("X-Client-IP"), "${client_ip} ignores the spoofed header")
	})

	t.Run("on: passed through as before", func(t *testing.T) {
		b := newRecordingBackend(t, nil, nil)
		g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        set_headers: {X-Client-IP: "${client_ip}"}`, b.srv.URL), `
transform:
  trust_forwarded_headers: true`))
		g.get(t, "/x", spoofed)
		got := b.last(t).header
		assert.Equal(t, "6.6.6.6, 127.0.0.1", got.Get("X-Forwarded-For"), "the client's chain is kept and the peer appended")
		assert.Equal(t, "6.6.6.6", got.Get("X-Real-IP"))
		assert.Equal(t, "evil.example", got.Get("X-Forwarded-Host"))
		assert.Equal(t, "for=6.6.6.6", got.Get("Forwarded"))
		assert.Equal(t, "6.6.6.6", got.Get("X-Client-IP"), "${client_ip} is the first forwarded address")
	})
}

func TestTransform_HopByHopHeadersHandled(t *testing.T) {
	b := newRecordingBackend(t, nil, http.Header{
		"Connection": {"X-Backend-Hop"}, "X-Backend-Hop": {"internal"}, "X-End-To-End": {"yes"},
	})
	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        set_headers: {X-Internal-Auth: "gateway-verified"}`, b.srv.URL), ""))

	resp := g.get(t, "/x", http.Header{
		"Connection":       {"X-Client-Hop, X-Internal-Auth, X-Real-IP"},
		"X-Client-Hop":     {"should-not-reach-backend"},
		"Keep-Alive":       {"timeout=5"},
		"Proxy-Connection": {"keep-alive"},
	})
	got := b.last(t).header
	assert.Empty(t, got.Get("X-Client-Hop"), "headers the client lists in Connection are hop-by-hop")
	assert.Empty(t, got.Get("Keep-Alive"))
	assert.Empty(t, got.Get("Proxy-Connection"))
	assert.Equal(t, "gateway-verified", got.Get("X-Internal-Auth"), "a client can't strip a header the gateway sets")
	assert.Equal(t, "127.0.0.1", got.Get("X-Real-IP"), "nor the forwarding headers")

	assert.Empty(t, resp.Header.Get("X-Backend-Hop"), "hop-by-hop response headers stay on the backend connection")
	assert.Equal(t, "yes", resp.Header.Get("X-End-To-End"))
}

func TestTransform_CacheKeyUsesTheForwardedRequest(t *testing.T) {
	t.Run("rewritten path", func(t *testing.T) {
		b := newRecordingBackend(t, nil, nil)
		g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {ttl: 1m}
    transform:
      request:
        rewrite: {pattern: "^/old/(.*)$", replacement: "/new/$1"}
        add_query_params: {v: "2"}`, b.srv.URL), ""))

		assert.Equal(t, "MISS", g.get(t, "/old/a", nil).Header.Get("X-Cache"))
		assert.Equal(t, "HIT", g.get(t, "/new/a", nil).Header.Get("X-Cache"),
			"both forward GET /new/a?v=2, so they share one entry")
		assert.Equal(t, "MISS", g.get(t, "/old/b", nil).Header.Get("X-Cache"))
		assert.Equal(t, int64(2), b.hits.Load())
	})

	t.Run("headers set from the client identity", func(t *testing.T) {
		b := newRecordingBackend(t, nil, nil)
		g := startTransformGateway(t, fmt.Sprintf(`
rate_limit:
  scope: header
  header_name: X-Tenant-Hint
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
routes:
  - path_prefix: "/"
    target: %q
    cache: {ttl: 1m}
    transform:
      request:
        remove_headers: ["X-Tenant-Hint"]
        set_headers: {X-Tenant: "${client_id}", X-Correlation-ID: "${request_id}"}
transform:
  request_id: {enabled: true}
`, b.srv.URL))

		g.get(t, "/report", http.Header{"X-Tenant-Hint": {"acme"}})
		assert.Equal(t, "MISS", g.get(t, "/report", http.Header{"X-Tenant-Hint": {"globex"}}).Header.Get("X-Cache"),
			"another tenant's response is never served from the first one's entry")
		assert.Equal(t, "HIT", g.get(t, "/report", http.Header{"X-Tenant-Hint": {"acme"}}).Header.Get("X-Cache"),
			"the same tenant hits, even though every request has a new request ID")
		assert.Equal(t, int64(2), b.hits.Load())
		assert.Equal(t, "globex", b.all()[1].header.Get("X-Tenant"))
	})
}

func TestTransform_WebSocketRouteWithRewrite(t *testing.T) {
	var mu sync.Mutex
	var seen seenRequest
	echo := wstest.EchoHandler()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = seenRequest{path: r.URL.Path, query: r.URL.RawQuery, header: r.Header.Clone()}
		mu.Unlock()
		echo.ServeHTTP(w, r)
	}))
	t.Cleanup(backend.Close)

	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/ws"
    target: %q
    transform:
      request:
        strip_prefix: true
        rewrite: {pattern: "^/rooms/(.*)$", replacement: "/chat/$1"}
        set_headers: {X-Gateway: "gatekeeper"}
        add_query_params: {via: "gw"}
      response:
        set_headers: {X-Served-By: "gatekeeper"}`, backend.URL), ""))

	c, resp, err := wstest.Dial("ws"+strings.TrimPrefix(g.srv.URL, "http")+"/ws/rooms/lobby?user=1", nil)
	require.NoError(t, err)
	defer c.Close()
	mustRoundTrip(t, c, "hello through a rewritten route")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "/chat/lobby", seen.path)
	assert.Equal(t, "user=1&via=gw", seen.query)
	assert.Equal(t, "gatekeeper", seen.header.Get("X-Gateway"))
	assert.Equal(t, "websocket", strings.ToLower(seen.header.Get("Upgrade")), "the upgrade itself is untouched")
	assert.Equal(t, "gatekeeper", resp.Header.Get("X-Served-By"), "the 101 gets the response transform")
	assert.Equal(t, 1.0, g.transforms("/ws", "response_headers"))
}

func TestTransform_ReloadAppliesNewTransforms(t *testing.T) {
	b := newRecordingBackend(t, nil, nil)
	route := func(replacement string) string {
		return transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        rewrite: {pattern: "^/(.*)$", replacement: %q}
      response:
        set_headers: {X-Version: %q}`, b.srv.URL, replacement, replacement), "")
	}
	g := startTransformGateway(t, route("/v1/$1"))

	resp := g.get(t, "/x", nil)
	assert.Equal(t, "/v1/x", b.last(t).path)
	assert.Equal(t, "/v1/$1", resp.Header.Get("X-Version"))

	require.NoError(t, os.WriteFile(g.path, []byte(route("/v2/$1")), 0o600))
	require.NoError(t, g.gw.Reload())
	resp = g.get(t, "/x", nil)
	assert.Equal(t, "/v2/x", b.last(t).path)
	assert.Equal(t, "/v2/$1", resp.Header.Get("X-Version"))

	require.NoError(t, os.WriteFile(g.path, []byte(strings.Replace(route("/v3/$1"), "(.*)", "(.*", 1)), 0o600))
	require.Error(t, g.gw.Reload(), "an invalid regex is rejected at load")
	g.get(t, "/x", nil)
	assert.Equal(t, "/v2/x", b.last(t).path, "the previous transforms stay in place")
}

func TestTransform_RouteWithoutTransformIsUnchanged(t *testing.T) {
	b := newRecordingBackend(t, nil, http.Header{"Server": {"backend/1.0"}})
	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}`, b.srv.URL), `
transform:
  trust_forwarded_headers: true`))

	resp := g.get(t, "/a%2Fb/c?z=2&a=1&a=0", http.Header{
		"X-Forwarded-For": {"203.0.113.1"}, "X-Custom": {"v"}, "Cookie": {"s=1"},
	})
	got := b.last(t)
	assert.Equal(t, "/a/b/c", got.path)
	assert.Equal(t, "/a%2Fb/c", got.rawPath, "the encoded path is forwarded byte for byte")
	assert.Equal(t, "z=2&a=1&a=0", got.query, "the query keeps its order and duplicates")
	assert.Equal(t, "203.0.113.1, 127.0.0.1", got.header.Get("X-Forwarded-For"))
	assert.Equal(t, "v", got.header.Get("X-Custom"))
	assert.Equal(t, "s=1", got.header.Get("Cookie"))
	assert.Empty(t, got.header.Get("X-Forwarded-Proto"), "nothing is added")
	assert.Empty(t, got.header.Get("X-Request-ID"))

	assert.Equal(t, "backend/1.0", resp.Header.Get("Server"))
	assert.Empty(t, resp.Header.Get("X-Request-ID"))
	assert.Empty(t, resp.Header.Get("X-Content-Type-Options"))
	for _, kind := range []string{"path", "query", "request_headers", "response_headers"} {
		assert.Equal(t, 0.0, g.transforms("/", kind), kind)
	}
}

func TestTransform_RetriesAndLoadBalancingForwardTheTransformedRequest(t *testing.T) {
	failing := newRecordingBackend(t, func(int64) int { return http.StatusInternalServerError }, nil)
	healthy := newRecordingBackend(t, nil, nil)
	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/api"
    cache: {enabled: false}
    passive_health_check: {enabled: false}
    circuit_breaker: {enabled: false}
    backends:
      - target: %q
      - target: %q
    transform:
      request:
        strip_prefix: true
        set_headers: {X-Gateway: "gatekeeper"}`, failing.srv.URL, healthy.srv.URL), `
proxy:
  retry: {max_retries: 3, base_backoff: 1ms, max_backoff: 2ms}`))

	for i := 0; i < 4; i++ {
		assert.Equal(t, http.StatusOK, g.get(t, "/api/orders/7", nil).StatusCode)
	}
	require.NotEmpty(t, failing.all(), "some attempts landed on the failing backend and were retried")
	for _, s := range append(failing.all(), healthy.all()...) {
		assert.Equal(t, "/orders/7", s.path, "every attempt forwards the path stripped exactly once")
		assert.Equal(t, []string{"gatekeeper"}, s.header.Values("X-Gateway"))
	}
	assert.Equal(t, 4.0, g.transforms("/api", "path"), "counted per request, not per attempt")
}

func TestTransform_APIKeyNeverReachesTheBackend(t *testing.T) {
	const apiKey = "k-transform-secret-0042"
	b := newRecordingBackend(t, nil, nil)
	g := startTransformGateway(t, fmt.Sprintf(`
rate_limit:
  scope: api_key
  tiers:
    default: {requests_per_second: 1000, burst: 1000}
    premium: {requests_per_second: 1000, burst: 1000}
  clients:
    %q: premium
auth:
  enabled: true
  api_keys: [%q]
routes:
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        remove_headers: ["X-API-Key"]
        set_headers: {X-Client-ID: "${client_id}", X-Client-Tier: "${client_tier}"}
`, apiKey, apiKey, b.srv.URL))

	assert.Equal(t, http.StatusOK, g.get(t, "/x", http.Header{"X-Api-Key": {apiKey}}).StatusCode)
	got := b.last(t).header
	assert.Empty(t, got.Get("X-API-Key"), "auth ran on the original request, then the key was removed")
	assert.Equal(t, middleware.APIKeyFingerprint(apiKey), got.Get("X-Client-ID"), "${client_id} is the fingerprint")
	assert.Equal(t, "premium", got.Get("X-Client-Tier"))
	for name, values := range got {
		for _, v := range values {
			assert.NotContains(t, v, apiKey, "header %s", name)
		}
	}
}

func TestTransform_TracingRecordsRewrittenPathNeverTheQuery(t *testing.T) {
	b := newRecordingBackend(t, nil, nil)
	rec := tracetest.NewSpanRecorder()
	g := startTransformGateway(t, transformYAML(fmt.Sprintf(`
  - path_prefix: "/api"
    target: %q
    cache: {enabled: false}
    transform:
      request:
        strip_prefix: true`, b.srv.URL), `
tracing:
  enabled: true
  exporter: stdout`),
		gateway.WithTracingOptions(tracing.WithSpanProcessor(rec), tracing.WithStdoutWriter(io.Discard)))

	g.get(t, "/api/v1/items?token=super-secret-query-value", nil)

	var found bool
	for _, s := range rec.Ended() {
		for _, kv := range s.Attributes() {
			assert.NotContains(t, kv.Value.Emit(), "super-secret-query-value", "span %s attribute %s", s.Name(), kv.Key)
			if string(kv.Key) == "gatekeeper.transform.path" {
				found = true
				assert.Equal(t, "/v1/items", kv.Value.AsString())
			}
		}
	}
	assert.True(t, found, "the rewritten path is on the request's span")
}
