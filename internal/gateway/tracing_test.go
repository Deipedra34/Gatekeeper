package gateway_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket/wstest"
)

const (
	tracedAPIKey = "sk-live-abcdef0123456789"
	// A valid traceparent from a hypothetical upstream caller.
	upstreamTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	upstreamSpanID  = "00f067aa0ba902b7"
)

// tracingYAML is a config with API key auth, per-API-key rate limiting,
// caching, a circuit breaker, and retries on "/api", plus the given
// tracing block and extra route settings.
func tracingYAML(backend string, burst int, tracingBlock, routeExtra string) string {
	return fmt.Sprintf(`
storage:
  backend: memory
rate_limit:
  algorithm: token_bucket
  scope: api_key
  tiers:
    default: {requests_per_second: 1, burst: %d}
auth:
  enabled: true
  api_keys: [%q]
routes:
  - path_prefix: "/api"
    target: %q
    cache: {ttl: 1m}
    circuit_breaker: {failure_threshold: 10}
%s
proxy:
  timeout: 2s
  retry: {max_retries: 3, base_backoff: 1ms, max_backoff: 2ms}
%s
`, burst, tracedAPIKey, backend, routeExtra, tracingBlock)
}

const tracingOn = `
tracing:
  enabled: true
  exporter: stdout
`

type traced struct {
	gw      *gateway.Gateway
	rec     *tracetest.SpanRecorder
	logs    *syncBuffer
	cfgPath string
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTraced(t *testing.T, cfgYAML string) *traced {
	t.Helper()
	path := writeConfig(t, t.TempDir(), "config.yaml", cfgYAML)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })

	rec := tracetest.NewSpanRecorder()
	logs := &syncBuffer{}
	g, err := gateway.New(cfg, path, st, metrics.New(), log.New(logs, "", 0),
		gateway.WithTracingOptions(tracing.WithSpanProcessor(rec), tracing.WithStdoutWriter(io.Discard)))
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = g.ShutdownTracing(ctx)
	})
	return &traced{gw: g, rec: rec, logs: logs, cfgPath: path}
}

func (tr *traced) get(path string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	tr.gw.ServeHTTP(rec, req)
	return rec
}

func withKey() http.Header { return http.Header{"X-Api-Key": {tracedAPIKey}} }

// spans returns the ended spans, keyed by name; a name that occurs more
// than once keeps every occurrence in order.
func spansByName(rec *tracetest.SpanRecorder) map[string][]sdktrace.ReadOnlySpan {
	out := map[string][]sdktrace.ReadOnlySpan{}
	for _, s := range rec.Ended() {
		out[s.Name()] = append(out[s.Name()], s)
	}
	return out
}

func attr(s sdktrace.ReadOnlySpan, key string) (any, bool) {
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.AsInterface(), true
		}
	}
	return nil, false
}

func mustAttr(t *testing.T, s sdktrace.ReadOnlySpan, key string) any {
	t.Helper()
	v, ok := attr(s, key)
	require.Truef(t, ok, "span %q has no attribute %s (has %v)", s.Name(), key, s.Attributes())
	return v
}

// backendRecorder is a backend that records the trace headers it got.
type backendRecorder struct {
	srv          *httptest.Server
	mu           sync.Mutex
	traceparents []string
	tracestates  []string
	baggage      []string
	status       func(call int) int
	calls        atomic.Int32
}

func newBackendRecorder(t *testing.T, status func(call int) int) *backendRecorder {
	t.Helper()
	b := &backendRecorder{status: status}
	b.srv = httptest.NewServer(http.HandlerFunc(b.handle))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backendRecorder) handle(w http.ResponseWriter, r *http.Request) {
	call := int(b.calls.Add(1))
	b.mu.Lock()
	b.traceparents = append(b.traceparents, r.Header.Get("Traceparent"))
	b.tracestates = append(b.tracestates, r.Header.Get("Tracestate"))
	b.baggage = append(b.baggage, r.Header.Get("Baggage"))
	b.mu.Unlock()
	status := http.StatusOK
	if b.status != nil {
		status = b.status(call)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "backend says hi")
}

func (b *backendRecorder) seen() (tp, ts, bg []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.traceparents...), append([]string(nil), b.tracestates...), append([]string(nil), b.baggage...)
}

func TestTracing_RequestProducesExpectedSpanTree(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, tracingOn, ""))

	require.Equal(t, http.StatusOK, tr.get("/api/items", withKey()).Code)

	spans := spansByName(tr.rec)
	require.Len(t, spans["GET /api"], 1, "one server span, named method + route")
	server := spans["GET /api"][0]
	assert.Equal(t, trace.SpanKindServer, server.SpanKind())
	assert.Equal(t, int64(200), mustAttr(t, server, "http.response.status_code"))
	assert.Equal(t, "/api", mustAttr(t, server, "http.route"))
	assert.Equal(t, "GET", mustAttr(t, server, "http.request.method"))
	assert.False(t, server.Parent().IsValid(), "a request without traceparent starts a new trace")

	for _, name := range []string{tracing.SpanAuth, tracing.SpanRateLimit, tracing.SpanCacheLookup, tracing.SpanCircuitBreaker, tracing.SpanBackendAttempt} {
		require.Lenf(t, spans[name], 1, "span %s", name)
		s := spans[name][0]
		assert.Equal(t, server.SpanContext().TraceID(), s.SpanContext().TraceID(), name)
		assert.Equal(t, server.SpanContext().SpanID(), s.Parent().SpanID(), "%s is a direct child of the server span", name)
	}

	auth := spans[tracing.SpanAuth][0]
	assert.Equal(t, "api_key", mustAttr(t, auth, "gatekeeper.auth.mode"))
	assert.Equal(t, "success", mustAttr(t, auth, "gatekeeper.auth.result"))

	rl := spans[tracing.SpanRateLimit][0]
	assert.Equal(t, true, mustAttr(t, rl, "gatekeeper.ratelimit.allowed"))
	assert.Equal(t, "token_bucket", mustAttr(t, rl, "gatekeeper.ratelimit.algorithm"))
	assert.Equal(t, "memory", mustAttr(t, rl, "gatekeeper.ratelimit.store"))
	assert.Equal(t, "default", mustAttr(t, rl, "gatekeeper.client.tier"))
	hash := mustAttr(t, rl, "gatekeeper.client.id_hash").(string)
	assert.Len(t, hash, 16)
	assert.NotContains(t, hash, tracedAPIKey)

	assert.Equal(t, false, mustAttr(t, spans[tracing.SpanCacheLookup][0], "gatekeeper.cache.hit"))

	cb := spans[tracing.SpanCircuitBreaker][0]
	assert.Equal(t, "closed", mustAttr(t, cb, "gatekeeper.circuit_breaker.state"))
	assert.Equal(t, true, mustAttr(t, cb, "gatekeeper.circuit_breaker.allowed"))

	attempt := spans[tracing.SpanBackendAttempt][0]
	assert.Equal(t, trace.SpanKindClient, attempt.SpanKind())
	assert.Equal(t, int64(1), mustAttr(t, attempt, "gatekeeper.backend.attempt"))
	assert.Equal(t, int64(200), mustAttr(t, attempt, "http.response.status_code"))
	assert.Equal(t, "127.0.0.1", mustAttr(t, attempt, "server.address"))

	// The backend's parent is the attempt span.
	tps, _, _ := backend.seen()
	require.Len(t, tps, 1)
	assert.Equal(t, fmt.Sprintf("00-%s-%s-01", attempt.SpanContext().TraceID(), attempt.SpanContext().SpanID()), tps[0])

	// The log line carries the trace ID.
	assert.Contains(t, tr.logs.String(), "trace_id="+server.SpanContext().TraceID().String())
}

func TestTracing_CacheHitVersusMiss(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, tracingOn, ""))

	require.Equal(t, "MISS", tr.get("/api/cached", withKey()).Header().Get("X-Cache"))
	require.Equal(t, "HIT", tr.get("/api/cached", withKey()).Header().Get("X-Cache"))

	lookups := spansByName(tr.rec)[tracing.SpanCacheLookup]
	require.Len(t, lookups, 2)
	assert.Equal(t, false, mustAttr(t, lookups[0], "gatekeeper.cache.hit"))
	assert.Equal(t, true, mustAttr(t, lookups[1], "gatekeeper.cache.hit"))
	assert.Len(t, spansByName(tr.rec)[tracing.SpanBackendAttempt], 1, "a cache hit never reaches the backend")
}

func TestTracing_RetriesProduceOneSpanPerAttempt(t *testing.T) {
	backend := newBackendRecorder(t, func(call int) int {
		if call < 3 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, tracingOn, ""))

	require.Equal(t, http.StatusOK, tr.get("/api/flaky", withKey()).Code)

	spans := spansByName(tr.rec)
	attempts := spans[tracing.SpanBackendAttempt]
	require.Len(t, attempts, 3)
	server := spans["GET /api"][0]
	tps, _, _ := backend.seen()
	require.Len(t, tps, 3)
	for i, a := range attempts {
		assert.Equal(t, int64(i+1), mustAttr(t, a, "gatekeeper.backend.attempt"))
		assert.Equal(t, i > 0, mustAttr(t, a, "gatekeeper.backend.retry"))
		assert.Equal(t, server.SpanContext().SpanID(), a.Parent().SpanID())
		// Each attempt is propagated with its own span as the parent.
		assert.Contains(t, tps[i], a.SpanContext().SpanID().String(), "attempt %d", i+1)
		assert.Contains(t, tps[i], server.SpanContext().TraceID().String())
	}
	assert.Equal(t, int64(503), mustAttr(t, attempts[0], "http.response.status_code"))
	assert.Equal(t, codes.Error, attempts[0].Status().Code)
	assert.Equal(t, codes.Error, attempts[1].Status().Code)
	assert.Equal(t, int64(200), mustAttr(t, attempts[2], "http.response.status_code"))
	assert.Equal(t, codes.Unset, attempts[2].Status().Code)
	assert.Len(t, spans[tracing.SpanCircuitBreaker], 3, "the breaker is checked before every attempt")
	assert.Equal(t, codes.Unset, server.Status().Code, "the request succeeded in the end")
}

func TestTracing_RateLimitedAndUnauthorized(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 1, tracingOn, ""))

	t.Run("unauthorized", func(t *testing.T) {
		tr.rec.Reset()
		require.Equal(t, http.StatusUnauthorized, tr.get("/api/x", http.Header{"X-Api-Key": {"wrong"}}).Code)
		spans := spansByName(tr.rec)
		auth := spans[tracing.SpanAuth][0]
		assert.Equal(t, "failure", mustAttr(t, auth, "gatekeeper.auth.result"))
		assert.Equal(t, codes.Error, auth.Status().Code)
		assert.Empty(t, spans[tracing.SpanRateLimit], "rejected before the rate limiter")
		assert.Empty(t, spans[tracing.SpanBackendAttempt])
		server := spans["GET /api"][0]
		assert.Equal(t, int64(401), mustAttr(t, server, "http.response.status_code"))
		assert.Equal(t, codes.Unset, server.Status().Code, "a 4xx is not a server error")
	})

	t.Run("rate limited", func(t *testing.T) {
		require.Equal(t, http.StatusOK, tr.get("/api/x", withKey()).Code) // uses the burst of 1
		tr.rec.Reset()
		require.Equal(t, http.StatusTooManyRequests, tr.get("/api/x", withKey()).Code)
		spans := spansByName(tr.rec)
		rl := spans[tracing.SpanRateLimit][0]
		assert.Equal(t, false, mustAttr(t, rl, "gatekeeper.ratelimit.allowed"))
		assert.Equal(t, int64(0), mustAttr(t, rl, "gatekeeper.ratelimit.remaining"))
		assert.Equal(t, codes.Error, rl.Status().Code)
		assert.Equal(t, "rate limit exceeded", rl.Status().Description)
		assert.Empty(t, spans[tracing.SpanBackendAttempt])
		assert.Equal(t, int64(429), mustAttr(t, spans["GET /api"][0], "http.response.status_code"))
	})
}

func TestTracing_HonorsIncomingTraceparentAndPropagates(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, tracingOn, ""))

	h := withKey()
	h.Set("Traceparent", "00-"+upstreamTraceID+"-"+upstreamSpanID+"-01")
	h.Set("Tracestate", "vendor=opaque")
	h.Set("Baggage", "tenant=acme")
	require.Equal(t, http.StatusOK, tr.get("/api/joined", h).Code)

	spans := spansByName(tr.rec)
	server := spans["GET /api"][0]
	assert.Equal(t, upstreamTraceID, server.SpanContext().TraceID().String(), "joins the caller's trace")
	assert.Equal(t, upstreamSpanID, server.Parent().SpanID().String())
	assert.True(t, server.Parent().IsRemote())

	attempt := spans[tracing.SpanBackendAttempt][0]
	tps, tss, bgs := backend.seen()
	assert.Equal(t, "00-"+upstreamTraceID+"-"+attempt.SpanContext().SpanID().String()+"-01", tps[0])
	assert.Equal(t, "vendor=opaque", tss[0], "tracestate is carried along")
	assert.Equal(t, "tenant=acme", bgs[0], "baggage is carried along")
}

func TestTracing_PropagatesToHTTPSBackend(t *testing.T) {
	var got atomic.Value
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Traceparent"))
	}))
	t.Cleanup(backend.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}), 0o644))

	tr := newTraced(t, tracingYAML(backend.URL, 10, tracingOn, fmt.Sprintf("    backend_tls: {enabled: true, ca_file: %q}", caFile)))
	require.Equal(t, http.StatusOK, tr.get("/api/secure", withKey()).Code)

	attempt := spansByName(tr.rec)[tracing.SpanBackendAttempt][0]
	assert.Equal(t, "https", mustAttr(t, attempt, "url.scheme"))
	assert.Contains(t, got.Load(), attempt.SpanContext().SpanID().String())
}

func TestTracing_WebSocketHandshakeAndConnectionSpans(t *testing.T) {
	var upgradeTraceparent atomic.Value
	echo := wstest.EchoHandler()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgradeTraceparent.Store(r.Header.Get("Traceparent"))
		echo.ServeHTTP(w, r)
	}))
	t.Cleanup(backend.Close)
	tr := newTraced(t, tracingYAML(backend.URL, 10, tracingOn, ""))
	srv := httptest.NewServer(tr.gw)
	t.Cleanup(srv.Close)

	c, _, err := wstest.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/ws", withKey())
	require.NoError(t, err)
	require.NoError(t, c.WriteText("ping"))
	_, err = c.ReadText()
	require.NoError(t, err)
	require.NoError(t, c.WriteClose(1000, ""))
	_, _, _ = c.ReadMessage()
	c.Close()

	var spans map[string][]sdktrace.ReadOnlySpan
	require.Eventually(t, func() bool {
		spans = spansByName(tr.rec)
		return len(spans[tracing.SpanWebSocketConnection]) == 1 && len(spans["GET /api"]) == 1
	}, 5*time.Second, 10*time.Millisecond)

	hs := spans[tracing.SpanWebSocketHandshake][0]
	conn := spans[tracing.SpanWebSocketConnection][0]
	server := spans["GET /api"][0]
	assert.Equal(t, int64(101), mustAttr(t, hs, "http.response.status_code"))
	assert.Equal(t, "client", mustAttr(t, conn, "gatekeeper.websocket.close_reason"))
	assert.Equal(t, server.SpanContext().SpanID(), hs.Parent().SpanID())
	assert.Equal(t, server.SpanContext().SpanID(), conn.Parent().SpanID())
	assert.False(t, conn.StartTime().Before(hs.EndTime()), "the connection span starts once the handshake is done")
	assert.Contains(t, upgradeTraceparent.Load(), hs.SpanContext().SpanID().String(), "the backend upgrade request carries the handshake span")
	assert.Empty(t, spans[tracing.SpanCacheLookup], "upgrades never touch the cache")
	assert.Empty(t, spans[tracing.SpanBackendAttempt], "nor the retrying HTTP transport")
}

func TestTracing_SecretsNeverRecorded(t *testing.T) {
	const (
		bearer     = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LWNsYWltcw.c2lnbmF0dXJl"
		cookie     = "session=cookie-secret-value"
		querySecr  = "query-secret-token"
		bodySecret = "body-secret-payload"
	)
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, tracingOn, `
  - path_prefix: "/dead"
    target: "http://127.0.0.1:1"`))
	send := func(method, path string) {
		req := httptest.NewRequest(method, path+"?token="+querySecr+"&x=1", strings.NewReader(bodySecret))
		req.Header.Set("X-Api-Key", tracedAPIKey)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Cookie", cookie)
		req.Header.Set("User-Agent", "secret-agent/"+querySecr)
		tr.gw.ServeHTTP(httptest.NewRecorder(), req)
	}
	send(http.MethodPost, "/api/things")
	send(http.MethodGet, "/api/things")
	send(http.MethodGet, "/api/../api/things")
	send(http.MethodGet, "/dead/things")   // failing backend: error paths too
	send("BREW-"+querySecr, "/api/things") // non-standard method
	tr.get("/api/x", http.Header{"X-Api-Key": {"leaked-" + tracedAPIKey}})

	require.NotEmpty(t, tr.rec.Ended())
	secrets := []string{tracedAPIKey, bearer, "cookie-secret-value", querySecr, bodySecret, "token="}
	for _, s := range tr.rec.Ended() {
		var texts []string
		texts = append(texts, s.Name(), s.Status().Description)
		for _, kv := range s.Attributes() {
			texts = append(texts, string(kv.Key), kv.Value.Emit())
		}
		for _, ev := range s.Events() {
			texts = append(texts, ev.Name)
			for _, kv := range ev.Attributes {
				texts = append(texts, string(kv.Key), kv.Value.Emit())
			}
		}
		for _, text := range texts {
			for _, secret := range secrets {
				assert.NotContainsf(t, text, secret, "span %q leaks a secret", s.Name())
			}
		}
	}
}

func TestTracing_UnreachableBackendErrorIsClassifiedNotQuoted(t *testing.T) {
	tr := newTraced(t, tracingYAML("http://127.0.0.1:1", 10, tracingOn, ""))
	require.Equal(t, http.StatusBadGateway, tr.get("/api/x?secret=hunter2", withKey()).Code)

	attempts := spansByName(tr.rec)[tracing.SpanBackendAttempt]
	require.Len(t, attempts, 4, "initial attempt plus 3 retries")
	for _, a := range attempts {
		assert.Equal(t, "connection_refused", mustAttr(t, a, "error.type"))
		assert.Equal(t, codes.Error, a.Status().Code)
		assert.NotContains(t, a.Status().Description, "hunter2")
	}
	server := spansByName(tr.rec)["GET /api"][0]
	assert.Equal(t, codes.Error, server.Status().Code, "a 502 is a server error")
}

func TestTracing_SamplingRatio(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	ratio := func(r string) string {
		return fmt.Sprintf("tracing: {enabled: true, exporter: stdout, sample_ratio: %s}", r)
	}

	t.Run("ratio 0 records nothing but still propagates", func(t *testing.T) {
		tr := newTraced(t, tracingYAML(backend.srv.URL, 1000, ratio("0"), ""))
		for i := 0; i < 20; i++ {
			require.Equal(t, http.StatusOK, tr.get(fmt.Sprintf("/api/%d", i), withKey()).Code)
		}
		assert.Empty(t, tr.rec.Ended())
		tps, _, _ := backend.seen()
		assert.True(t, strings.HasSuffix(tps[len(tps)-1], "-00"), "unsampled trace context still goes to the backend: %s", tps[len(tps)-1])
	})

	t.Run("parent-based: a sampled caller is recorded even at ratio 0", func(t *testing.T) {
		tr := newTraced(t, tracingYAML(backend.srv.URL, 1000, ratio("0"), ""))
		h := withKey()
		h.Set("Traceparent", "00-"+upstreamTraceID+"-"+upstreamSpanID+"-01")
		tr.get("/api/sampled", h)
		assert.NotEmpty(t, tr.rec.Ended())
	})

	t.Run("parent-based: an unsampled caller is not recorded at ratio 1", func(t *testing.T) {
		tr := newTraced(t, tracingYAML(backend.srv.URL, 1000, ratio("1"), ""))
		h := withKey()
		h.Set("Traceparent", "00-"+upstreamTraceID+"-"+upstreamSpanID+"-00")
		tr.get("/api/unsampled", h)
		assert.Empty(t, tr.rec.Ended())
	})

	t.Run("ratio 0.5 records about half", func(t *testing.T) {
		tr := newTraced(t, tracingYAML(backend.srv.URL, 1000, ratio("0.5"), ""))
		const n = 400
		for i := 0; i < n; i++ {
			tr.get(fmt.Sprintf("/api/r%d", i), withKey())
		}
		servers := len(spansByName(tr.rec)["GET /api"])
		assert.InDelta(t, n/2, servers, n/4, "got %d of %d", servers, n)
	})
}

func TestTracing_DisabledProducesNoSpansAndNoChange(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	off := newTraced(t, tracingYAML(backend.srv.URL, 10, "tracing: {enabled: false, response_header: X-Trace-Id}", ""))
	none := newTraced(t, tracingYAML(backend.srv.URL, 10, "", ""))

	h := withKey()
	h.Set("Traceparent", "00-"+upstreamTraceID+"-"+upstreamSpanID+"-01")
	h.Set("Baggage", "tenant=acme")
	a := off.get("/api/same", h)
	b := none.get("/api/same?x", h) // different URL so the cache doesn't interfere

	assert.Empty(t, off.rec.Ended())
	assert.Equal(t, b.Code, a.Code)
	assert.Equal(t, b.Body.String(), a.Body.String())
	assert.Empty(t, a.Header().Get("X-Trace-Id"))
	assert.Equal(t, b.Header().Get("X-Ratelimit-Limit"), a.Header().Get("X-Ratelimit-Limit"))

	tps, _, bgs := backend.seen()
	for i := range tps {
		assert.Equal(t, "00-"+upstreamTraceID+"-"+upstreamSpanID+"-01", tps[i], "forwarded untouched, as before tracing existed")
		assert.Equal(t, "tenant=acme", bgs[i])
	}
	off.get("/api/no-header", withKey())
	tps, _, _ = backend.seen()
	assert.Empty(t, tps[len(tps)-1], "nothing injected when the client sent nothing")
	assert.NotContains(t, off.logs.String(), "trace_id=")
}

func TestTracing_ResponseHeader(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 10, "tracing: {enabled: true, exporter: stdout, response_header: X-Trace-Id}", ""))
	resp := tr.get("/api/x", withKey())
	server := spansByName(tr.rec)["GET /api"][0]
	assert.Equal(t, server.SpanContext().TraceID().String(), resp.Header().Get("X-Trace-Id"))

	// Also on rejections, which is when a client most needs it.
	assert.NotEmpty(t, tr.get("/api/x", nil).Header().Get("X-Trace-Id"))
}

func TestTracing_UnreachableCollectorDoesNotSlowRequests(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	for _, exporter := range []string{"otlp_grpc", "otlp_http"} {
		t.Run(exporter, func(t *testing.T) {
			tr := newTraced(t, tracingYAML(backend.srv.URL, 100000,
				fmt.Sprintf("tracing: {enabled: true, exporter: %s, endpoint: \"127.0.0.1:1\", insecure: true}", exporter), ""))

			start := time.Now()
			for i := 0; i < 300; i++ {
				require.Equal(t, http.StatusOK, tr.get(fmt.Sprintf("/api/%d", i), withKey()).Code)
			}
			assert.Less(t, time.Since(start), 5*time.Second, "requests never wait on the exporter")

			// Shutdown gives up at its deadline instead of hanging.
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			start = time.Now()
			_ = tr.gw.ShutdownTracing(ctx)
			assert.Less(t, time.Since(start), 3*time.Second)
		})
	}
}

func TestTracing_ReloadPicksUpTracingChanges(t *testing.T) {
	backend := newBackendRecorder(t, nil)
	tr := newTraced(t, tracingYAML(backend.srv.URL, 100, "tracing: {enabled: false}", ""))
	tr.get("/api/before", withKey())
	assert.Empty(t, tr.rec.Ended())

	require.NoError(t, os.WriteFile(tr.cfgPath, []byte(tracingYAML(backend.srv.URL, 100, tracingOn, "")), 0o644))
	require.NoError(t, tr.gw.Reload())
	tr.get("/api/after", withKey())
	assert.NotEmpty(t, spansByName(tr.rec)["GET /api"], "tracing turned on by SIGHUP reload")

	require.NoError(t, os.WriteFile(tr.cfgPath, []byte(tracingYAML(backend.srv.URL, 100, "tracing: {enabled: false}", "")), 0o644))
	require.NoError(t, tr.gw.Reload())
	tr.rec.Reset()
	tr.get("/api/off-again", withKey())
	assert.Empty(t, tr.rec.Ended(), "and off again")
}
