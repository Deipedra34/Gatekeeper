package proxy

import (
	"bytes"
	"encoding/json"
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

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/cache"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

// ordersSpec is the spec the router tests validate against: the
// backend's own paths, /orders and /orders/{id}.
const ordersSpec = `openapi: 3.0.3
info: {title: Orders, version: "1"}
paths:
  /orders:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 10}}
      responses: {"200": {description: ok}}
    post:
      parameters:
        - {name: X-Tenant, in: header, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [qty]
              properties: {qty: {type: integer, minimum: 1}}
      responses: {"201": {description: ok}}
  /orders/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses: {"200": {description: ok}}
`

const (
	validOrder   = `{"qty":3}`
	invalidOrder = `{"qty":0}`
)

func writeOrdersSpec(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "orders.yaml")
	require.NoError(t, os.WriteFile(path, []byte(ordersSpec), 0o644))
	return path
}

// seen is one request a recordingBackend received.
type seen struct {
	method, path, body string
	contentLength      int64
	header             http.Header
}

// recordingBackend records every request it gets; the first failFirst
// answer 503, the rest 200 "ok".
type recordingBackend struct {
	srv       *httptest.Server
	failFirst int32

	mu   sync.Mutex
	reqs []seen
}

func newRecordingBackend(t *testing.T) *recordingBackend {
	t.Helper()
	b := &recordingBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.reqs = append(b.reqs, seen{r.Method, r.URL.Path, string(body), r.ContentLength, r.Header.Clone()})
		n := len(b.reqs)
		b.mu.Unlock()
		if int32(n) <= atomic.LoadInt32(&b.failFirst) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *recordingBackend) requests() []seen {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]seen(nil), b.reqs...)
}

// validated is a "/" route to target, validated against spec with v's
// settings.
func validated(target, spec string, v config.RouteValidation) config.Route {
	v.Enabled, v.OpenAPIFile = true, spec
	return config.Route{PathPrefix: "/", Target: target, Validation: &v}
}

// syncBuffer is a log destination safe for concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// validationRouter builds a router over routes, logging invalid requests
// to the returned buffer.
func validationRouter(t *testing.T, routes []config.Route, pc config.ProxyConfig, m *metrics.Metrics, c *cache.Cache, opts ...Option) (*Router, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	opts = append(opts, WithValidationLog(accesscontrol.NewLogThrottle(log.New(logs, "", 0), time.Second, 100)))
	router, err := NewRouter(routes, pc, m, c, opts...)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	return router, logs
}

func send(router http.Handler, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func errorReason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code, Reason string
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	assert.Equal(t, "request_validation_failed", body.Error.Code)
	return body.Error.Reason
}

func TestValidation_InvalidRequestsNeverReachTheBackend(t *testing.T) {
	b := newRecordingBackend(t)
	router, _ := validationRouter(t, []config.Route{validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})}, noRetryProxyConfig(), nil, nil)

	rec := send(router, http.MethodPost, "/orders", invalidOrder, "X-Tenant", "acme")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "body", errorReason(t, rec))
	rec = send(router, http.MethodGet, "/orders/abc", "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "parameter", errorReason(t, rec))
	assert.Empty(t, b.requests(), "nothing invalid reached the backend")

	rec = send(router, http.MethodPost, "/orders", validOrder, "X-Tenant", "acme")
	assert.Equal(t, http.StatusOK, rec.Code)
	got := b.requests()
	require.Len(t, got, 1)
	assert.Equal(t, validOrder, got[0].body, "the body validation read arrives intact")
	assert.EqualValues(t, len(validOrder), got[0].contentLength)
}

func TestValidation_RejectStatusAndBodyTooLarge(t *testing.T) {
	b := newRecordingBackend(t)
	spec := writeOrdersSpec(t)
	router, _ := validationRouter(t, []config.Route{validated(b.srv.URL, spec, config.RouteValidation{RejectStatus: 422, MaxBodyBytes: 16})}, noRetryProxyConfig(), nil, nil)

	assert.Equal(t, http.StatusUnprocessableEntity, send(router, http.MethodGet, "/orders?limit=99", "").Code)
	rec := send(router, http.MethodPost, "/orders", `{"qty":1,"note":"`+strings.Repeat("x", 64)+`"}`, "X-Tenant", "acme")
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, "body_too_large", errorReason(t, rec))
	assert.Empty(t, b.requests())
}

func TestValidation_InvalidRequestsSkipTheCacheAndCircuitBreaker(t *testing.T) {
	b := newRecordingBackend(t)
	atomic.StoreInt32(&b.failFirst, 1000) // every backend call fails
	m := metrics.New()
	rt := validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})
	rt.Cache = config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: time.Minute}}
	rt.CircuitBreaker = config.RouteCircuitBreaker{FailureThreshold: 2, OpenDuration: config.Duration{Duration: time.Minute},
		HalfOpenMaxRequests: 1, HalfOpenSuccessesToClose: 1, HalfOpenFailuresToReopen: 1}
	router, _ := validationRouter(t, []config.Route{rt}, noRetryProxyConfig(), m, cache.New(store.NewMemoryStore()))

	for i := 0; i < 5; i++ {
		rec := send(router, http.MethodGet, "/orders?limit=50", "")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, rec.Header().Get("X-Cache"), "the cache was never consulted")
	}
	assert.Zero(t, testutil.ToFloat64(m.CacheMisses.WithLabelValues("/")))
	assert.Zero(t, testutil.ToFloat64(m.CacheHits.WithLabelValues("/")))
	assert.Zero(t, testutil.ToFloat64(m.CircuitBreakerState.WithLabelValues("/")), "the breaker stays closed")
	assert.Empty(t, b.requests())

	// Valid requests still reach the (failing) backend and trip it.
	send(router, http.MethodGet, "/orders?limit=5", "")
	send(router, http.MethodGet, "/orders?limit=6", "")
	assert.Len(t, b.requests(), 2)
	assert.Equal(t, http.StatusServiceUnavailable, send(router, http.MethodGet, "/orders?limit=7", "").Code, "now the circuit is open")
}

func TestValidation_RetriesReplayTheRestoredBody(t *testing.T) {
	b := newRecordingBackend(t)
	atomic.StoreInt32(&b.failFirst, 1)
	pc := noRetryProxyConfig()
	pc.Retry.MaxRetries = 1
	router, _ := validationRouter(t, []config.Route{validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})}, pc, nil, nil)

	rec := send(router, http.MethodPost, "/orders", validOrder, "X-Tenant", "acme")
	assert.Equal(t, http.StatusOK, rec.Code)
	got := b.requests()
	require.Len(t, got, 2, "the first attempt failed and was retried")
	for _, r := range got {
		assert.Equal(t, validOrder, r.body, "every attempt carries the whole body")
	}
}

func TestValidation_ReportOnlyForwardsInvalidRequests(t *testing.T) {
	b := newRecordingBackend(t)
	m := metrics.New()
	router, logs := validationRouter(t, []config.Route{validated(b.srv.URL, writeOrdersSpec(t),
		config.RouteValidation{Mode: config.ValidationModeReportOnly})}, noRetryProxyConfig(), m, nil)

	rec := send(router, http.MethodPost, "/orders", invalidOrder, "X-Tenant", "acme")
	assert.Equal(t, http.StatusOK, rec.Code, "forwarded anyway")
	got := b.requests()
	require.Len(t, got, 1)
	assert.Equal(t, invalidOrder, got[0].body, "exactly as the client sent it")

	assert.Equal(t, 1.0, testutil.ToFloat64(m.ValidationReportOnly.WithLabelValues("/", "body")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.ValidationRequests.WithLabelValues("/", "report_only")))
	assert.Zero(t, testutil.ToFloat64(m.ValidationRejected.WithLabelValues("/", "body")))
	assert.Contains(t, logs.String(), `validation: route /: report_only POST "/orders" operation="POST /orders" reason=body: body /qty must be at least 1`)
}

func TestValidation_LoadBalancedRoutes(t *testing.T) {
	b1, b2 := newRecordingBackend(t), newRecordingBackend(t)
	rt := validated("", writeOrdersSpec(t), config.RouteValidation{})
	rt.Backends = []config.BackendConfig{{Target: b1.srv.URL}, {Target: b2.srv.URL}}
	router, _ := validationRouter(t, []config.Route{rt}, noRetryProxyConfig(), nil, nil)

	for i := 0; i < 4; i++ {
		assert.Equal(t, http.StatusBadRequest, send(router, http.MethodPost, "/orders", invalidOrder, "X-Tenant", "a").Code)
		assert.Equal(t, http.StatusOK, send(router, http.MethodPost, "/orders", validOrder, "X-Tenant", "a").Code)
	}
	assert.Len(t, append(b1.requests(), b2.requests()...), 4, "only the valid requests, spread over both")
	assert.NotEmpty(t, b1.requests())
	assert.NotEmpty(t, b2.requests())
}

func TestValidation_Metrics(t *testing.T) {
	b := newRecordingBackend(t)
	m := metrics.New()
	router, _ := validationRouter(t, []config.Route{validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})}, noRetryProxyConfig(), m, nil)

	send(router, http.MethodGet, "/orders?limit=5", "")
	send(router, http.MethodGet, "/orders?limit=50", "")
	send(router, http.MethodPost, "/orders", invalidOrder, "X-Tenant", "a")
	send(router, http.MethodPost, "/orders", invalidOrder, "X-Tenant", "a")
	send(router, http.MethodGet, "/unknown", "")

	assert.Equal(t, 1.0, testutil.ToFloat64(m.ValidationRequests.WithLabelValues("/", "passed")))
	assert.Equal(t, 3.0, testutil.ToFloat64(m.ValidationRequests.WithLabelValues("/", "rejected")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.ValidationRequests.WithLabelValues("/", "unmatched")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.ValidationRejected.WithLabelValues("/", "parameter")))
	assert.Equal(t, 2.0, testutil.ToFloat64(m.ValidationRejected.WithLabelValues("/", "body")))
	assert.Equal(t, 1, testutil.CollectAndCount(m.ValidationDuration), "one latency series for the route")

	const want = `
# HELP gatekeeper_validation_duration_seconds Time spent checking requests against a route's OpenAPI spec, reading the body included, by route.
# TYPE gatekeeper_validation_duration_seconds histogram
`
	assert.NoError(t, testutil.CollectAndCompare(m.ValidationDuration, strings.NewReader(want+histogramCount(t, m))))

	rv := router.Validators()
	require.Len(t, rv, 1)
	snap := rv[0].Stats.Snapshot()
	assert.EqualValues(t, 5, snap.Validated)
	assert.EqualValues(t, 3, snap.Rejected)
	assert.Equal(t, map[string]uint64{"parameter": 1, "body": 2}, snap.RejectedByReason)
}

// histogramCount renders the duration histogram as scraped, after
// checking it counted five requests.
func histogramCount(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	var lines []string
	for _, l := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(l, "gatekeeper_validation_duration_seconds") {
			lines = append(lines, l)
		}
	}
	require.Contains(t, lines, `gatekeeper_validation_duration_seconds_count{route="/"} 5`)
	return strings.Join(lines, "\n") + "\n"
}

func TestValidation_LogLinesAreRateLimitedAndHoldNoValues(t *testing.T) {
	b := newRecordingBackend(t)
	logs := &syncBuffer{}
	throttle := accesscontrol.NewLogThrottle(log.New(logs, "", 0), time.Hour, 3)
	router, err := NewRouter([]config.Route{validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})},
		noRetryProxyConfig(), nil, nil, WithValidationLog(throttle))
	require.NoError(t, err)
	t.Cleanup(router.Close)

	for i := 0; i < 50; i++ {
		send(router, http.MethodPost, "/orders?token=hunter2", `{"qty":"hunter2"}`, "X-Tenant", "a")
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	assert.Len(t, lines, 3, "a flood of invalid requests logs a burst, then nothing")
	assert.Contains(t, lines[0], "body /qty must be an integer")
	assert.NotContains(t, logs.String(), "hunter2", "no query string, no values")
}

func TestValidation_BrokenSpecFailsTheRouterBuild(t *testing.T) {
	_, err := NewRouter([]config.Route{validated("http://localhost:1", "no/such/spec.yaml", config.RouteValidation{})}, noRetryProxyConfig(), nil, nil)
	require.Error(t, err)
	assert.Equal(t, "proxy: route /: validation: OpenAPI spec no/such/spec.yaml does not exist", err.Error())

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("openapi: 3.0.3\npaths: {}\n"), 0o644))
	_, err = NewRouter([]config.Route{validated("http://localhost:1", bad, config.RouteValidation{})}, noRetryProxyConfig(), nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is invalid")
}

func TestValidation_SpecSharedByRoutesAndReusedAcrossReloads(t *testing.T) {
	b := newRecordingBackend(t)
	spec := writeOrdersSpec(t)
	a := validated(b.srv.URL, spec, config.RouteValidation{})
	a.PathPrefix = "/a"
	a.Transform.Request.StripPrefix = true
	c := validated(b.srv.URL, spec, config.RouteValidation{Mode: config.ValidationModeReportOnly})
	c.PathPrefix = "/c"
	c.Transform.Request.StripPrefix = true
	routes := []config.Route{a, c}

	first, _ := validationRouter(t, routes, noRetryProxyConfig(), nil, nil)
	rv := first.Validators()
	require.Len(t, rv, 2)
	assert.Same(t, rv[0].Validator.Spec(), rv[1].Validator.Spec(), "one file, compiled once")

	second, _ := validationRouter(t, routes, noRetryProxyConfig(), nil, nil, WithPrevious(first))
	assert.Same(t, rv[0].Validator.Spec(), second.Validators()[0].Validator.Spec(), "unchanged: reused by the reload")

	require.NoError(t, os.WriteFile(spec, []byte(ordersSpec+"# changed\n"), 0o644))
	third, _ := validationRouter(t, routes, noRetryProxyConfig(), nil, nil, WithPrevious(second))
	assert.NotSame(t, rv[0].Validator.Spec(), third.Validators()[0].Validator.Spec(), "changed: loaded again")
}
