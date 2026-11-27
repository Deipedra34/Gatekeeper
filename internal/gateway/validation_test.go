package gateway_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// ordersSpecWithMax is the spec of the backend's /orders, whose limit
// query parameter may go up to max.
func ordersSpecWithMax(max int) string {
	return fmt.Sprintf(`openapi: 3.0.3
info: {title: Orders, version: "%d"}
paths:
  /orders:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: %d}}
      responses: {"200": {description: ok}}
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, required: [qty], properties: {qty: {type: integer, minimum: 1}}}
      responses: {"201": {description: ok}}
`, max, max)
}

func writeSpec(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "orders.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	return path
}

// validationYAML is a gateway with API key auth (key "tester", burst
// requests), request IDs, and "/api" stripped and validated against
// spec with the extra validation settings in block; extra is more
// top-level config.
func validationYAML(target, spec string, burst int, block, extra string) string {
	return fmt.Sprintf(`
rate_limit:
  scope: api_key
  tiers:
    default: {requests_per_second: 0.0001, burst: %d}
auth:
  enabled: true
  api_keys: [tester]
transform:
  request_id: {enabled: true}
routes:
  - path_prefix: "/api"
    target: %q
    cache: {enabled: false}
    transform: {request: {strip_prefix: true}}
    validation:
      enabled: true
      openapi_file: %q
%s
%s`, burst, target, filepath.ToSlash(spec), block, extra)
}

// send sends method path with body (as JSON) through h's gateway, with
// header name/value pairs.
func (h *splitHarness) send(method, path, body string, headers ...string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = "10.0.0.1:1234"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.gw.ServeHTTP(rec, req)
	return rec
}

func TestGatewayValidation_RunsAfterAuthAndRateLimiting(t *testing.T) {
	b := newSplitBackend(t, "b")
	spec := writeSpec(t, t.TempDir(), ordersSpecWithMax(10))
	h := newSplitHarness(t, validationYAML(b.srv.URL, spec, 3, "", ""))

	assert.Equal(t, http.StatusUnauthorized, h.send(http.MethodGet, "/api/orders?limit=99", "").Code,
		"auth answers first: an unauthenticated client learns nothing about the spec")
	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusBadRequest, h.send(http.MethodGet, "/api/orders?limit=99", "", testerKey, "tester").Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, h.send(http.MethodGet, "/api/orders?limit=1", "", testerKey, "tester").Code,
		"invalid requests use up the client's rate limit like any other")
	assert.Zero(t, b.hits())
}

func TestGatewayValidation_ErrorBodyCarriesTheRequestID(t *testing.T) {
	b := newSplitBackend(t, "b")
	h := newSplitHarness(t, validationYAML(b.srv.URL, writeSpec(t, t.TempDir(), ordersSpecWithMax(10)), 100, "", ""))

	rec := h.send(http.MethodPost, "/api/orders", `{"qty":"three","card":"4111111111111111"}`, testerKey, "tester", "X-Request-ID", "client-req-42")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body struct {
		Error struct {
			Reason string `json:"reason"`
			ID     string `json:"request_id"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "client-req-42", body.Error.ID)
	assert.Equal(t, rec.Header().Get("X-Request-ID"), body.Error.ID, "the same ID as the response header")
	assert.NotContains(t, rec.Body.String(), "4111111111111111")
	assert.NotContains(t, rec.Body.String(), "three")
	assert.Equal(t, "body", body.Error.Reason)
	assert.Contains(t, h.logs.String(), "POST /api/orders 400", "the request log line")
	assert.Contains(t, h.logs.String(), "validation=rejected")
	assert.Contains(t, h.logs.String(), "request_id=client-req-42", "the violation log line names the request")
}

func TestGatewayValidation_SplitAndFaultsSeeOnlyValidRequests(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	spec := writeSpec(t, t.TempDir(), ordersSpecWithMax(10))
	h := newSplitHarness(t, fmt.Sprintf(`
rate_limit:
  scope: api_key
  tiers:
    default: {requests_per_second: 0.0001, burst: 1000}
auth:
  enabled: true
  api_keys: [tester]
routes:
  - path_prefix: "/api"
    cache: {enabled: false}
    transform: {request: {strip_prefix: true}}
    validation: {enabled: true, openapi_file: %q}
    fault_injection:
      enabled: true
      abort: {percentage: 100, status: 503}
      count_as_backend_failure: false
      match:
        header: {name: X-Gatekeeper-Fault, value: "true"}
    traffic_split:
      variants:
        - {name: stable, weight: 50, target: %q}
        - {name: canary, weight: 50, target: %q}
fault_injection:
  global_enabled: true
  environment: test
`, filepath.ToSlash(spec), stable.srv.URL, canary.srv.URL))

	for i := 0; i < 10; i++ {
		rec := h.send(http.MethodGet, "/api/orders?limit=50", "", testerKey, "tester", "X-Gatekeeper-Fault", "true")
		assert.Equal(t, http.StatusBadRequest, rec.Code, "rejected before a fault is decided")
		assert.Empty(t, rec.Header().Get("X-Gatekeeper-Fault"))
	}
	assert.Zero(t, testutil.CollectAndCount(h.m.VariantRequests), "no variant was picked for an invalid request")
	assert.Zero(t, testutil.CollectAndCount(h.m.FaultsInjected))

	rec := h.send(http.MethodGet, "/api/orders?limit=5", "", testerKey, "tester", "X-Gatekeeper-Fault", "true")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "a valid one goes on to the fault")
	assert.Equal(t, http.StatusOK, h.send(http.MethodGet, "/api/orders?limit=5", "", testerKey, "tester").Code)
	assert.Equal(t, 1, stable.hits()+canary.hits())
	assert.Equal(t, []string{"/orders"}, append(stable.seen(), canary.seen()...), "the variant got the stripped path")
}

func TestGatewayValidation_SpanAttributes(t *testing.T) {
	b := newSplitBackend(t, "b")
	spec := writeSpec(t, t.TempDir(), ordersSpecWithMax(10))
	tr := newTraced(t, tracingOn+fmt.Sprintf(`
rate_limit:
  tiers:
    default: {requests_per_second: 100, burst: 100}
auth:
  enabled: true
  api_keys: [%q]
routes:
  - path_prefix: "/api"
    target: %q
    cache: {enabled: false}
    transform: {request: {strip_prefix: true}}
    validation: {enabled: true, openapi_file: %q}
`, tracedAPIKey, b.srv.URL, filepath.ToSlash(spec)))

	assert.Equal(t, http.StatusBadRequest, tr.get("/api/orders?limit=987654", withKey()).Code)
	spans := spansByName(tr.rec)
	require.Len(t, spans["validation"], 1)
	v := spans["validation"][0]
	for key, want := range map[string]any{
		"validation.result":               "rejected",
		"gatekeeper.validation.reason":    "parameter",
		"gatekeeper.validation.operation": "GET /orders",
		"http.route":                      "/api",
	} {
		got, ok := attr(v, key)
		assert.True(t, ok, key)
		assert.Equal(t, want, got, key)
	}
	var server bool
	for _, s := range tr.rec.Ended() {
		if s.SpanKind() == trace.SpanKindServer {
			got, _ := attr(s, "validation.result")
			assert.Equal(t, "rejected", got, "the server span carries the result too")
			server = true
		}
		for _, kv := range s.Attributes() {
			assert.NotContains(t, kv.Value.Emit(), "987654", "no request values in any span: %s", kv.Key)
		}
	}
	assert.True(t, server)

	tr.rec.Reset()
	assert.Equal(t, http.StatusOK, tr.get("/api/orders?limit=3", withKey()).Code)
	spans = spansByName(tr.rec)
	require.Len(t, spans["validation"], 1)
	got, _ := attr(spans["validation"][0], "validation.result")
	assert.Equal(t, "passed", got)
}
