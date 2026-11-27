package validation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// errorJSON is the error body as a client decodes it.
type errorJSON struct {
	Error struct {
		Code       string      `json:"code"`
		Message    string      `json:"message"`
		Reason     string      `json:"reason"`
		RequestID  *string     `json:"request_id"`
		Violations []Violation `json:"violations"`
		Truncated  bool        `json:"violations_truncated"`
	} `json:"error"`
}

func writeError(t *testing.T, status int, res Result, requestID string) (*httptest.ResponseRecorder, errorJSON) {
	t.Helper()
	rec := httptest.NewRecorder()
	WriteError(rec, status, res, requestID)
	var body errorJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return rec, body
}

func TestWriteError_Format(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	res := check(v, postItem(`{"name":"hammer","price":-1}`))
	rec, body := writeError(t, http.StatusUnprocessableEntity, res, "req-123")

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, ErrorCode, body.Error.Code)
	assert.Equal(t, "the request does not match the API specification", body.Error.Message)
	assert.Equal(t, ReasonBody, body.Error.Reason)
	require.NotNil(t, body.Error.RequestID)
	assert.Equal(t, "req-123", *body.Error.RequestID)
	assert.Equal(t, []Violation{{In: "body", Field: "/price", Message: "must be at least 0"}}, body.Error.Violations)
	assert.False(t, body.Error.Truncated)
}

func TestWriteError_WithoutRequestIDsOrViolations(t *testing.T) {
	rec, body := writeError(t, http.StatusBadRequest, Result{Outcome: Invalid, Reason: ReasonTimeout}, "")
	assert.Nil(t, body.Error.RequestID, "left out when request IDs are off")
	assert.NotContains(t, rec.Body.String(), "request_id")
	assert.Equal(t, []Violation{}, body.Error.Violations, "always a list, never null")
	assert.Equal(t, "the request could not be validated in time", body.Error.Message)
}

func TestResult_Status(t *testing.T) {
	for reason, want := range map[string]int{
		ReasonParameter: http.StatusUnprocessableEntity, ReasonBody: http.StatusUnprocessableEntity,
		ReasonUnknownOperation: http.StatusUnprocessableEntity, ReasonContentType: http.StatusUnprocessableEntity,
		ReasonTimeout: http.StatusUnprocessableEntity, ReasonBodyTooLarge: http.StatusRequestEntityTooLarge,
		ReasonInternal: http.StatusInternalServerError,
	} {
		assert.Equal(t, want, Result{Outcome: Invalid, Reason: reason}.Status(http.StatusUnprocessableEntity), reason)
	}
}

// secret stands for a credential or personal value a client sent: it
// must never come back in an error body.
const secret = "s3cr3t-T0KEN-value"

func TestErrorBody_NeverEchoesWhatTheClientSent(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	body := fmt.Sprintf(`{"name":{"token":%q},"price":%q,"owner":%q,"kind":%q,"tags":[%q],%q:1}`,
		secret, secret, secret, secret, secret, secret)
	req := request(http.MethodPost, "/v1/items?limit="+secret, "application/json", body,
		"X-Request-Source", secret, "Authorization", "Bearer "+secret, "X-Api-Key", secret)
	res := check(v, req)
	require.Equal(t, Invalid, res.Outcome)
	require.NotEmpty(t, res.Violations)

	rec, _ := writeError(t, http.StatusBadRequest, res, "")
	assert.NotContains(t, rec.Body.String(), secret)
	assert.NotContains(t, rec.Body.String(), "s3cr3t", "not even in part")
	assert.Equal(t, body, readAll(t, req), "the body itself is untouched")
}

func TestErrorBody_NeverEchoesValuesWithOpenAPI31(t *testing.T) {
	// OpenAPI 3.1 schemas are checked by a JSON Schema 2020-12 validator
	// whose own messages include the failing values; ours don't use them.
	spec, err := ParseSpec("v31.yaml", []byte(`openapi: 3.1.0
info: {title: T, version: "1"}
paths:
  /x:
    post:
      parameters:
        - {name: q, in: query, schema: {type: string, pattern: "^[0-9]+$"}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [a]
              properties:
                a: {type: string, enum: [one, two]}
                b: {type: integer, maximum: 3}
                c: {type: string, format: email, maxLength: 5}
      responses: {"200": {description: ok}}
`))
	require.NoError(t, err)
	res := check(New(spec, config.RouteValidation{}), request(http.MethodPost, "/x?q="+secret, "application/json",
		fmt.Sprintf(`{"a":%q,"b":987654321,"c":%q}`, secret, secret)))
	require.Equal(t, Invalid, res.Outcome)
	rec, body := writeError(t, http.StatusBadRequest, res, "")
	assert.NotContains(t, rec.Body.String(), secret)
	assert.NotContains(t, rec.Body.String(), "987654321")
	_, ok := violation(res, "body", "/a")
	assert.True(t, ok, "the failing fields are still named: %+v", body.Error.Violations)
}

func TestViolations_AreCapped(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	tags := make([]string, 30)
	for i := range tags {
		tags[i] = `"UPPER"`
	}
	res := check(v, postItem(`{"name":"hammer","price":1,"tags":[`+strings.Join(tags, ",")+`]}`))
	require.Equal(t, Invalid, res.Outcome)
	assert.Len(t, res.Violations, maxViolations)
	assert.True(t, res.Truncated)
	_, body := writeError(t, http.StatusBadRequest, res, "")
	assert.True(t, body.Error.Truncated, "the body says there were more")
}

func TestFieldNames_AreSafeToEchoAndLog(t *testing.T) {
	spec, err := ParseSpec("m.yaml", []byte(`openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /counts:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object, additionalProperties: {type: integer}}
      responses: {"200": {description: ok}}
`))
	require.NoError(t, err)
	long := strings.Repeat("k", 500)
	res := check(New(spec, config.RouteValidation{}), request(http.MethodPost, "/counts", "application/json",
		`{"line\nbreak":"x","a/b~c":"x",`+fmt.Sprintf("%q", long)+`:"x"}`))
	require.Equal(t, Invalid, res.Outcome)

	fields := map[string]bool{}
	for _, v := range res.Violations {
		fields[v.Field] = true
		assert.NotContains(t, v.Field, "\n", "no control characters for a log line to break on")
		assert.LessOrEqual(t, len(v.Field), maxFieldSegment+8, "property names are cut short")
	}
	assert.True(t, fields["/line?break"], "%v", fields)
	assert.True(t, fields["/a~1b~0c"], "JSON pointer escaping: %v", fields)
	assert.True(t, fields["/"+strings.Repeat("k", maxFieldSegment)+"..."], "%v", fields)
}

func TestCleanSegment(t *testing.T) {
	assert.Equal(t, "plain", cleanSegment("plain"))
	assert.Equal(t, "tab?del?", cleanSegment("tab\tdel\x7f"))
	assert.Equal(t, "bad?utf8", cleanSegment("bad\xffutf8"))
	assert.Equal(t, "ünïcode", cleanSegment("ünïcode"), "valid UTF-8 is kept")
}
