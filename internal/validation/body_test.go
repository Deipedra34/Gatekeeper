package validation

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// readAll reads what's left of req's body.
func readAll(t *testing.T, req *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	return string(b)
}

func TestCheck_JSONBodyViolations(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	for _, tc := range []struct {
		name, body, field, msg string
	}{
		{"missing required field", `{"name":"hammer"}`, "/price", "is required"},
		{"wrong type", `{"name":"hammer","price":"cheap"}`, "/price", "must be a number"},
		{"wrong type of string", `{"name":7,"price":1}`, "/name", "must be a string"},
		{"enum", `{"name":"hammer","price":1,"kind":"car"}`, "/kind", "must be one of the allowed values"},
		{"email format", `{"name":"hammer","price":1,"owner":"not-an-email"}`, "/owner", "must be a valid email"},
		{"minimum", `{"name":"hammer","price":-1}`, "/price", "must be at least 0"},
		{"maxLength", `{"name":"` + strings.Repeat("x", 41) + `","price":1}`, "/name", "must be at most 40 characters long"},
		{"minLength", `{"name":"","price":1}`, "/name", "must be at least 1 characters long"},
		{"pattern", `{"name":"hammer","price":1,"tags":["DIY"]}`, "/tags/0", "must match the pattern ^[a-z]+$"},
		{"maxItems", `{"name":"hammer","price":1,"tags":["a","b","c","d"]}`, "/tags", "must have at most 3 items"},
		{"unknown property", `{"name":"hammer","price":1,"discount":50}`, "", "has a property the schema does not allow"},
		{"not an object", `["hammer"]`, "", "must be an object"},
		{"malformed JSON", `{"name": "hammer",`, "", "is not well-formed for its Content-Type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := check(v, postItem(tc.body))
			require.Equal(t, Invalid, res.Outcome)
			assert.Equal(t, ReasonBody, res.Reason)
			got, ok := violation(res, "body", tc.field)
			require.True(t, ok, "%+v", res.Violations)
			assert.Equal(t, tc.msg, got.Message)
		})
	}
}

func TestCheck_DateTimeAndUUIDFormats(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	assert.Equal(t, Passed, check(v, request(http.MethodGet, "/v1/items?since=2026-02-28T10:00:00%2B03:00", "", "")).Outcome)
	assert.Equal(t, Invalid, check(v, request(http.MethodGet, "/v1/items?since=2026-02-30T10:00:00Z", "", "")).Outcome,
		"February has no 30th")
	assert.Equal(t, Invalid, check(v, request(http.MethodGet, "/v1/items/6f1d2a3b-1c2d-4e5f-8a9b", "", "")).Outcome)
}

func TestCheck_MissingRequiredBody(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	res := check(v, request(http.MethodPost, "/v1/items", "", "", "X-Request-Source", "web"))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonBody, res.Reason)
	assert.Equal(t, []Violation{{In: "body", Message: "is required"}}, res.Violations)
}

func TestCheck_ParameterFaultsOutrankBodyFaults(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	res := check(v, request(http.MethodPut, "/v1/items/42", "application/json", `{"name":1}`))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonParameter, res.Reason, "one reason per request, by precedence")
	_, pathFault := violation(res, "path", "id")
	_, bodyFault := violation(res, "body", "/name")
	assert.True(t, pathFault && bodyFault, "both are listed: %+v", res.Violations)
}

func TestCheck_BodyIsRestoredIntactForTheBackend(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	for _, body := range []string{validItem, `{"name":1,"price":"x"}`, `{"broken"`} {
		req := postItem(body)
		check(v, req)
		assert.Equal(t, body, readAll(t, req), "the backend reads the same bytes, valid or not")
		assert.EqualValues(t, len(body), req.ContentLength)
	}
}

func TestCheck_JSONWithoutContentTypeIsCheckedAsJSON(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	req := request(http.MethodPost, "/v1/items", "", `{"name":"hammer"}`, "X-Request-Source", "web")
	res := check(v, req)
	require.Equal(t, Invalid, res.Outcome, "leaving Content-Type out doesn't get a body past validation")
	_, ok := violation(res, "body", "/price")
	assert.True(t, ok, "%+v", res.Violations)
	assert.Empty(t, req.Header.Get("Content-Type"), "the request itself isn't given one")
}

func TestCheck_ContentTypeParametersAreAccepted(t *testing.T) {
	v := newValidator(t, config.RouteValidation{ValidateContentType: true})
	req := request(http.MethodPost, "/v1/items", "application/json; charset=utf-8", validItem, "X-Request-Source", "web")
	assert.Equal(t, Passed, check(v, req).Outcome)
}

func TestCheck_UndeclaredContentType(t *testing.T) {
	body := "<item><name>hammer</name></item>"

	lenient := newValidator(t, config.RouteValidation{})
	req := request(http.MethodPost, "/v1/items", "application/xml", body, "X-Request-Source", "web")
	orig := req.Body
	assert.Equal(t, Passed, check(lenient, req).Outcome, "a type the operation doesn't declare isn't checked by default")
	assert.True(t, orig == req.Body, "nor read")

	strict := newValidator(t, config.RouteValidation{ValidateContentType: true})
	req = request(http.MethodPost, "/v1/items", "application/xml", body, "X-Request-Source", "web")
	res := check(strict, req)
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonContentType, res.Reason)
	assert.Equal(t, []Violation{{In: "header", Field: "Content-Type",
		Message: "is not a media type this operation accepts; use application/json or application/x-www-form-urlencoded"}}, res.Violations)
	assert.Equal(t, body, readAll(t, req))

	req = request(http.MethodPost, "/v1/items", "", validItem, "X-Request-Source", "web")
	res = check(strict, req)
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonContentType, res.Reason, "a body without a Content-Type")
	assert.Contains(t, res.Violations[0].Message, "is required with a request body")
}

func TestCheck_NonJSONBodies(t *testing.T) {
	const form = "application/x-www-form-urlencoded"

	skip := newValidator(t, config.RouteValidation{})
	req := request(http.MethodPost, "/v1/items", form, "name=ab", "X-Request-Source", "web")
	orig := req.Body
	assert.Equal(t, Passed, check(skip, req).Outcome, "only JSON is checked by default")
	assert.True(t, orig == req.Body, "a skipped body isn't even read")

	validate := newValidator(t, config.RouteValidation{ValidateNonJSONBodies: true})
	req = request(http.MethodPost, "/v1/items", form, "name=ab", "X-Request-Source", "web")
	res := check(validate, req)
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, []Violation{{In: "body", Field: "/name", Message: "must be at least 3 characters long"}}, res.Violations)
	assert.Equal(t, "name=ab", readAll(t, req))

	req = request(http.MethodPost, "/v1/items", form, "name=anvil", "X-Request-Source", "web")
	assert.Equal(t, Passed, check(validate, req).Outcome)
}

func TestCheck_NoDefaultsAreAddedToTheRequest(t *testing.T) {
	spec, err := ParseSpec("d.yaml", []byte(`openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /x:
    post:
      parameters:
        - {name: page, in: query, schema: {type: integer, default: 1}}
        - {name: X-Mode, in: header, schema: {type: string, default: fast}}
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {size: {type: integer, default: 10}}}
      responses: {"200": {description: ok}}
`))
	require.NoError(t, err)
	req := request(http.MethodPost, "/x", "application/json", `{}`)
	require.Equal(t, Passed, check(New(spec, config.RouteValidation{}), req).Outcome)
	assert.Empty(t, req.URL.RawQuery, "the backend gets the request as sent")
	assert.Empty(t, req.Header.Get("X-Mode"))
	assert.Equal(t, `{}`, readAll(t, req))
}
