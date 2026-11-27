package validation

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

func TestCheck_ValidRequestsPass(t *testing.T) {
	v := newValidator(t, config.RouteValidation{RejectUnknownOperations: true})
	for _, tc := range []struct {
		req *http.Request
		op  string
	}{
		{request(http.MethodGet, "/v1/items", "", ""), "listItems"},
		{request(http.MethodGet, "/v1/items?limit=10&sort=asc&since=2026-01-02T03:04:05Z", "", ""), "listItems"},
		{request(http.MethodGet, "/v1/items/"+validUUID, "", ""), "getItem"},
		{request(http.MethodPut, "/v1/items/"+validUUID, "application/json", validItem), "PUT /items/{id}"},
		{postItem(validItem), "createItem"},
		// HEAD falls back to the path's GET.
		{request(http.MethodHead, "/v1/items/"+validUUID, "", ""), "getItem"},
	} {
		res := check(v, tc.req)
		assert.Equal(t, Passed, res.Outcome, "%s %s: %+v", tc.req.Method, tc.req.URL, res.Violations)
		assert.Empty(t, res.Reason)
		assert.Equal(t, tc.op, res.Operation, "named by operationId, or method and path template")
	}
}

func TestCheck_InvalidQueryParameters(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	for _, tc := range []struct {
		query, field, msg string
	}{
		{"limit=abc", "limit", "must be an integer"},
		{"limit=0", "limit", "must be at least 1"},
		{"limit=101", "limit", "must be at most 100"},
		{"sort=sideways", "sort", "must be one of the allowed values"},
		{"since=yesterday", "since", "must be a valid date-time"},
	} {
		res := check(v, request(http.MethodGet, "/v1/items?"+tc.query, "", ""))
		require.Equal(t, Invalid, res.Outcome, tc.query)
		assert.Equal(t, ReasonParameter, res.Reason)
		got, ok := violation(res, "query", tc.field)
		require.True(t, ok, "%s: %+v", tc.query, res.Violations)
		assert.Equal(t, tc.msg, got.Message, tc.query)
	}
}

func TestCheck_InvalidPathParameter(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	res := check(v, request(http.MethodGet, "/v1/items/42", "", ""))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonParameter, res.Reason)
	assert.Equal(t, []Violation{{In: "path", Field: "id", Message: "must be a valid uuid"}}, res.Violations)
	assert.Equal(t, "getItem", res.Operation)
}

func TestCheck_HeaderParameters(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})

	res := check(v, request(http.MethodPost, "/v1/items", "application/json", validItem))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, []Violation{{In: "header", Field: "X-Request-Source", Message: "is required"}}, res.Violations)

	res = check(v, request(http.MethodPost, "/v1/items", "application/json", validItem, "X-Request-Source", "tv"))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, []Violation{{In: "header", Field: "X-Request-Source", Message: "must be one of the allowed values"}}, res.Violations)
}

func TestCheck_CredentialsAreNeverValidated(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	// The spec requires an X-Api-Key matching ^k- and a session cookie,
	// and declares an API key security scheme: all of it is auth's job.
	res := check(v, postItem(validItem))
	assert.Equal(t, Passed, res.Outcome, "missing credentials aren't validation's business: %+v", res.Violations)

	req := postItem(validItem)
	req.Header.Set("X-Api-Key", "not-matching-the-pattern")
	req.Header.Set("Authorization", "Bearer whatever")
	req.Header.Set("Cookie", "session=1")
	res = check(v, req)
	assert.Equal(t, Passed, res.Outcome, "%+v", res.Violations)
	assert.Equal(t, "not-matching-the-pattern", req.Header.Get("X-Api-Key"), "the request keeps its credentials for the backend")
}

func TestCheck_EveryFaultIsReported(t *testing.T) {
	v := newValidator(t, config.RouteValidation{})
	res := check(v, request(http.MethodGet, "/v1/items?limit=abc&sort=up&since=never", "", ""))
	require.Equal(t, Invalid, res.Outcome)
	assert.Len(t, res.Violations, 3, "%+v", res.Violations)
}

func TestCheck_UnknownOperations(t *testing.T) {
	forward := newValidator(t, config.RouteValidation{})
	reject := newValidator(t, config.RouteValidation{RejectUnknownOperations: true})

	for _, req := range []*http.Request{
		request(http.MethodGet, "/v1/nothing-here", "", ""),
		request(http.MethodGet, "/items", "", ""), // missing the server's /v1
		request(http.MethodDelete, "/v1/items", "", ""),
	} {
		res := check(forward, req)
		assert.Equal(t, Unmatched, res.Outcome, "%s %s is forwarded unchecked", req.Method, req.URL)
		assert.Empty(t, res.Violations)
	}

	res := check(reject, request(http.MethodGet, "/v1/nothing-here", "", ""))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonUnknownOperation, res.Reason)
	assert.Equal(t, []Violation{{In: "request", Message: "no operation in the API specification matches this path"}}, res.Violations)
	assert.Empty(t, res.Operation)

	res = check(reject, request(http.MethodDelete, "/v1/items", "", ""))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonUnknownOperation, res.Reason)
	assert.Equal(t, "the API specification has no operation for this method on this path", res.Violations[0].Message)
}

func TestResult_Label(t *testing.T) {
	assert.Equal(t, ResultPassed, Result{Outcome: Passed}.Label(true))
	assert.Equal(t, ResultUnmatched, Result{Outcome: Unmatched}.Label(false))
	assert.Equal(t, ResultRejected, Result{Outcome: Invalid}.Label(false))
	assert.Equal(t, ResultReportOnly, Result{Outcome: Invalid}.Label(true))
}
