package validation

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// testSpec exercises every kind of check: query, header, and path
// parameters, JSON and form bodies, formats, enums, bounds, patterns,
// and a credential header parameter. Its server URL has a host, which
// is ignored, and a path, /v1, which every operation's path starts with.
const testSpec = `openapi: 3.0.3
info: {title: Test API, version: 2.1.0}
servers:
  - url: https://api.example.com/v1
security: [{key: []}]
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 100}}
        - {name: sort, in: query, schema: {type: string, enum: [asc, desc]}}
        - {name: since, in: query, schema: {type: string, format: date-time}}
      responses: {"200": {description: ok}}
    post:
      operationId: createItem
      parameters:
        - {name: X-Request-Source, in: header, required: true, schema: {type: string, enum: [web, mobile]}}
        - {name: X-Api-Key, in: header, required: true, schema: {type: string, pattern: "^k-"}}
        - {name: session, in: cookie, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Item"}
          application/x-www-form-urlencoded:
            schema:
              type: object
              required: [name]
              properties: {name: {type: string, minLength: 3}}
      responses: {"201": {description: created}}
  /items/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: string, format: uuid}}
    get:
      operationId: getItem
      responses: {"200": {description: ok}}
    put:
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Item"}
      responses: {"200": {description: ok}}
components:
  securitySchemes:
    key: {type: apiKey, in: header, name: X-Api-Key}
  schemas:
    Item:
      type: object
      additionalProperties: false
      required: [name, price]
      properties:
        name: {type: string, minLength: 1, maxLength: 40}
        price: {type: number, minimum: 0}
        owner: {type: string, format: email}
        kind: {type: string, enum: [book, tool]}
        tags: {type: array, maxItems: 3, items: {type: string, pattern: "^[a-z]+$"}}
        meta: {type: object}
`

const (
	validUUID = "6f1d2a3b-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	validItem = `{"name":"hammer","price":12.5,"kind":"tool","tags":["diy"]}`
)

// writeFile writes contents to name in dir and returns its path.
func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	return path
}

// loadTestSpec loads testSpec, with X-Api-Key as the API key header.
func loadTestSpec(t *testing.T) *Spec {
	t.Helper()
	spec, err := ParseSpec("test.yaml", []byte(testSpec), "X-Api-Key")
	require.NoError(t, err)
	return spec
}

// newValidator is a validator for testSpec with cfg's settings.
func newValidator(t *testing.T, cfg config.RouteValidation) *Validator {
	t.Helper()
	return New(loadTestSpec(t), cfg)
}

// request builds a request; a non-empty contentType is set as the
// Content-Type, and headers are name/value pairs.
func request(method, target, contentType, body string, headers ...string) *http.Request {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	return req
}

// postItem is a POST /v1/items with body and the headers the operation
// requires.
func postItem(body string) *http.Request {
	return request(http.MethodPost, "/v1/items", "application/json", body, "X-Request-Source", "web")
}

func check(v *Validator, req *http.Request) Result {
	return v.Check(context.Background(), req)
}

// violation finds the violation for in and field.
func violation(res Result, in, field string) (Violation, bool) {
	for _, v := range res.Violations {
		if v.In == in && v.Field == field {
			return v, true
		}
	}
	return Violation{}, false
}
