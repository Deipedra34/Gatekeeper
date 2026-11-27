package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

const jsonSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "JSON API", "version": "1"},
  "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}}
}`

func TestLoadSpec_YAMLAndJSON(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeFile(t, dir, "api.yaml", testSpec)
	spec, err := LoadSpec(yamlPath)
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(testSpec))
	assert.Equal(t, yamlPath, spec.Path)
	assert.Equal(t, hex.EncodeToString(sum[:]), spec.Digest, "the digest is the file's SHA-256")
	assert.Equal(t, "3.0.3", spec.OpenAPI)
	assert.Equal(t, "Test API", spec.Title)
	assert.Equal(t, "2.1.0", spec.Version)
	assert.Equal(t, 4, spec.Operations, "GET and POST /items, GET and PUT /items/{id}")
	assert.False(t, spec.LoadedAt.IsZero())

	spec, err = LoadSpec(writeFile(t, dir, "api.json", jsonSpec))
	require.NoError(t, err)
	assert.Equal(t, "JSON API", spec.Title)
	assert.Equal(t, 1, spec.Operations)
}

func TestLoadSpec_MissingFileFailsClearly(t *testing.T) {
	_, err := LoadSpec("no/such/spec.yaml")
	require.Error(t, err)
	assert.Equal(t, "OpenAPI spec no/such/spec.yaml does not exist", err.Error())

	_, err = LoadSpec(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is a directory, not a file")
}

func TestLoadSpec_InvalidSpecsFail(t *testing.T) {
	for _, tc := range []struct {
		name, spec, want string
	}{
		{"not YAML or JSON", "openapi: [3.0.3\n", "could not be parsed"},
		{"Swagger 2.0", "swagger: \"2.0\"\ninfo: {title: T, version: \"1\"}\npaths: {}\n", "use OpenAPI 3.x"},
		{"no info", "openapi: 3.0.3\npaths: {}\n", "is invalid"},
		{"array without items", `openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /x:
    post:
      requestBody: {content: {application/json: {schema: {type: array}}}}
      responses: {"200": {description: ok}}
`, "is invalid"},
		{"undeclared path parameter", `openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /x/{id}:
    get:
      responses: {"200": {description: ok}}
`, "is invalid"},
		{"dangling $ref", `openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /x:
    get:
      responses: {"200": {$ref: "#/components/responses/Missing"}}
`, "could not be parsed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, t.TempDir(), "api.yaml", tc.spec)
			_, err := LoadSpec(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "OpenAPI spec "+path)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoadSpec_LocalRefsResolveAgainstTheSpecsDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "schemas/item.yaml", "Item:\n  type: object\n  required: [name]\n  properties:\n    name: {type: string}\n")
	path := writeFile(t, dir, "api.yaml", `openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /items:
    post:
      requestBody: {required: true, content: {application/json: {schema: {$ref: "./schemas/item.yaml#/Item"}}}}
      responses: {"201": {description: ok}}
`)
	spec, err := LoadSpec(path)
	require.NoError(t, err)
	v := New(spec, config.RouteValidation{})
	res := check(v, request(http.MethodPost, "/items", "application/json", `{}`))
	assert.Equal(t, Invalid, res.Outcome, "the referenced schema is applied")
	_, ok := violation(res, "body", "/name")
	assert.True(t, ok, "%+v", res.Violations)
}

func TestLoadSpec_RemoteRefsAreRefused(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("Item: {type: object}\n"))
	}))
	defer srv.Close()
	path := writeFile(t, t.TempDir(), "api.yaml", `openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /items:
    post:
      requestBody: {content: {application/json: {schema: {$ref: "`+srv.URL+`/item.yaml#/Item"}}}}
      responses: {"201": {description: ok}}
`)
	_, err := LoadSpec(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not be parsed")
	assert.Zero(t, hits.Load(), "loading a spec never reaches the network")
}

func TestLoadSpec_ServerHostIsIgnoredAndItsPathKept(t *testing.T) {
	spec := loadTestSpec(t)
	for _, tc := range []struct {
		host, path string
		found      bool
	}{
		{"api.example.com", "/v1/items", true},
		{"gateway.internal:8080", "/v1/items", true},
		{"api.example.com", "/items", false},
	} {
		req := request(http.MethodGet, tc.path, "", "")
		req.Host = tc.host
		_, _, err := spec.findRoute(req)
		assert.Equal(t, tc.found, err == nil, "%s%s", tc.host, tc.path)
	}
}

func TestLoadSpec_CredentialsAreLeftToAuth(t *testing.T) {
	spec := loadTestSpec(t)
	assert.Equal(t, 2, spec.IgnoredParameters, "the X-Api-Key header and the session cookie")
	assert.Nil(t, spec.doc.Security, "security requirements are dropped")
	assert.ElementsMatch(t, []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key"}, spec.secretHeaders)

	h := http.Header{"Authorization": {"Bearer t"}, "X-Api-Key": {"k"}, "Cookie": {"s=1"}, "Accept": {"*/*"}}
	assert.Equal(t, http.Header{"Accept": {"*/*"}}, spec.withoutSecrets(h))
	assert.Len(t, h, 4, "the request's own headers are untouched")
}

func TestLoadSpecReusing_ReusesOnlyAnUnchangedSpec(t *testing.T) {
	dir := t.TempDir()
	ref := writeFile(t, dir, "item.yaml", "Item: {type: object}\n")
	main := `openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /items:
    post:
      requestBody: {content: {application/json: {schema: {$ref: "./item.yaml#/Item"}}}}
      responses: {"201": {description: ok}}
`
	path := writeFile(t, dir, "api.yaml", main)
	first, reused, err := LoadSpecReusing(path, nil)
	require.NoError(t, err)
	assert.False(t, reused)

	again, reused, err := LoadSpecReusing(path, first)
	require.NoError(t, err)
	assert.True(t, reused)
	assert.Same(t, first, again, "nothing changed: the compiled spec is reused")

	_, reused, err = LoadSpecReusing(path, first, "X-Other-Key")
	require.NoError(t, err)
	assert.False(t, reused, "different credential headers")

	require.NoError(t, os.WriteFile(ref, []byte("Item: {type: object, required: [name]}\n"), 0o644))
	changedRef, reused, err := LoadSpecReusing(path, first)
	require.NoError(t, err)
	assert.False(t, reused, "a file the spec references changed")
	assert.NotSame(t, first, changedRef)

	require.NoError(t, os.WriteFile(path, []byte(main+"# edited\n"), 0o644))
	changedMain, reused, err := LoadSpecReusing(path, changedRef)
	require.NoError(t, err)
	assert.False(t, reused, "the spec itself changed")
	assert.NotEqual(t, changedRef.Digest, changedMain.Digest)

	other := writeFile(t, dir, "copy.yaml", main+"# edited\n")
	_, reused, err = LoadSpecReusing(other, changedMain)
	require.NoError(t, err)
	assert.False(t, reused, "another file, even with the same contents")
}

func TestLoadSpec_ShippedSpecsLoad(t *testing.T) {
	for _, path := range []string{"../../examples/openapi/orders.yaml", "../../docs/admin-openapi.yaml"} {
		_, err := LoadSpec(path)
		assert.NoError(t, err, path)
	}
}
