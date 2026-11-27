package admin_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const adminOrdersSpec = `openapi: 3.0.3
info: {title: Orders, version: 1.2.0}
paths:
  /orders:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 10}}
      responses: {"200": {description: ok}}
`

// validationAdminYAML is simpleYAML plus an "/api" route, its prefix
// stripped, validated against spec in report_only mode or not.
func validationAdminYAML(target, spec string, reportOnly bool) string {
	mode := "enforce"
	if reportOnly {
		mode = "report_only"
	}
	return simpleYAML(target) + fmt.Sprintf(`  - path_prefix: "/api"
    target: %q
    transform: {request: {strip_prefix: true}}
    validation:
      enabled: true
      openapi_file: %q
      mode: %s
      reject_status: 422
`, target, filepath.ToSlash(spec), mode)
}

func TestAdminValidation_ListsSpecsSettingsAndCounts(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	spec := filepath.Join(t.TempDir(), "orders.yaml")
	require.NoError(t, os.WriteFile(spec, []byte(adminOrdersSpec), 0o644))
	h := start(t, validationAdminYAML(backend.URL, spec, false), harnessOptions{})

	assert.Equal(t, http.StatusOK, h.get("/api/orders?limit=5", nil).StatusCode)
	assert.Equal(t, http.StatusUnprocessableEntity, h.get("/api/orders?limit=50", nil).StatusCode)
	assert.Equal(t, http.StatusUnprocessableEntity, h.get("/api/orders?limit=x", nil).StatusCode)
	assert.Equal(t, http.StatusOK, h.get("/api/elsewhere", nil).StatusCode, "unmatched, forwarded")
	assert.Equal(t, http.StatusOK, h.get("/other", nil).StatusCode, "not a validated route")

	r := h.call(http.MethodGet, "/admin/v1/validation", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	routes := r.json["routes"].([]any)
	require.Len(t, routes, 1, "only routes that validate are listed")
	route := routes[0].(map[string]any)
	assert.Equal(t, "/api", route["route"])
	var routeID any
	for _, rt := range h.call(http.MethodGet, "/admin/v1/routes", adminToken, "").json["routes"].([]any) {
		if rt.(map[string]any)["label"] == "/api" {
			routeID = rt.(map[string]any)["id"]
		}
	}
	assert.Equal(t, routeID, route["route_id"], "the same id GET /admin/v1/routes gives the route")
	assert.Equal(t, "enforce", route["mode"])

	sum := sha256.Sum256([]byte(adminOrdersSpec))
	s := route["spec"].(map[string]any)
	assert.Equal(t, filepath.ToSlash(spec), s["file"])
	assert.Equal(t, "Orders", s["title"])
	assert.Equal(t, "1.2.0", s["version"])
	assert.Equal(t, "3.0.3", s["openapi"])
	assert.EqualValues(t, 1, s["operations"])
	assert.Equal(t, hex.EncodeToString(sum[:]), s["sha256"])
	assert.NotEmpty(t, s["loaded_at"])

	settings := route["settings"].(map[string]any)
	assert.EqualValues(t, 422, settings["reject_status"])
	assert.EqualValues(t, 1<<20, settings["max_body_bytes"])
	assert.EqualValues(t, 32, settings["max_json_depth"])
	assert.Equal(t, "100ms", settings["timeout"])
	assert.Equal(t, false, settings["reject_unknown_operations"])

	counters := route["counters"].(map[string]any)
	assert.EqualValues(t, 4, counters["validated"])
	assert.EqualValues(t, 1, counters["passed"])
	assert.EqualValues(t, 2, counters["rejected"])
	assert.EqualValues(t, 1, counters["unmatched"])
	assert.EqualValues(t, 0, counters["report_only"])
	assert.Equal(t, map[string]any{"parameter": 2.0}, counters["rejected_by_reason"])
	assert.Equal(t, map[string]any{}, counters["report_only_by_reason"])

	assert.Equal(t, []any{"unknown_operation", "content_type", "body_too_large", "parameter", "body", "timeout", "internal"}, r.json["reasons"])
}

func TestAdminValidation_RequiresAuthentication(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{})
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/admin/v1/validation", "", "").status)

	r := h.call(http.MethodGet, "/admin/v1/validation", adminToken, "")
	require.Equal(t, http.StatusOK, r.status)
	assert.Equal(t, []any{}, r.json["routes"], "an empty list without validated routes")
}

func TestAdminValidation_ReloadWithABrokenSpecIsRefused(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	spec := filepath.Join(t.TempDir(), "orders.yaml")
	require.NoError(t, os.WriteFile(spec, []byte(adminOrdersSpec), 0o644))
	h := start(t, validationAdminYAML(backend.URL, spec, true), harnessOptions{})
	before := h.call(http.MethodGet, "/admin/v1/validation", adminToken, "").json["routes"].([]any)[0].(map[string]any)["spec"].(map[string]any)["sha256"]

	require.NoError(t, os.WriteFile(spec, []byte("openapi: 3.0.3\ninfo: {title: broken}\n"), 0o644))
	for _, path := range []string{"/admin/v1/reload?dry_run=true", "/admin/v1/reload"} {
		bad := h.call(http.MethodPost, path, adminToken, "")
		assert.Equal(t, http.StatusUnprocessableEntity, bad.status, path)
		assert.Equal(t, "invalid_config", bad.errorCode(), path)
		assert.Contains(t, bad.raw, "OpenAPI spec", path)
	}

	r := h.call(http.MethodGet, "/admin/v1/validation", adminToken, "")
	route := r.json["routes"].([]any)[0].(map[string]any)
	assert.Equal(t, "report_only", route["mode"])
	assert.Equal(t, before, route["spec"].(map[string]any)["sha256"], "the spec in force is unchanged")
	assert.Equal(t, http.StatusOK, h.get("/api/orders?limit=50", nil).StatusCode, "report_only forwards it")
}
