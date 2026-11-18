package admin_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// splitAdminYAML is simpleYAML plus "/api", split 90/10 between stable
// and canary (with extra under traffic_split).
func splitAdminYAML(target, stable, canary, extra string) string {
	return simpleYAML(target) + fmt.Sprintf(`  - path_prefix: "/api"
    traffic_split:
      variants:
        - {name: stable, weight: 90, target: %q}
        - {name: canary, weight: 10, backends: [{target: %q, weight: 3}]}
%s`, stable, canary, extra)
}

func TestAdminSplit_RouteListingShowsVariantBackends(t *testing.T) {
	root, _ := namedBackend(t, "root")
	stable, _ := namedBackend(t, "stable")
	canary, _ := namedBackend(t, "canary")
	h := start(t, splitAdminYAML(root.URL, stable.URL, canary.URL, ""), harnessOptions{})

	r := h.call(http.MethodGet, "/admin/v1/routes", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	routes := r.json["routes"].([]any)
	require.Len(t, routes, 2)
	api := routes[1].(map[string]any)
	assert.Equal(t, "/api", api["label"])
	backends := api["backends"].([]any)
	require.Len(t, backends, 2)
	b0, b1 := backends[0].(map[string]any), backends[1].(map[string]any)
	assert.Equal(t, "stable", b0["variant"])
	assert.Equal(t, "canary", b1["variant"])
	assert.EqualValues(t, 3, b1["weight"])
	assert.NotEmpty(t, b0["target"])

	plain := routes[0].(map[string]any)["backends"].([]any)[0].(map[string]any)
	assert.NotContains(t, plain, "variant", "unsplit routes list backends as before")
}
