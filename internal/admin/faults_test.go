package admin_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// faultAdminYAML is simpleYAML plus an "/api" route with fault injection
// settings faults (indented under fault_injection), and global settings
// global (indented under the top-level fault_injection).
func faultAdminYAML(target, global, faults string) string {
	return simpleYAML(target) + fmt.Sprintf(`  - path_prefix: "/api"
    target: %q
    fault_injection:
%s
fault_injection:
%s
`, target, faults, global)
}

func TestAdminFaults_ConfigRedactsFaultSecrets(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, "  global_enabled: false", `      enabled: true
      abort: {percentage: 5, status: 503}
      match:
        header: {name: X-Chaos-Token, value: chaos-token-0123456789}
        clients: {api_keys: [chaos-key-0123456789], tiers: [default]}`), harnessOptions{})

	r := h.call(http.MethodGet, "/admin/v1/config", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	for _, secret := range []string{"chaos-token-0123456789", "chaos-key-0123456789"} {
		assert.NotContains(t, r.raw, secret)
	}
	assert.Contains(t, r.raw, "key:", "targeted keys are shown as fingerprints")
	assert.Contains(t, r.raw, "X-Chaos-Token", "the header's name stays visible")
}
