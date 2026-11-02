package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalRoutes = `
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`

// validHash is the SHA-256 of the empty string; any 64 hex chars would do.
const validHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func loadYAML(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	return Load(path)
}

func TestAdminConfig_DisabledByDefault(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes)
	require.NoError(t, err)
	assert.False(t, cfg.Admin.Enabled)
	assert.Equal(t, "127.0.0.1:9090", cfg.Admin.Listen, "loopback-only by default")
}

func TestAdminConfig_Validation(t *testing.T) {
	cases := []struct {
		name, admin, wantErr string
	}{
		{"no auth configured", `
admin:
  enabled: true`, "no admin authentication is configured"},
		{"plaintext token instead of a hash", `
admin:
  enabled: true
  tokens: [{id: ops, sha256: "my-plain-secret-token"}]`, "sha256 must be the 64-character hex SHA-256"},
		{"missing token id", `
admin:
  enabled: true
  tokens: [{sha256: "` + validHash + `"}]`, "admin.tokens[0].id is required"},
		{"duplicate token id", `
admin:
  enabled: true
  tokens: [{id: ops, sha256: "` + validHash + `"}, {id: ops, sha256: "` + validHash + `"}]`, "listed twice"},
		{"same port as the proxy", `
admin:
  enabled: true
  listen: "0.0.0.0:8080"
  tokens: [{id: ops, sha256: "` + validHash + `"}]`, "different port from server.listen_addr"},
		{"mtls without tls", `
admin:
  enabled: true
  mtls: {enabled: true}`, "admin.mtls.enabled needs admin.tls.enabled"},
		{"bad cidr", `
admin:
  enabled: true
  tokens: [{id: ops, sha256: "` + validHash + `"}]
  allowed_cidrs: ["10.0.0.0/33"]`, "admin.allowed_cidrs[0]"},
		{"tls without cert", `
admin:
  enabled: true
  tokens: [{id: ops, sha256: "` + validHash + `"}]
  tls: {enabled: true}`, "admin.tls.enabled is true but tls.cert_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, minimalRoutes+tc.admin)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.NotContains(t, err.Error(), "my-plain-secret-token", "errors never echo token material")
		})
	}
}

func TestAdminConfig_ValidSetups(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes+`
admin:
  enabled: true
  tokens: [{id: ops, sha256: "`+strings.ToUpper(validHash)+`"}]
  allowed_cidrs: ["10.0.0.0/8", "192.0.2.10", "::1"]
`)
	require.NoError(t, err)
	assert.Equal(t, validHash, cfg.Admin.Tokens[0].SHA256, "hashes are normalised to lowercase")
	prefixes, err := cfg.Admin.ParseAllowedCIDRs()
	require.NoError(t, err)
	assert.Len(t, prefixes, 3)
	assert.Equal(t, "192.0.2.10/32", prefixes[1].String())

	_, err = loadYAML(t, minimalRoutes+`
admin:
  enabled: true
  mtls: {enabled: true, allowed_cns: [ops]}
  tls:
    enabled: true
    cert_file: server.pem
    key_file: server-key.pem
    client_auth: require_and_verify
    client_ca_file: ca.pem
`)
	require.NoError(t, err, "client certificates alone are enough auth")
}
