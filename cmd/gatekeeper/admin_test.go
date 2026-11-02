package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

func loadConfig(t *testing.T, yaml string) (*config.Config, string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	cfg, err := config.Load(path)
	return cfg, path, err
}

// freePort returns a local port nothing is listening on right now.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func TestStartAdmin_DisabledByDefaultOpensNoPort(t *testing.T) {
	addr := freePort(t)
	// admin.listen is set but admin.enabled is left at its default.
	cfg, path, err := loadConfig(t, fmt.Sprintf(`
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
admin:
  listen: %q
`, addr))
	require.NoError(t, err)
	require.False(t, cfg.Admin.Enabled)

	st := store.NewMemoryStore()
	defer st.Close()
	m := metrics.New()
	gw, err := gateway.New(cfg, path, st, m, log.New(io.Discard, "", 0))
	require.NoError(t, err)
	defer gw.Close()

	srv, err := startAdmin(cfg, gw, gw.Reload, m)
	require.NoError(t, err)
	assert.Nil(t, srv)

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		conn.Close()
	}
	assert.Error(t, err, "nothing listens on the admin address while admin is disabled")
}

func TestStartup_FailsWithAdminEnabledButNoAuth(t *testing.T) {
	_, _, err := loadConfig(t, `
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
admin:
  enabled: true
`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin.enabled is true but no admin authentication is configured")
}
