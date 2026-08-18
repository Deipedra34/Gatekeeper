package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	return path
}

func TestLoad_ValidMinimalConfig(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  algorithm: token_bucket
  scope: ip
  tiers:
    default:
      requests_per_second: 5
      burst: 10
routes:
  - path_prefix: "/api"
    target: "http://localhost:9000"
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.Server.ListenAddr, "unset server fields should get defaults")
	assert.Equal(t, 10*time.Second, cfg.Server.ReadTimeout.Duration)
	assert.Equal(t, "memory", cfg.Storage.Backend, "backend should default to memory")
	assert.Equal(t, "/metrics", cfg.Metrics.Path)
}

func TestLoad_DurationsParseFromHumanStrings(t *testing.T) {
	path := writeConfig(t, `
server:
  listen_addr: ":9090"
  read_timeout: 5s
rate_limit:
  tiers:
    default:
      requests_per_second: 1
      burst: 1
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, cfg.Server.ReadTimeout.Duration)
}

func TestLoad_RejectsUnknownAlgorithm(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  algorithm: leaky_bucket
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "algorithm")
}

func TestLoad_RejectsMissingRoutes(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "route")
}

func TestLoad_RejectsRedisBackendWithoutAddr(t *testing.T) {
	path := writeConfig(t, `
storage:
  backend: redis
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "redis")
}

func TestLoad_RejectsHeaderScopeWithoutHeaderName(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  scope: header
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "header_name")
}

func TestLoad_RejectsAuthEnabledWithoutKeys(t *testing.T) {
	path := writeConfig(t, `
auth:
  enabled: true
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "api_keys")
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	assert.Error(t, err)
}
