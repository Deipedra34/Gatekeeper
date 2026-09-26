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

	assert.Equal(t, 5*time.Second, cfg.Proxy.Timeout.Duration, "proxy timeout should default to 5s")
	assert.Equal(t, 3, cfg.Proxy.Retry.MaxRetries, "max_retries should default to 3")
	assert.Equal(t, 100*time.Millisecond, cfg.Proxy.Retry.BaseBackoff.Duration)
	assert.Equal(t, 2*time.Second, cfg.Proxy.Retry.MaxBackoff.Duration)
}

func TestLoad_ProxyTimeoutAndRetryAreConfigurable(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
proxy:
  timeout: 2s
  retry:
    max_retries: 5
    base_backoff: 50ms
    max_backoff: 1s
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Second, cfg.Proxy.Timeout.Duration)
	assert.Equal(t, 5, cfg.Proxy.Retry.MaxRetries)
	assert.Equal(t, 50*time.Millisecond, cfg.Proxy.Retry.BaseBackoff.Duration)
	assert.Equal(t, time.Second, cfg.Proxy.Retry.MaxBackoff.Duration)
}

func TestLoad_RejectsMaxBackoffBelowBaseBackoff(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
proxy:
  retry:
    base_backoff: 1s
    max_backoff: 500ms
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "max_backoff")
}

func TestLoad_RejectsNegativeMaxRetries(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
proxy:
  retry:
    max_retries: -1
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "max_retries")
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

func TestLoad_RouteCacheDefaultsToEnabledWithSixtySecondTTL(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	require.True(t, cfg.Routes[0].Cache.IsEnabled(), "cache should be enabled by default")
	assert.Equal(t, 60*time.Second, cfg.Routes[0].Cache.TTL.Duration, "cache ttl should default to 60s")
}

func TestLoad_RouteCacheCanBeDisabledAndTTLOverridden(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/api"
    target: "http://localhost:9000"
    cache:
      enabled: false
  - path_prefix: "/"
    target: "http://localhost:9001"
    cache:
      ttl: 30s
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.False(t, cfg.Routes[0].Cache.IsEnabled(), "explicitly disabled route should opt out of caching")
	assert.True(t, cfg.Routes[1].Cache.IsEnabled())
	assert.Equal(t, 30*time.Second, cfg.Routes[1].Cache.TTL.Duration)
}

func TestLoad_RejectsNegativeCacheTTL(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
    cache:
      ttl: -5s
`)

	_, err := Load(path)
	assert.ErrorContains(t, err, "cache.ttl")
}

func TestLoad_RouteCircuitBreakerDefaults(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	cb := cfg.Routes[0].CircuitBreaker
	require.True(t, cb.IsEnabled(), "circuit breaker should be enabled by default")
	assert.Equal(t, 5, cb.FailureThreshold)
	assert.Equal(t, 30*time.Second, cb.OpenDuration.Duration)
	assert.Equal(t, 1, cb.HalfOpenMaxRequests)
	assert.Equal(t, 1, cb.HalfOpenSuccessesToClose)
	assert.Equal(t, 1, cb.HalfOpenFailuresToReopen)
}

func TestLoad_RouteCircuitBreakerCanBeDisabledAndTuned(t *testing.T) {
	path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/api"
    target: "http://localhost:9000"
    circuit_breaker:
      enabled: false
  - path_prefix: "/"
    target: "http://localhost:9001"
    circuit_breaker:
      failure_threshold: 10
      open_duration: 15s
      half_open_max_requests: 3
      half_open_successes_to_close: 2
      half_open_failures_to_reopen: 2
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.False(t, cfg.Routes[0].CircuitBreaker.IsEnabled())

	cb := cfg.Routes[1].CircuitBreaker
	assert.True(t, cb.IsEnabled())
	assert.Equal(t, 10, cb.FailureThreshold)
	assert.Equal(t, 15*time.Second, cb.OpenDuration.Duration)
	assert.Equal(t, 3, cb.HalfOpenMaxRequests)
	assert.Equal(t, 2, cb.HalfOpenSuccessesToClose)
	assert.Equal(t, 2, cb.HalfOpenFailuresToReopen)
}

func TestLoad_RejectsNegativeCircuitBreakerFields(t *testing.T) {
	cases := []struct {
		name  string
		field string
	}{
		{"failure_threshold: -1", "failure_threshold"},
		{"open_duration: -5s", "open_duration"},
		{"half_open_max_requests: -1", "half_open_max_requests"},
		{"half_open_successes_to_close: -1", "half_open_successes_to_close"},
		{"half_open_failures_to_reopen: -1", "half_open_failures_to_reopen"},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			path := writeConfig(t, `
rate_limit:
  tiers:
    default: {requests_per_second: 1, burst: 1}
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
    circuit_breaker:
      `+tc.name+`
`)
			_, err := Load(path)
			assert.ErrorContains(t, err, tc.field)
		})
	}
}
