package gateway_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

// configYAML builds a minimal but complete config pointing "/" at target
// with a single "default" tier of the given burst. Auth and CORS are off
// so the tests exercise routing and rate-limit rules directly.
func configYAML(target string, burst int) string {
	return fmt.Sprintf(`
storage:
  backend: memory
rate_limit:
  algorithm: fixed_window
  scope: header
  header_name: "X-Client-ID"
  tiers:
    default: {requests_per_second: 1, burst: %d}
auth:
  enabled: false
cors:
  enabled: false
routes:
  - path_prefix: "/"
    target: "%s"
metrics:
  enabled: true
  path: "/metrics"
`, burst, target)
}

// writeConfig writes contents to a fresh file and returns its path.
func writeConfig(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	return path
}

// do sends a GET / through the gateway as client and returns the
// recorder.
func do(g *gateway.Gateway, client string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Client-ID", client)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

func newGateway(t *testing.T, configPath string) *gateway.Gateway {
	t.Helper()
	cfg, err := config.Load(configPath)
	require.NoError(t, err)

	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })

	g, err := gateway.New(cfg, configPath, st, metrics.New(), nil)
	require.NoError(t, err)
	return g
}

// TestGateway_ReloadAppliesNewConfig starts on one config, reloads a
// different valid config over it, and confirms the running gateway
// switches to the new backend route and the new rate-limit rule without
// a restart.
func TestGateway_ReloadAppliesNewConfig(t *testing.T) {
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-A"))
	}))
	t.Cleanup(backendA.Close)
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-B"))
	}))
	t.Cleanup(backendB.Close)

	dir := t.TempDir()
	// Config file the gateway reloads is always the same path; its
	// contents change between reloads.
	path := writeConfig(t, dir, "config.yaml", configYAML(backendA.URL, 2))
	g := newGateway(t, path)

	// Baseline: requests are proxied to backend A, and the default tier's
	// burst of 2 is enforced (3rd request in the same instant is 429).
	rec := do(g, "alice")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend-A", rec.Body.String())

	assert.Equal(t, http.StatusOK, do(g, "bob").Code)
	assert.Equal(t, http.StatusOK, do(g, "bob").Code)
	assert.Equal(t, http.StatusTooManyRequests, do(g, "bob").Code,
		"default tier burst is 2, third request should be rejected")

	// Reload a different valid config: new backend, higher burst.
	require.NoError(t, os.WriteFile(path, []byte(configYAML(backendB.URL, 5)), 0o644))
	require.NoError(t, g.Reload())

	// New route is live.
	rec = do(g, "carol")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend-B", rec.Body.String(), "reload should switch the proxied backend")

	// New rate-limit rule is live: a fresh client can now make 5 requests
	// before being rejected, not 2.
	for i := 0; i < 5; i++ {
		assert.Equal(t, http.StatusOK, do(g, "dave").Code, "request %d should be allowed under the new burst of 5", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, do(g, "dave").Code, "6th request should be rejected under the new burst of 5")

	assert.Equal(t, backendB.URL, g.Config().Routes[0].Target)
}

// TestGateway_ReloadRejectsInvalidConfig confirms that reloading a config
// that fails to parse or validate is refused, and the gateway keeps
// serving the previous config unchanged.
func TestGateway_ReloadRejectsInvalidConfig(t *testing.T) {
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-A"))
	}))
	t.Cleanup(backendA.Close)

	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", configYAML(backendA.URL, 2))
	g := newGateway(t, path)

	require.Equal(t, http.StatusOK, do(g, "alice").Code)

	t.Run("unknown algorithm is rejected", func(t *testing.T) {
		bad := `
rate_limit:
  algorithm: not_a_real_algorithm
  scope: header
  header_name: "X-Client-ID"
  tiers:
    default: {requests_per_second: 1, burst: 2}
routes:
  - path_prefix: "/"
    target: "` + backendA.URL + `"
`
		require.NoError(t, os.WriteFile(path, []byte(bad), 0o644))
		err := g.Reload()
		require.Error(t, err)
	})

	t.Run("malformed yaml is rejected", func(t *testing.T) {
		require.NoError(t, os.WriteFile(path, []byte("server: [::::\n"), 0o644))
		require.Error(t, g.Reload())
	})

	t.Run("missing file is rejected", func(t *testing.T) {
		require.NoError(t, os.Remove(path))
		require.Error(t, g.Reload())
	})

	// After every failed reload the original config is still active:
	// backend A, default burst 2.
	rec := do(g, "erin")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend-A", rec.Body.String())

	assert.Equal(t, http.StatusOK, do(g, "frank").Code)
	assert.Equal(t, http.StatusOK, do(g, "frank").Code)
	assert.Equal(t, http.StatusTooManyRequests, do(g, "frank").Code,
		"original burst of 2 should still be enforced after the rejected reloads")

	assert.Equal(t, "fixed_window", g.Config().RateLimit.Algorithm)
	assert.Equal(t, backendA.URL, g.Config().Routes[0].Target)
}

// TestGateway_ReloadIsSafeUnderConcurrentRequests hammers the gateway
// with concurrent traffic while repeatedly reloading the config, to
// surface races between request handling and the atomic pipeline swap
// (run with -race).
func TestGateway_ReloadIsSafeUnderConcurrentRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", configYAML(backend.URL, 100))
	g := newGateway(t, path)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			burst := 10 + i
			_ = os.WriteFile(path, []byte(configYAML(backend.URL, burst)), 0o644)
			_ = g.Reload()
		}
		close(done)
	}()

	for {
		select {
		case <-done:
			return
		default:
			do(g, "client")
		}
	}
}
