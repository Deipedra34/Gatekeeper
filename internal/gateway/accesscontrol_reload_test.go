package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (h *acHarness) rewrite(t *testing.T, yaml string) {
	t.Helper()
	require.NoError(t, os.WriteFile(h.cfgPath, []byte(yaml), 0o644))
}

func TestAccessControlReload_AppliesChangedLists(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.1"]}
`))
	require.Equal(t, http.StatusForbidden, h.get("/", "198.51.100.1:1").Code)
	require.Equal(t, http.StatusOK, h.get("/", "198.51.100.2:1").Code)

	h.rewrite(t, acYAML(be.srv.URL, 100, `
    access_control: {mode: allowlist_only, allow: ["10.0.0.0/8"]}
`, `
access_control: {mode: denylist, deny: ["198.51.100.2"]}
`))
	require.NoError(t, h.gw.Reload())

	assert.Equal(t, http.StatusOK, h.get("/", "198.51.100.1:1").Code, "no longer denied")
	assert.Equal(t, http.StatusForbidden, h.get("/", "198.51.100.2:1").Code, "newly denied")
	assert.Equal(t, http.StatusForbidden, h.get("/admin", "198.51.100.1:1").Code, "new route override")
	assert.Equal(t, http.StatusOK, h.get("/admin", "10.0.0.1:1").Code)
	assert.Contains(t, h.logs.String(), "access_control: mode=denylist allow=0 deny=1 trusted_proxies=0 route_overrides=[/admin]")
}

func TestAccessControlReload_InvalidListKeepsTheOldOnes(t *testing.T) {
	be := newACBackend(t)
	good := acYAML(be.srv.URL, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.1"]}
`)
	h := newACHarness(t, good)
	before := h.gw.Config()

	for _, bad := range []string{
		`
access_control: {mode: denylist, deny: ["198.51.100.2", "198.51.100.300"]}
`, `
access_control: {mode: denylist, deny: ["198.51.100.2"], trusted_proxies: ["lb.internal"]}
`, `
access_control: {mode: allowlist_only}
`,
	} {
		h.rewrite(t, acYAML(be.srv.URL, 100, "", bad))
		err := h.gw.Reload()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_control")
		assert.Same(t, before, h.gw.Config(), "the old config stays live")
		assert.Equal(t, http.StatusForbidden, h.get("/", "198.51.100.1:1").Code, "the old deny list still applies")
		assert.Equal(t, http.StatusOK, h.get("/", "198.51.100.2:1").Code, "the rejected list never applied")
	}
}

func TestAccessControlReload_BansSurvive(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control: {}
`))
	_, err := h.gw.AccessControl().Ban(t.Context(), netipAddr("203.0.113.5"), time.Hour, "")
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, h.get("/", "203.0.113.5:1").Code)

	h.rewrite(t, acYAML(be.srv.URL, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.1"]}
`))
	require.NoError(t, h.gw.Reload())
	assert.Equal(t, http.StatusForbidden, h.get("/", "203.0.113.5:1").Code, "the ban is in the store, not the config")

	// Removing access control altogether removes the middleware with it.
	h.rewrite(t, acYAML(be.srv.URL, 100, "", ""))
	require.NoError(t, h.gw.Reload())
	assert.Nil(t, h.gw.AccessControl())
	assert.Equal(t, http.StatusOK, h.get("/", "203.0.113.5:1").Code)
	assert.Equal(t, http.StatusOK, h.get("/", "198.51.100.1:1").Code)
}

// TestAccessControlReload_InFlightRequestsFinish starts a request, reloads
// a config that denies its client while it's still at the backend, and
// checks it still completes — then that the next one is blocked.
func TestAccessControlReload_InFlightRequestsFinish(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		_, _ = w.Write([]byte("done"))
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	h := newACHarness(t, acYAML(slow.URL, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.1"]}
`))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- h.get("/", "203.0.113.7:1") }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the backend")
	}

	h.rewrite(t, acYAML(slow.URL, 100, "", `
access_control: {mode: denylist, deny: ["203.0.113.7"]}
`))
	require.NoError(t, h.gw.Reload())
	close(release)

	select {
	case rec := <-done:
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "done", rec.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never finished")
	}
	assert.Equal(t, http.StatusForbidden, h.get("/", "203.0.113.7:1").Code)
}
