package admin_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const splitPath = "/admin/v1/routes/%2Fapi/split"

func splitHarness(t *testing.T, extra string) *harness {
	t.Helper()
	root, _ := namedBackend(t, "root")
	stable, _ := namedBackend(t, "stable")
	canary, _ := namedBackend(t, "canary")
	return start(t, splitAdminYAML(root.URL, stable.URL, canary.URL, extra), harnessOptions{})
}

// weightsOf returns the variant weights in a split status.
func weightsOf(t *testing.T, status map[string]any) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, v := range status["variants"].([]any) {
		m := v.(map[string]any)
		out[m["name"].(string)] = m["weight"].(float64)
	}
	return out
}

// publicGet fetches path from the public listener and returns the body.
func (h *harness) publicGet(t *testing.T, path string) string {
	t.Helper()
	resp, err := http.Get(h.public.URL + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestAdminSplit_GetStatus(t *testing.T) {
	h := splitHarness(t, "      rollout: {variant: canary, steps: [5, 50], interval: 1h}\n")
	for _, path := range []string{splitPath, "/admin/v1/routes/api/split"} {
		r := h.call(http.MethodGet, path, adminToken, "")
		require.Equal(t, http.StatusOK, r.status, r.raw)
		assert.Equal(t, "/api", r.json["route"])
		assert.Equal(t, "stable", r.json["baseline"])
		assert.Equal(t, map[string]float64{"stable": 95, "canary": 5}, weightsOf(t, r.json))
		assert.Equal(t, false, r.json["manual"])
		ro := r.json["rollout"].(map[string]any)
		assert.Equal(t, "running", ro["state"])
		assert.Equal(t, "canary", ro["variant"])
		assert.NotEmpty(t, ro["next_step_at"])
	}

	// Every route has an id, which works for any label, "/" included.
	routes := h.call(http.MethodGet, "/admin/v1/routes", adminToken, "").json["routes"].([]any)
	rootID := routes[0].(map[string]any)["id"].(string)
	apiID := routes[1].(map[string]any)["id"].(string)
	assert.Len(t, apiID, 12)
	r := h.call(http.MethodGet, "/admin/v1/routes/"+apiID+"/split", adminToken, "")
	assert.Equal(t, http.StatusOK, r.status)
	assert.Equal(t, "/api", r.json["route"])

	r = h.call(http.MethodGet, "/admin/v1/routes/"+rootID+"/split", adminToken, "")
	assert.Equal(t, http.StatusConflict, r.status)
	assert.Contains(t, r.raw, "route / has no traffic_split")
	assert.Equal(t, http.StatusNotFound, h.call(http.MethodGet, "/admin/v1/routes/nope/split", adminToken, "").status)
}

func TestAdminSplit_SetPauseResumePromoteRollback(t *testing.T) {
	h := splitHarness(t, "      rollout: {variant: canary, steps: [5, 50], interval: 1h}\n")
	post := func(body string) response { return h.call(http.MethodPost, splitPath, adminToken, body) }
	splitOf := func(r response) map[string]any { return r.json["split"].(map[string]any) }

	r := post(`{"action": "pause"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, "paused", splitOf(r)["rollout"].(map[string]any)["state"])
	r = post(`{"action": "resume"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, "running", splitOf(r)["rollout"].(map[string]any)["state"])

	r = post(`{"action": "set", "weights": {"stable": 75, "canary": 25}}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, map[string]float64{"stable": 75, "canary": 25}, weightsOf(t, splitOf(r)))
	assert.Equal(t, true, splitOf(r)["manual"])

	r = post(`{"action": "promote"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, map[string]float64{"stable": 0, "canary": 100}, weightsOf(t, splitOf(r)))
	for range 10 {
		assert.Equal(t, "canary", h.publicGet(t, "/api/x"), "the gateway serves what the admin API set")
	}

	r = post(`{"action": "rollback", "reason": "error budget"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, map[string]float64{"stable": 100, "canary": 0}, weightsOf(t, splitOf(r)))
	lr := splitOf(r)["last_rollback"].(map[string]any)
	assert.Equal(t, "error budget", lr["reason"])
	assert.Equal(t, "manual", lr["trigger"])
	for range 10 {
		assert.Equal(t, "stable", h.publicGet(t, "/api/x"))
	}

	r = post(`{"action": "rollback"}`)
	assert.Equal(t, http.StatusConflict, r.status, "nothing left to roll back")

	r = post(`{"action": "resume"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, map[string]float64{"stable": 95, "canary": 5}, weightsOf(t, splitOf(r)), "the rollout starts over")
}

func TestAdminSplit_RejectsBadRequests(t *testing.T) {
	h := splitHarness(t, "")
	for body, want := range map[string]int{
		`{}`:                    http.StatusBadRequest,
		`{"action": "explode"}`: http.StatusBadRequest,
		`{"action": "set"}`:     http.StatusBadRequest,
		`{"action": "set", "weights": {"stable": 50}}`:                       http.StatusBadRequest,
		`{"action": "set", "weights": {"stable": 50, "blue": 50}}`:           http.StatusBadRequest,
		`{"action": "set", "weights": {"stable": 50, "canary": 60}}`:         http.StatusBadRequest,
		`{"action": "set", "weights": {"stable": 50, "canary": 50}, "x": 1}`: http.StatusBadRequest,
		`{"action": "promote", "variant": "blue"}`:                           http.StatusBadRequest,
		`{"action": "rollback", "variant": "stable"}`:                        http.StatusConflict,
		`{"action": "pause"}`:                                                http.StatusConflict, // no rollout
		`{"action": "resume"}`:                                               http.StatusConflict, // nothing to resume
	} {
		r := h.call(http.MethodPost, splitPath, adminToken, body)
		assert.Equal(t, want, r.status, "%s: %s", body, r.raw)
	}
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodPost, splitPath, "", `{"action": "pause"}`).status)
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, splitPath, "wrong", "").status)

	r := h.call(http.MethodDelete, splitPath, adminToken, "")
	assert.Equal(t, http.StatusMethodNotAllowed, r.status)
	assert.Equal(t, "GET, POST", r.header.Get("Allow"))
}

func TestAdminSplit_DryRunChangesNothing(t *testing.T) {
	h := splitHarness(t, "")
	r := h.call(http.MethodPost, splitPath+"?dry_run=true", adminToken, `{"action": "promote"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["dry_run"])
	assert.Equal(t, map[string]float64{"stable": 90, "canary": 10}, weightsOf(t, r.json["split"].(map[string]any)))

	// A dry run still checks the request.
	r = h.call(http.MethodPost, splitPath+"?dry_run=true", adminToken, `{"action": "set", "weights": {"stable": 1}}`)
	assert.Equal(t, http.StatusBadRequest, r.status)
}

func TestAdminSplit_CooldownNeedsForce(t *testing.T) {
	root, _ := namedBackend(t, "root")
	stable, _ := namedBackend(t, "stable")
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)
	h := start(t, strings.Replace(splitAdminYAML(root.URL, stable.URL, failing.URL, ""),
		"weight: 3}]}", "weight: 3}], auto_rollback: {min_requests: 5, max_error_rate_increase: 0.1, cooldown: 1h}}", 1), harnessOptions{})

	r := h.call(http.MethodPost, splitPath, adminToken, `{"action": "set", "weights": {"stable": 0, "canary": 100}}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	require.Eventually(t, func() bool {
		h.publicGet(t, "/api/x")
		st := h.call(http.MethodGet, splitPath, adminToken, "")
		return weightsOf(t, st.json)["canary"] == 0
	}, 5*time.Second, 50*time.Millisecond, "the failing canary is rolled back")

	st := h.call(http.MethodGet, splitPath, adminToken, "")
	lr := st.json["last_rollback"].(map[string]any)
	assert.Equal(t, "error_rate", lr["trigger"])
	assert.Equal(t, true, lr["auto"])
	assert.NotEmpty(t, st.json["variants"].([]any)[1].(map[string]any)["cooldown_until"])

	r = h.call(http.MethodPost, splitPath, adminToken, `{"action": "resume"}`)
	assert.Equal(t, http.StatusConflict, r.status)
	assert.Contains(t, r.raw, "cooling down")
	r = h.call(http.MethodPost, splitPath, adminToken, `{"action": "resume", "force": true}`)
	assert.Equal(t, http.StatusOK, r.status, r.raw)
}

func TestAdminSplit_ActionsAreAudited(t *testing.T) {
	h := splitHarness(t, "")
	h.call(http.MethodPost, splitPath, adminToken, `{"action": "rollback"}`)
	h.call(http.MethodPost, splitPath, adminToken, `{"action": "explode"}`)
	h.call(http.MethodGet, splitPath, adminToken, "")

	var seen []string
	for _, rec := range h.auditRecords() {
		if strings.Contains(rec["endpoint"].(string), "split") {
			assert.Equal(t, "token:ops", rec["identity"])
			seen = append(seen, rec["endpoint"].(string)+" "+rec["result"].(string))
		}
	}
	assert.Equal(t, []string{
		"POST /admin/v1/routes/{route}/split success",
		"POST /admin/v1/routes/{route}/split error",
		"GET /admin/v1/routes/{route}/split success",
	}, seen)
}
