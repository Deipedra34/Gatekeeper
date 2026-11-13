package admin_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accessYAML is simpleYAML plus an "/internal" route, and the given
// top-level access_control block. The public test server's clients —
// and the admin API's — connect from 127.0.0.1.
func accessYAML(target, accessControl string) string {
	return strings.Replace(simpleYAML(target), "routes:\n", `routes:
  - path_prefix: "/internal"
    target: "`+target+`"
    access_control: {mode: allowlist_only, allow: ["10.0.0.0/8"], deny_status: 404}
`, 1) + accessControl
}

func TestAdminAccessControl_NotConfigured(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, simpleYAML(backend.URL), harnessOptions{})

	r := h.call(http.MethodGet, "/admin/v1/access-control", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, false, r.json["enabled"])
	assert.Equal(t, []any{}, r.json["bans"])

	ban := h.call(http.MethodPost, "/admin/v1/bans", adminToken, `{"ip": "203.0.113.7"}`)
	assert.Equal(t, http.StatusConflict, ban.status)
	assert.Contains(t, ban.raw, "access control is not configured")
	unban := h.call(http.MethodDelete, "/admin/v1/bans/203.0.113.7", adminToken, "")
	assert.Equal(t, http.StatusConflict, unban.status)
}

func TestAdminAccessControl_ListsSettingsAndBans(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, accessYAML(backend.URL, `
access_control:
  mode: denylist
  deny: ["198.51.100.0/24", "2001:db8:bad::/48"]
  trusted_proxies: ["192.0.2.10"]
  auto_ban:
    enabled: true
    threshold: 7
    never_ban: ["::1"]
    escalation: {enabled: true}
`), harnessOptions{})

	r := h.call(http.MethodGet, "/admin/v1/access-control", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["enabled"])
	global := r.json["global"].(map[string]any)
	assert.Equal(t, "denylist", global["mode"])
	assert.Equal(t, []any{"198.51.100.0/24", "2001:db8:bad::/48"}, global["deny"])
	assert.Equal(t, []any{}, global["allow"])
	assert.EqualValues(t, 403, global["deny_status"])

	routes := r.json["routes"].([]any)
	require.Len(t, routes, 1)
	internal := routes[0].(map[string]any)
	assert.Equal(t, "/internal", internal["route"])
	assert.Equal(t, "allowlist_only", internal["mode"])
	assert.Equal(t, []any{"10.0.0.0/8"}, internal["allow"])
	assert.Equal(t, []any{"198.51.100.0/24", "2001:db8:bad::/48"}, internal["deny"], "inherited from global")
	assert.EqualValues(t, 404, internal["deny_status"])

	assert.Equal(t, []any{"192.0.2.10"}, r.json["trusted_proxies"])
	ab := r.json["auto_ban"].(map[string]any)
	assert.Equal(t, true, ab["enabled"])
	assert.EqualValues(t, 7, ab["threshold"])
	assert.Equal(t, "1m0s", ab["window"])
	assert.Equal(t, []any{"::1"}, ab["never_ban"])
	assert.Equal(t, true, ab["escalation"].(map[string]any)["enabled"])
	assert.Equal(t, []any{}, r.json["bans"])
	assert.EqualValues(t, 0, r.json["active_bans"])
}

func TestAdminAccessControl_BanAndUnban(t *testing.T) {
	backend, hits := namedBackend(t, "b")
	h := start(t, accessYAML(backend.URL, "\naccess_control: {}\n"), harnessOptions{})

	require.Equal(t, http.StatusOK, h.get("/", nil).StatusCode)

	r := h.call(http.MethodPost, "/admin/v1/bans", adminToken, `{"ip": "127.0.0.1", "duration": "30m", "reason": "load test gone wrong"}`)
	require.Equal(t, http.StatusCreated, r.status, r.raw)
	assert.Equal(t, "ban", r.json["action"])
	ban := r.json["ban"].(map[string]any)
	assert.Equal(t, "127.0.0.1", ban["ip"])
	assert.Equal(t, "manual", ban["source"])
	assert.Equal(t, "load test gone wrong", ban["reason"])
	expires, err := time.Parse(time.RFC3339Nano, ban["expires_at"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), expires, 5*time.Second)
	assert.Equal(t, 1.0, testutil.ToFloat64(h.metrics.BansIssued.WithLabelValues("manual")))

	// The public listener now refuses this address...
	resp := h.get("/", nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
	assert.EqualValues(t, 1, hits.Load())

	// ...but the admin listener, on the same address, is unaffected.
	list := h.call(http.MethodGet, "/admin/v1/access-control", adminToken, "")
	require.Equal(t, http.StatusOK, list.status)
	bans := list.json["bans"].([]any)
	require.Len(t, bans, 1)
	assert.Equal(t, "127.0.0.1", bans[0].(map[string]any)["ip"])
	assert.EqualValues(t, 1, list.json["active_bans"])

	r = h.call(http.MethodDelete, "/admin/v1/bans/127.0.0.1", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, "unban", r.json["action"])
	assert.Equal(t, http.StatusOK, h.get("/", nil).StatusCode)

	r = h.call(http.MethodDelete, "/admin/v1/bans/127.0.0.1", adminToken, "")
	assert.Equal(t, http.StatusNotFound, r.status)
	assert.Equal(t, "not_found", r.errorCode())

	// Every call is in the audit log, attributed to the token.
	var endpoints []string
	for _, rec := range h.auditRecords() {
		if strings.Contains(rec["endpoint"].(string), "bans") {
			assert.Equal(t, "token:ops", rec["identity"])
			endpoints = append(endpoints, rec["endpoint"].(string)+" "+rec["result"].(string))
		}
	}
	assert.Equal(t, []string{
		"POST /admin/v1/bans success",
		"DELETE /admin/v1/bans/{ip} success",
		"DELETE /admin/v1/bans/{ip} error",
	}, endpoints)
	for _, rec := range h.auditRecords() {
		assert.NotContains(t, rec, "reason_text", "bodies are never logged")
	}
}

func TestAdminAccessControl_IPv6AndDefaults(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, accessYAML(backend.URL, `
access_control: {auto_ban: {enabled: true, ban_duration: 2h}}
`), harnessOptions{})

	r := h.call(http.MethodPost, "/admin/v1/bans", adminToken, `{"ip": "2001:DB8::7"}`)
	require.Equal(t, http.StatusCreated, r.status, r.raw)
	ban := r.json["ban"].(map[string]any)
	assert.Equal(t, "2001:db8::7", ban["ip"], "normalised")
	expires, _ := time.Parse(time.RFC3339Nano, ban["expires_at"].(string))
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), expires, 5*time.Second, "with auto-ban on, its ban_duration is the default")

	r = h.call(http.MethodDelete, "/admin/v1/bans/2001:db8::7", adminToken, "")
	assert.Equal(t, http.StatusOK, r.status, r.raw)
}

func TestAdminAccessControl_DryRun(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, accessYAML(backend.URL, "\naccess_control: {}\n"), harnessOptions{})

	r := h.call(http.MethodPost, "/admin/v1/bans?dry_run=true", adminToken, `{"ip": "127.0.0.1"}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["dry_run"])
	assert.Equal(t, http.StatusOK, h.get("/", nil).StatusCode, "nothing was banned")

	require.Equal(t, http.StatusCreated, h.call(http.MethodPost, "/admin/v1/bans", adminToken, `{"ip": "127.0.0.1"}`).status)
	r = h.call(http.MethodDelete, "/admin/v1/bans/127.0.0.1?dry_run=true", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["dry_run"])
	assert.Equal(t, http.StatusForbidden, h.get("/", nil).StatusCode, "still banned")
}

func TestAdminAccessControl_RejectsBadRequests(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, accessYAML(backend.URL, `
access_control:
  trusted_proxies: ["192.0.2.10"]
  auto_ban: {never_ban: ["127.0.0.0/8"]}
`), harnessOptions{})

	for body, want := range map[string]int{
		`{}`:                                       http.StatusBadRequest,
		`{"ip": "10.0.0.0/8"}`:                     http.StatusBadRequest,
		`{"ip": "not-an-ip"}`:                      http.StatusBadRequest,
		`{"ip": "fe80::1%eth0"}`:                   http.StatusBadRequest,
		`{"ip": "203.0.113.7", "duration": "x"}`:   http.StatusBadRequest,
		`{"ip": "203.0.113.7", "duration": "-1h"}`: http.StatusBadRequest,
		`{"ip": "203.0.113.7", "until": "never"}`:  http.StatusBadRequest, // unknown field
		`{"ip": "127.0.0.1"}`:                      http.StatusConflict,   // never_ban
		`{"ip": "192.0.2.10"}`:                     http.StatusConflict,   // trusted proxy
	} {
		r := h.call(http.MethodPost, "/admin/v1/bans", adminToken, body)
		assert.Equal(t, want, r.status, "%s: %s", body, r.raw)
	}
	assert.Equal(t, http.StatusBadRequest, h.call(http.MethodDelete, "/admin/v1/bans/nope", adminToken, "").status)

	// Unauthenticated callers get nowhere.
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/admin/v1/access-control", "", "").status)
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodPost, "/admin/v1/bans", "", `{"ip": "203.0.113.7"}`).status)
	assert.Equal(t, http.StatusUnauthorized, h.call(http.MethodDelete, "/admin/v1/bans/203.0.113.7", "wrong", "").status)

	// The wrong method on a ban path says which methods it takes.
	r := h.call(http.MethodGet, "/admin/v1/bans/203.0.113.7", adminToken, "")
	assert.Equal(t, http.StatusMethodNotAllowed, r.status)
	assert.Equal(t, "DELETE", r.header.Get("Allow"))
}
