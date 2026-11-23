package admin_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// faultAdminYAML is simpleYAML plus an "/api" route with fault injection
// settings faults (indented under the route's fault_injection, left out
// when empty), and global settings global (indented under the top-level
// fault_injection).
func faultAdminYAML(target, global, faults string) string {
	section := ""
	if faults != "" {
		section = "    fault_injection:\n" + faults + "\n"
	}
	return simpleYAML(target) + fmt.Sprintf(`  - path_prefix: "/api"
    target: %q
%s
fault_injection:
%s
`, target, section, global)
}

const faultsOn = "  global_enabled: true"

// fresh returns a path under /api no earlier request used, so a cached
// response never stands in for one that would be faulted.
func fresh(t *testing.T) string {
	t.Helper()
	freshN++
	return fmt.Sprintf("/api/%s-%d", t.Name(), freshN)
}

var freshN int

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

	faults := h.call(http.MethodGet, "/admin/v1/faults", adminToken, "")
	require.Equal(t, http.StatusOK, faults.status, faults.raw)
	for _, secret := range []string{"chaos-token-0123456789", "chaos-key-0123456789"} {
		assert.NotContains(t, faults.raw, secret, "nor in the faults listing")
	}
}

func TestAdminFaults_RequireAuthentication(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn, ""), harnessOptions{})
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/admin/v1/faults", ""},
		{http.MethodPost, "/admin/v1/faults", `{"route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 503}}`},
		{http.MethodDelete, "/admin/v1/faults/x", ""},
	} {
		r := h.call(c.method, c.path, "", c.body)
		assert.Equal(t, http.StatusUnauthorized, r.status, "%s %s", c.method, c.path)
	}
	assert.Empty(t, h.gw.Faults().Rules(), "nothing was created")
}

func TestAdminFaults_ListShowsConfigRulesAndRemainingTime(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn, `      enabled: true
      max_duration: 1h
      delay: {percentage: 10, fixed: 500ms}`), harnessOptions{})

	r := h.call(http.MethodGet, "/admin/v1/faults", adminToken, "")
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["global_enabled"])
	assert.Equal(t, true, r.json["active"])
	assert.Equal(t, "production", r.json["environment"])
	rules := r.json["rules"].([]any)
	require.Len(t, rules, 1)
	rule := rules[0].(map[string]any)
	assert.Equal(t, "/api", rule["route"])
	assert.Equal(t, "config", rule["source"])
	assert.True(t, strings.HasPrefix(rule["id"].(string), "config-"))
	assert.Equal(t, true, rule["in_force"])
	assert.Equal(t, "delay 10% 500ms; every request", rule["summary"])
	assert.InDelta(t, 3600, rule["remaining_seconds"].(float64), 5)
	assert.NotNil(t, rule["expires_at"])
}

func TestAdminFaults_CreateInjectAndDelete(t *testing.T) {
	backend, hits := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn, ""), harnessOptions{})
	header := http.Header{"X-Gatekeeper-Fault": {"true"}}

	r := h.call(http.MethodPost, "/admin/v1/faults", adminToken, `{
		"id": "chaos-1", "route": "api", "ttl": "10m",
		"abort": {"percentage": 100, "status": 503},
		"allow_full_abort": true,
		"count_as_backend_failure": false,
		"match": {"header": {"name": "X-Gatekeeper-Fault", "value": "true"}}
	}`)
	require.Equal(t, http.StatusCreated, r.status, r.raw)
	assert.Equal(t, false, r.json["replaced"])
	rule := r.json["rule"].(map[string]any)
	assert.Equal(t, "chaos-1", rule["id"])
	assert.Equal(t, "runtime", rule["source"])
	assert.InDelta(t, 600, rule["remaining_seconds"].(float64), 5)

	before := hits.Load()
	resp := h.get(fresh(t), header)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "the header triggers the abort")
	assert.Equal(t, "abort", resp.Header.Get("X-Gatekeeper-Fault"))
	assert.Equal(t, before, hits.Load(), "an aborted request never reaches the backend")
	assert.Equal(t, http.StatusOK, h.get(fresh(t), nil).StatusCode, "requests without the header go through")
	assert.Equal(t, http.StatusOK, h.get("/other", header).StatusCode, "other routes are untouched")

	list := h.call(http.MethodGet, "/admin/v1/faults", adminToken, "")
	require.Len(t, list.json["rules"].([]any), 1)

	// Replaced by ID.
	r = h.call(http.MethodPost, "/admin/v1/faults", adminToken, `{"id": "chaos-1", "route": "api", "ttl": "5m", "abort": {"percentage": 100, "status": 500}, "allow_full_abort": true, "count_as_backend_failure": false}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["replaced"])
	assert.Equal(t, http.StatusInternalServerError, h.get(fresh(t), nil).StatusCode)

	del := h.call(http.MethodDelete, "/admin/v1/faults/chaos-1", adminToken, "")
	require.Equal(t, http.StatusOK, del.status, del.raw)
	assert.Equal(t, http.StatusOK, h.get(fresh(t), header).StatusCode, "gone once deleted")
	assert.Equal(t, http.StatusNotFound, h.call(http.MethodDelete, "/admin/v1/faults/chaos-1", adminToken, "").status)

	var targets []string
	for _, rec := range h.auditRecords() {
		if tgt, ok := rec["target"].(string); ok {
			targets = append(targets, rec["method"].(string)+" "+tgt)
		}
	}
	assert.Contains(t, targets, "POST fault rule chaos-1 on route /api", "changes are audited with the rule and route")
	assert.Contains(t, targets, "DELETE fault rule chaos-1 on route /api")
}

func TestAdminFaults_DryRunChangesNothing(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn, ""), harnessOptions{})
	r := h.call(http.MethodPost, "/admin/v1/faults?dry_run=true", adminToken, `{"route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 503}}`)
	require.Equal(t, http.StatusOK, r.status, r.raw)
	assert.Equal(t, true, r.json["dry_run"])
	assert.Empty(t, h.gw.Faults().Rules())
}

func TestAdminFaults_Validation(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn, ""), harnessOptions{})
	for name, c := range map[string]struct {
		body   string
		status int
		msg    string
	}{
		"no route":       {`{"ttl": "1m", "abort": {"percentage": 5, "status": 503}}`, 400, "route"},
		"unknown route":  {`{"route": "nope", "ttl": "1m", "abort": {"percentage": 5, "status": 503}}`, 404, "no route"},
		"no ttl":         {`{"route": "api", "abort": {"percentage": 5, "status": 503}}`, 400, "ttl"},
		"ttl too long":   {`{"route": "api", "ttl": "25h", "abort": {"percentage": 5, "status": 503}}`, 400, "24h"},
		"bad ttl":        {`{"route": "api", "ttl": "soon", "abort": {"percentage": 5, "status": 503}}`, 400, "ttl"},
		"no fault":       {`{"route": "api", "ttl": "1m"}`, 400, "at least one"},
		"bad percentage": {`{"route": "api", "ttl": "1m", "abort": {"percentage": 101, "status": 503}}`, 400, "percentage"},
		"bad status":     {`{"route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 200}}`, 400, "status"},
		"bad delay":      {`{"route": "api", "ttl": "1m", "delay": {"percentage": 5, "fixed": "slow"}}`, 400, "delay.fixed"},
		"bad id":         {`{"id": "a b", "route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 503}}`, 400, "id"},
		"config id":      {`{"id": "config-x", "route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 503}}`, 400, "config"},
		"unknown field":  {`{"route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 503}, "oops": 1}`, 400, "oops"},
		"full abort":     {`{"route": "api", "ttl": "1m", "abort": {"percentage": 100, "status": 503}}`, 400, "allow_full_abort"},
		"full reset":     {`{"route": "api", "ttl": "1m", "connection_reset": {"percentage": 100}}`, 400, "allow_full_abort"},
	} {
		t.Run(name, func(t *testing.T) {
			r := h.call(http.MethodPost, "/admin/v1/faults", adminToken, c.body)
			assert.Equal(t, c.status, r.status, r.raw)
			assert.Contains(t, r.raw, c.msg)
		})
	}
	assert.Empty(t, h.gw.Faults().Rules(), "nothing invalid was stored")
}

func TestAdminFaults_FullAbortAllowedOutsideProduction(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn+"\n  environment: test", ""), harnessOptions{})
	r := h.call(http.MethodPost, "/admin/v1/faults", adminToken, `{"route": "api", "ttl": "1m", "abort": {"percentage": 100, "status": 503}}`)
	assert.Equal(t, http.StatusCreated, r.status, r.raw)
}

func TestAdminFaults_KillSwitchOffWarns(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, "  global_enabled: false", ""), harnessOptions{})
	r := h.call(http.MethodPost, "/admin/v1/faults", adminToken, `{"route": "api", "ttl": "1m", "abort": {"percentage": 50, "status": 503}}`)
	require.Equal(t, http.StatusCreated, r.status, r.raw)
	assert.Contains(t, r.json["warning"], "global_enabled is false")
	assert.Equal(t, false, r.json["rule"].(map[string]any)["in_force"])
	for i := 0; i < 20; i++ {
		require.Equal(t, http.StatusOK, h.get(fresh(t), nil).StatusCode, "the kill switch keeps it from injecting")
	}
}

func TestAdminFaults_DeleteConfigRuleUntilReload(t *testing.T) {
	backend, _ := namedBackend(t, "b")
	h := start(t, faultAdminYAML(backend.URL, faultsOn+"\n  environment: test", `      enabled: true
      abort: {percentage: 100, status: 503}
      count_as_backend_failure: false`), harnessOptions{})
	require.Equal(t, http.StatusServiceUnavailable, h.get(fresh(t), nil).StatusCode)

	list := h.call(http.MethodGet, "/admin/v1/faults", adminToken, "")
	id := list.json["rules"].([]any)[0].(map[string]any)["id"].(string)

	r := h.call(http.MethodPost, "/admin/v1/faults", adminToken, `{"id": "`+id+`", "route": "api", "ttl": "1m", "abort": {"percentage": 5, "status": 503}}`)
	assert.Equal(t, http.StatusBadRequest, r.status, "a config rule's ID can't be taken over")

	del := h.call(http.MethodDelete, "/admin/v1/faults/"+id, adminToken, "")
	require.Equal(t, http.StatusOK, del.status, del.raw)
	assert.Contains(t, del.json["note"], "next reload")
	assert.Equal(t, http.StatusOK, h.get(fresh(t), nil).StatusCode)

	require.NoError(t, h.gw.Reload())
	assert.Equal(t, http.StatusServiceUnavailable, h.get(fresh(t), nil).StatusCode, "the config file brings it back")
}
