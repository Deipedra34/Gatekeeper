package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// withRootRoute adds a "/" route as routes[0] to extra, which may list
// further routes of its own.
func withRootRoute(extra string) string {
	if !strings.Contains(extra, "routes:") {
		return minimalRoutes + extra
	}
	return strings.Replace(extra, "routes:\n", "routes:\n  - path_prefix: \"/\"\n    target: \"http://localhost:9000\"\n", 1)
}

func TestAccessControl_AbsentByDefault(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes)
	require.NoError(t, err)
	assert.Nil(t, cfg.AccessControl)
	assert.Nil(t, cfg.Routes[0].AccessControl)
	assert.False(t, cfg.AccessControlEnabled())

	// Nothing about access control shows up when the config is rendered
	// (as /admin/v1/config does) without it.
	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "access_control")
}

func TestAccessControl_Defaults(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes+`
access_control: {}
`)
	require.NoError(t, err)
	require.NotNil(t, cfg.AccessControl)
	assert.True(t, cfg.AccessControlEnabled())
	ac := cfg.AccessControl
	assert.Equal(t, AccessModeOff, ac.Mode)
	assert.Equal(t, 403, ac.DenyStatus)
	assert.False(t, ac.AutoBan.Enabled)
	assert.Equal(t, DefaultAutoBanThreshold, ac.AutoBan.Threshold)
	assert.Equal(t, time.Minute, ac.AutoBan.Window.Duration)
	assert.Equal(t, 10*time.Minute, ac.AutoBan.BanDuration.Duration)
	assert.Equal(t, []string{"rate_limit", "auth_failure", "denied"}, ac.AutoBan.Triggers)
	assert.False(t, ac.AutoBan.Escalation.Enabled)
	assert.Equal(t, 2.0, ac.AutoBan.Escalation.Multiplier)
	assert.Equal(t, 24*time.Hour, ac.AutoBan.Escalation.MaxDuration.Duration)
	assert.Equal(t, 24*time.Hour, ac.AutoBan.Escalation.ResetAfter.Duration)
}

func TestAccessControl_FullExampleLoads(t *testing.T) {
	cfg, err := loadYAML(t, `
routes:
  - path_prefix: "/admin"
    target: "http://localhost:9000"
    access_control:
      mode: allowlist_only
      allow: ["10.0.0.0/8", "2001:db8:a::/48"]
      deny_status: 404
  - path_prefix: "/"
    target: "http://localhost:9000"
access_control:
  mode: denylist
  deny: ["198.51.100.0/24", "203.0.113.7", "2001:db8:bad::/48", "::ffff:192.0.2.1"]
  deny_status: 451
  trusted_proxies: ["10.0.0.1", "fd00::/8"]
  auto_ban:
    enabled: true
    threshold: 5
    window: 30s
    ban_duration: 2m
    triggers: [auth_failure]
    never_ban: ["127.0.0.1", "::1"]
    escalation: {enabled: true, multiplier: 3, max_duration: 1h, reset_after: 6h}
`)
	require.NoError(t, err)
	ac := cfg.AccessControl
	assert.Equal(t, AccessModeDenylist, ac.Mode)
	assert.Equal(t, 451, ac.DenyStatus)
	assert.Equal(t, 5, ac.AutoBan.Threshold)
	assert.Equal(t, []string{"auth_failure"}, ac.AutoBan.Triggers)
	assert.Equal(t, 3.0, ac.AutoBan.Escalation.Multiplier)

	admin := cfg.Routes[0].AccessControl
	require.NotNil(t, admin)
	assert.Equal(t, AccessModeAllowlistOnly, admin.Mode)
	assert.Nil(t, cfg.Routes[1].AccessControl)
}

func TestEffectiveAccessControl_RouteOverridesGlobal(t *testing.T) {
	global := AccessControlConfig{Mode: AccessModeDenylist, Allow: []string{"10.0.0.0/8"}, Deny: []string{"198.51.100.0/24"}, DenyStatus: 403}

	assert.Equal(t, RouteAccessControl{Mode: AccessModeDenylist, Allow: global.Allow, Deny: global.Deny, DenyStatus: 403},
		EffectiveAccessControl(global, nil), "no override: the global settings")

	eff := EffectiveAccessControl(global, &RouteAccessControl{Mode: AccessModeAllowlistOnly})
	assert.Equal(t, AccessModeAllowlistOnly, eff.Mode)
	assert.Equal(t, global.Allow, eff.Allow, "unset fields inherit")
	assert.Equal(t, global.Deny, eff.Deny)
	assert.Equal(t, 403, eff.DenyStatus)

	eff = EffectiveAccessControl(global, &RouteAccessControl{Deny: []string{}, Allow: []string{"192.168.0.0/16"}, DenyStatus: 404})
	assert.Equal(t, AccessModeDenylist, eff.Mode)
	assert.Empty(t, eff.Deny, "an explicit empty list replaces the global one")
	assert.Equal(t, []string{"192.168.0.0/16"}, eff.Allow)
	assert.Equal(t, 404, eff.DenyStatus)

	eff = EffectiveAccessControl(AccessControlConfig{}, &RouteAccessControl{Mode: AccessModeDenylist, Deny: []string{"10.0.0.1"}})
	assert.Equal(t, 403, eff.DenyStatus, "defaults apply without a global section")
}

func TestAccessControl_RouteOnlyEnablesIt(t *testing.T) {
	cfg, err := loadYAML(t, `
routes:
  - path_prefix: "/"
    target: "http://localhost:9000"
    access_control: {mode: denylist, deny: ["198.51.100.1"]}
`)
	require.NoError(t, err)
	assert.Nil(t, cfg.AccessControl)
	assert.True(t, cfg.AccessControlEnabled())
}

func TestAccessControl_InvalidEntriesRejectedAtLoad(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"bad deny entry": {`
access_control: {mode: denylist, deny: ["10.0.0.0/8", "10.0.0.300"]}`,
			`access_control.deny[1]: "10.0.0.300" is not a valid IP address or CIDR range`},
		"bad allow CIDR": {`
access_control: {mode: allowlist_only, allow: ["10.0.0.0/33"]}`,
			`access_control.allow[0]: "10.0.0.0/33" is not a valid CIDR range`},
		"bad IPv6 entry": {`
access_control: {mode: denylist, deny: ["2001:db8:::1"]}`,
			`access_control.deny[0]`},
		"empty entry": {`
access_control: {mode: denylist, deny: [""]}`,
			`access_control.deny[0]: empty entry`},
		"hostname": {`
access_control: {mode: denylist, deny: ["evil.example.com"]}`,
			`access_control.deny[0]`},
		"zone": {`
access_control: {mode: denylist, deny: ["fe80::1%eth0"]}`,
			`zones are not allowed`},
		"bad trusted proxy": {`
access_control: {trusted_proxies: ["lb.internal"]}`,
			`access_control.trusted_proxies[0]`},
		"bad never_ban": {`
access_control: {auto_ban: {never_ban: ["127.0.0.1/40"]}}`,
			`access_control.auto_ban.never_ban[0]`},
		"bad route entry": {`
access_control: {mode: denylist}
routes:
  - path_prefix: "/x"
    target: "http://localhost:9000"
    access_control: {deny: ["300.1.1.1"]}`,
			`routes[1].access_control.deny[0]`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, withRootRoute(c.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

func TestAccessControl_InvalidSettingsRejected(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"unknown mode": {`
access_control: {mode: strict}`, `access_control.mode must be one of off, denylist, allowlist_only`},
		"deny status not an error": {`
access_control: {mode: denylist, deny_status: 200}`, `access_control.deny_status must be an HTTP error status`},
		"lists with mode off": {`
access_control: {deny: ["10.0.0.1"]}`, `mode is off`},
		"empty allowlist": {`
access_control: {mode: allowlist_only}`, `empty allow list would reject every request`},
		"route unknown mode": {`
routes:
  - path_prefix: "/x"
    target: "http://localhost:9000"
    access_control: {mode: whitelist}`, `routes[1].access_control.mode`},
		"route lists with effective mode off": {`
routes:
  - path_prefix: "/x"
    target: "http://localhost:9000"
    access_control: {allow: ["10.0.0.1"]}`, `routes[1].access_control: allow or deny entries are set but the effective mode is off`},
		"route empty allowlist": {`
access_control: {mode: allowlist_only, allow: ["10.0.0.0/8"]}
routes:
  - path_prefix: "/x"
    target: "http://localhost:9000"
    access_control: {allow: []}`, `routes[1].access_control: mode allowlist_only with an empty allow list`},
		"route bad deny status": {`
routes:
  - path_prefix: "/x"
    target: "http://localhost:9000"
    access_control: {deny_status: 99}`, `routes[1].access_control.deny_status`},
		"threshold": {`
access_control: {auto_ban: {enabled: true, threshold: -1}}`, `auto_ban.threshold must be >= 1`},
		"window": {`
access_control: {auto_ban: {enabled: true, window: -1s}}`, `auto_ban.window must be > 0`},
		"ban duration": {`
access_control: {auto_ban: {enabled: true, ban_duration: -5m}}`, `auto_ban.ban_duration must be > 0`},
		"unknown trigger": {`
access_control: {auto_ban: {enabled: true, triggers: [rate_limit, 404]}}`, `auto_ban.triggers[1]`},
		"no triggers": {`
access_control: {auto_ban: {enabled: true, triggers: []}}`, `auto_ban.triggers must list at least one`},
		"multiplier": {`
access_control: {auto_ban: {escalation: {enabled: true, multiplier: 0.5}}}`, `escalation.multiplier must be >= 1`},
		"max below base": {`
access_control: {auto_ban: {ban_duration: 1h, escalation: {max_duration: 30m}}}`, `escalation.max_duration must be >=`},
		"reset after": {`
access_control: {auto_ban: {escalation: {reset_after: -1h}}}`, `escalation.reset_after must be > 0`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, withRootRoute(c.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

func TestAccessControl_RouteCanTurnGlobalListsOff(t *testing.T) {
	cfg, err := loadYAML(t, `
access_control: {mode: denylist, deny: ["198.51.100.0/24"]}
routes:
  - path_prefix: "/health"
    target: "http://localhost:9000"
    access_control: {mode: "off"}
  - path_prefix: "/"
    target: "http://localhost:9000"
`)
	require.NoError(t, err)
	eff := EffectiveAccessControl(*cfg.AccessControl, cfg.Routes[0].AccessControl)
	assert.Equal(t, AccessModeOff, eff.Mode)
}

func TestAccessControl_MaxDurationDefaultsToAtLeastBanDuration(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes+`
access_control: {auto_ban: {enabled: true, ban_duration: 48h}}
`)
	require.NoError(t, err)
	assert.Equal(t, 48*time.Hour, cfg.AccessControl.AutoBan.Escalation.MaxDuration.Duration)
}
