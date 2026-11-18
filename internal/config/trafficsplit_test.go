package config

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// splitRoute is a "/api" route split 90/10 between two single-target
// variants, with extra appended to its traffic_split block (indented to
// match).
func splitRoute(extra string) string {
	return `
rate_limit:
  tiers:
    default: {requests_per_second: 10, burst: 10}
    internal: {requests_per_second: 100, burst: 100}
routes:
  - path_prefix: "/api"
    traffic_split:
      variants:
        - name: stable
          weight: 90
          target: "http://stable:9000"
        - name: canary
          weight: 10
          target: "http://canary:9000"
` + extra
}

func TestTrafficSplit_AbsentByDefault(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes)
	require.NoError(t, err)
	assert.Nil(t, cfg.Routes[0].TrafficSplit)

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "traffic_split", "nothing shows up in a rendered config without it")
}

func TestTrafficSplit_Defaults(t *testing.T) {
	cfg, err := loadYAML(t, splitRoute(`
        - name: dark
          weight: 0
          target: "http://dark:9000"
          auto_rollback: {max_error_rate_increase: 0.05}
`))
	require.NoError(t, err)
	ts := cfg.Routes[0].TrafficSplit
	require.NotNil(t, ts)
	assert.Equal(t, "stable", ts.Baseline, "the first variant")
	assert.Equal(t, StickyClientIP, ts.Sticky.By)
	assert.Equal(t, "gk_variant", ts.Sticky.Cookie.Name)
	assert.Equal(t, 24*time.Hour, ts.Sticky.Cookie.TTL.Duration)
	assert.Equal(t, "/", ts.Sticky.Cookie.Path)
	assert.Equal(t, "X-Gatekeeper-Variant", ts.Override.Header)
	assert.False(t, ts.Override.Enabled)
	assert.Empty(t, ts.ResponseHeader)

	ar := ts.Variants[2].AutoRollback
	require.NotNil(t, ar)
	assert.Equal(t, 5*time.Minute, ar.Window.Duration)
	assert.Equal(t, 100, ar.MinRequests)
	assert.Equal(t, 10*time.Minute, ar.Cooldown.Duration)
}

func TestTrafficSplit_VariantRouteInheritsRouteSettings(t *testing.T) {
	cfg, err := loadYAML(t, `
routes:
  - path_prefix: "/api"
    lb_strategy: least_connections
    health_check: {enabled: true, path: /healthz}
    circuit_breaker: {failure_threshold: 9}
    traffic_split:
      variants:
        - name: stable
          weight: 50
          backends: [{target: "http://s1:9000"}, {target: "http://s2:9000"}]
        - name: canary
          weight: 50
          target: "http://c1:9000"
          lb_strategy: random
          health_check: {enabled: true, path: /ready}
`)
	require.NoError(t, err)
	rt := cfg.Routes[0]

	stable := rt.VariantRoute(0)
	assert.Nil(t, stable.TrafficSplit)
	assert.Len(t, stable.EffectiveBackends(), 2)
	assert.Equal(t, LBLeastConnections, stable.EffectiveLBStrategy(), "inherited")
	assert.Equal(t, "/healthz", stable.HealthCheck.Path, "inherited")
	assert.Equal(t, 9, stable.CircuitBreaker.FailureThreshold)
	assert.Equal(t, "/api", stable.Label())

	canary := rt.VariantRoute(1)
	assert.Equal(t, "http://c1:9000", canary.EffectiveBackends()[0].Target)
	assert.Equal(t, LBRandom, canary.EffectiveLBStrategy(), "its own")
	assert.Equal(t, "/ready", canary.HealthCheck.Path, "its own")
}

func TestTrafficSplit_WeightValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		stable, canary int
		wantErr        string
	}{
		"sums to 100": {90, 10, ""},
		"all on one":  {100, 0, ""},
		"under 100":   {80, 10, "must add up to 100, got 90"},
		"over 100":    {90, 20, "must add up to 100, got 110"},
		"negative":    {90, -10, "weight must be between 0 and 100, got -10"},
		"above 100":   {101, -1, "weight must be between 0 and 100"},
		"all zero":    {0, 0, "must add up to 100, got 0"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, withWeights(splitRoute(""), tc.stable, tc.canary))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Contains(t, err.Error(), "routes[0]")
		})
	}
}

// withWeights replaces splitRoute's 90/10 weights.
func withWeights(y string, stable, canary int) string {
	y = strings.Replace(y, "weight: 90\n", "weight: "+strconv.Itoa(stable)+"\n", 1)
	return strings.Replace(y, "weight: 10\n", "weight: "+strconv.Itoa(canary)+"\n", 1)
}

func TestTrafficSplit_ThreeVariantWeights(t *testing.T) {
	three := withWeights(splitRoute(`
        - name: other
          weight: 34
          target: "http://other:9000"
`), 33, 33)
	_, err := loadYAML(t, three)
	assert.NoError(t, err)

	_, err = loadYAML(t, strings.Replace(three, "weight: 34", "weight: 33", 1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "got 99", "rounding down isn't silently accepted")
}

func TestTrafficSplit_VariantValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml, wantErr string
	}{
		"route target alongside variants": {
			strings.Replace(splitRoute(""), `  - path_prefix: "/api"`, `  - path_prefix: "/api"
    target: "http://other:9000"`, 1),
			"remove the route's target/backends",
		},
		"a single variant": {
			`
routes:
  - path_prefix: "/api"
    traffic_split:
      variants: [{name: only, weight: 100, target: "http://a:1"}]
`, "at least two variants",
		},
		"duplicate names": {
			strings.Replace(splitRoute(""), "name: canary", "name: stable", 1),
			`variant "stable" is listed twice`,
		},
		"bad name": {
			strings.Replace(splitRoute(""), "name: canary", `name: "can ary"`, 1),
			"must be 1-64 letters",
		},
		"variant without backends": {
			strings.Replace(splitRoute(""), `          target: "http://canary:9000"`, "", 1),
			"variants[1] (canary): target is required",
		},
		"variant with both": {
			strings.Replace(splitRoute(""), `          target: "http://canary:9000"`, `          target: "http://canary:9000"
          backends: [{target: "http://canary2:9000"}]`, 1),
			"variants[1] (canary): set either target or backends",
		},
		"bad backend url": {
			strings.Replace(splitRoute(""), `          target: "http://canary:9000"`, `          backends: [{target: "canary:9000"}]`, 1),
			"must be an http:// or https:// URL",
		},
		"shared target": {
			strings.Replace(splitRoute(""), "http://canary:9000", "http://stable:9000", 1),
			`is also used by variant "stable"`,
		},
		"bad lb strategy": {
			strings.Replace(splitRoute(""), `          target: "http://canary:9000"`, `          target: "http://canary:9000"
          lb_strategy: fastest`, 1),
			"lb_strategy must be one of",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, tc.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// splitSettings appends settings (indented under traffic_split) to
// splitRoute.
func splitSettings(settings string) string {
	return splitRoute("") + settings
}

func TestTrafficSplit_FullExampleLoads(t *testing.T) {
	t.Setenv("GK_TEST_COOKIE_SECRET", "0123456789abcdef0123")
	cfg, err := loadYAML(t, splitSettings(`      baseline: stable
      sticky:
        by: cookie
        cookie: {name: gk_canary, ttl: 1h, secret_env: GK_TEST_COOKIE_SECRET, secure: true}
      override:
        enabled: true
        allow: {tiers: [internal], api_keys: [tester-key], cidrs: ["10.0.0.0/8", "2001:db8::/32"]}
      rules:
        - variant: canary
          match: {header: {name: X-Tester, value: "yes"}}
        - variant: canary
          match: {cookie: {name: beta}, path_prefix: /api/beta}
      rollout: {variant: canary, steps: [5, 25, 50, 100], interval: 10m}
      response_header: X-Variant
`))
	require.NoError(t, err)
	ts := cfg.Routes[0].TrafficSplit
	assert.Equal(t, StickyCookie, ts.Sticky.By)
	secret, err := ts.Sticky.Cookie.SigningSecret()
	require.NoError(t, err)
	assert.Equal(t, "0123456789abcdef0123", string(secret))
	assert.Len(t, ts.Rules, 2)
	assert.Equal(t, []int{5, 25, 50, 100}, ts.Rollout.Steps)
	assert.Equal(t, 10*time.Minute, ts.Rollout.Interval.Duration)
	assert.Equal(t, "X-Variant", ts.ResponseHeader)
}

func TestTrafficSplit_SettingsValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		settings, wantErr string
	}{
		"unknown baseline": {
			"      baseline: blue\n", `traffic_split.baseline: no variant is called "blue"`,
		},
		"unknown sticky mode": {
			"      sticky: {by: session}\n", "sticky.by must be one of",
		},
		"bad cookie name": {
			"      sticky: {by: cookie, cookie: {name: \"a b\"}}\n", "is not a valid cookie name",
		},
		"short cookie secret": {
			"      sticky: {by: cookie, cookie: {secret: short}}\n", "at least 16 bytes",
		},
		"two cookie secrets": {
			"      sticky: {by: cookie, cookie: {secret: 0123456789abcdef, secret_env: X}}\n", "set only one of secret and secret_env",
		},
		"missing cookie secret env": {
			"      sticky: {by: cookie, cookie: {secret_env: GK_TEST_UNSET_SECRET}}\n", "GK_TEST_UNSET_SECRET named by secret_env is empty or unset",
		},
		"override for everyone by accident": {
			"      override: {enabled: true}\n", "list the tiers, api_keys, or cidrs that may pick a variant",
		},
		"override for an unknown tier": {
			"      override: {enabled: true, allow: {tiers: [vip]}}\n", `override.allow.tiers[0]: no rate_limit tier is called "vip"`,
		},
		"override with a bad cidr": {
			"      override: {enabled: true, allow: {cidrs: [\"10.0.0.0/8\", \"10.0.0.300\"]}}\n", "override.allow.cidrs[1]",
		},
		"override with a bad header": {
			"      override: {enabled: true, header: \"X Variant\", allow: {anyone: true}}\n", "is not a valid header name",
		},
		"rule for an unknown variant": {
			"      rules: [{variant: blue, match: {path_prefix: /x}}]\n", `rules[0]: no variant is called "blue"`,
		},
		"rule without conditions": {
			"      rules: [{variant: canary, match: {}}]\n", "match needs a header, cookie, or path_prefix",
		},
		"rule with a relative path": {
			"      rules: [{variant: canary, match: {path_prefix: beta}}]\n", "match.path_prefix must start with /",
		},
		"rollout of the baseline": {
			"      rollout: {variant: stable, steps: [50], interval: 1m}\n", "is the baseline",
		},
		"rollout without steps": {
			"      rollout: {variant: canary, interval: 1m}\n", "rollout.steps: list the weights",
		},
		"rollout going down": {
			"      rollout: {variant: canary, steps: [25, 5], interval: 1m}\n", "steps must increase, got 5 after 25",
		},
		"rollout past 100": {
			"      rollout: {variant: canary, steps: [50, 120], interval: 1m}\n", "steps[1]: weight must be between 1 and 100",
		},
		"rollout without interval": {
			"      rollout: {variant: canary, steps: [5, 50]}\n", "rollout.interval must be > 0",
		},
		"bad response header": {
			"      response_header: \"X Variant\"\n", "response_header",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, splitSettings(tc.settings))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestTrafficSplit_OverrideForAnyoneMustBeExplicit(t *testing.T) {
	_, err := loadYAML(t, splitSettings("      override: {enabled: true, allow: {anyone: true}}\n"))
	assert.NoError(t, err)
	_, err = loadYAML(t, splitSettings("      override: {enabled: false}\n"))
	assert.NoError(t, err, "a disabled override needs no allowlist")
}

func TestTrafficSplit_AutoRollbackValidation(t *testing.T) {
	guard := func(settings string) string {
		return strings.Replace(splitRoute(""), `          target: "http://canary:9000"`, `          target: "http://canary:9000"
          auto_rollback: `+settings, 1)
	}
	_, err := loadYAML(t, guard("{max_error_rate_increase: 0.05, max_p95_latency_ratio: 1.5, window: 1m, min_requests: 20, cooldown: 0s}"))
	assert.NoError(t, err)

	for settings, wantErr := range map[string]string{
		"{}":                                           "set max_error_rate_increase, max_p95_latency_ratio, or both",
		"{max_error_rate_increase: 1.5}":               "max_error_rate_increase must be between 0 and 1",
		"{max_error_rate_increase: -0.1}":              "max_error_rate_increase must be between 0 and 1",
		"{max_p95_latency_ratio: 0.9}":                 "max_p95_latency_ratio must be greater than 1",
		"{max_p95_latency_ratio: 1}":                   "max_p95_latency_ratio must be greater than 1",
		"{max_p95_latency_ratio: 2, min_requests: -1}": "min_requests must be >= 1",
		"{max_p95_latency_ratio: 2, window: -1s}":      "window must be > 0",
		"{max_p95_latency_ratio: 2, cooldown: -1s}":    "cooldown must be >= 0",
	} {
		_, err := loadYAML(t, guard(settings))
		require.Error(t, err, settings)
		assert.Contains(t, err.Error(), wantErr, settings)
	}

	_, err = loadYAML(t, strings.Replace(splitRoute(""), `          target: "http://stable:9000"`, `          target: "http://stable:9000"
          auto_rollback: {max_error_rate_increase: 0.05}`, 1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the baseline is what other variants are compared with")
}
