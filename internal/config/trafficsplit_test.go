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
