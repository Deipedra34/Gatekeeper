package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// faultRoute is a "/api" route with a fault_injection block (indented to
// match) and global, the top-level fault_injection section.
func faultRoute(global, block string) string {
	return `
rate_limit:
  tiers:
    default: {requests_per_second: 10, burst: 10}
    internal: {requests_per_second: 100, burst: 100}
fault_injection:
` + global + `
routes:
  - path_prefix: "/api"
    backends:
      - target: "http://a:9000"
      - target: "http://b:9000"
    fault_injection:
` + block
}

func TestFaultInjection_OffByDefault(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes)
	require.NoError(t, err)
	assert.False(t, cfg.FaultInjection.GlobalEnabled, "the kill switch starts off")
	assert.Equal(t, FaultEnvProduction, cfg.FaultInjection.Environment)
	assert.True(t, cfg.FaultInjection.ProductionLike())
	assert.Nil(t, cfg.Routes[0].FaultInjection)

	out, err := yaml.Marshal(cfg.Routes[0])
	require.NoError(t, err)
	assert.NotContains(t, string(out), "fault_injection", "nothing shows up in a rendered route without it")
}

func TestFaultInjection_RouteDefaults(t *testing.T) {
	cfg, err := loadYAML(t, faultRoute("  global_enabled: true", `
      delay: {percentage: 10, fixed: 500ms}
`))
	require.NoError(t, err)
	f := cfg.Routes[0].FaultInjection
	require.NotNil(t, f)
	assert.False(t, f.Enabled, "a rule must be enabled explicitly")
	assert.True(t, f.CountsAsBackendFailure(), "counted as a backend failure by default")
	assert.Zero(t, f.MaxDuration.Duration, "no expiry by default")
	assert.Equal(t, 500*time.Millisecond, f.Delay.Fixed.Duration)
}

func TestFaultInjection_Percentages(t *testing.T) {
	for _, tc := range []struct {
		block string
		ok    bool
	}{
		{"      delay: {percentage: 0, fixed: 1s}", true},
		{"      delay: {percentage: 100, fixed: 1s}", true},
		{"      delay: {percentage: 0.5, fixed: 1s}", true},
		{"      delay: {percentage: -1, fixed: 1s}", false},
		{"      delay: {percentage: 100.1, fixed: 1s}", false},
		{"      abort: {percentage: 5, status: 503}", true},
		{"      abort: {percentage: 101, status: 503}", false},
		{"      abort: {percentage: -0.1, status: 503}", false},
		{"      connection_reset: {percentage: 1}", true},
		{"      connection_reset: {percentage: 150}", false},
		{"      connection_reset: {percentage: .nan}", false},
	} {
		t.Run(tc.block, func(t *testing.T) {
			_, err := loadYAML(t, faultRoute("", tc.block))
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "percentage must be between 0 and 100")
		})
	}
}

func TestFaultInjection_Validation(t *testing.T) {
	for _, tc := range []struct {
		name, block, want string
	}{
		{"no fault", "      enabled: true", "set at least one of delay, abort, connection_reset"},
		{"delay without duration", "      delay: {percentage: 5}", "set fixed (e.g. 500ms) or min and max"},
		{"delay both forms", "      delay: {percentage: 5, fixed: 1s, min: 1s, max: 2s}", "not both"},
		{"delay min over max", "      delay: {percentage: 5, min: 2s, max: 1s}", "must not be greater than max"},
		{"delay only min", "      delay: {percentage: 5, min: 1s}", "min must be >= 0 and max > 0"},
		{"abort status 200", "      abort: {percentage: 5, status: 200}", "400-599"},
		{"abort status 600", "      abort: {percentage: 5, status: 600}", "400-599"},
		{"negative max_duration", "      abort: {percentage: 5, status: 503}\n      max_duration: -1s", "max_duration must be >= 0"},
		{"bad header", "      delay: {percentage: 5, fixed: 1s}\n      match: {header: {name: \"bad header\"}}", "not a valid header name"},
		{"relative path", "      delay: {percentage: 5, fixed: 1s}\n      match: {path_prefixes: [api]}", "must start with /"},
		{"lower-case method", "      delay: {percentage: 5, fixed: 1s}\n      match: {methods: [get]}", "upper-case HTTP method"},
		{"unknown variant", "      delay: {percentage: 5, fixed: 1s}\n      match: {variants: [canary]}", "has no traffic_split"},
		{"unknown backend", "      delay: {percentage: 5, fixed: 1s}\n      match: {backends: [\"http://c:9000\"]}", "not one of the route's backends"},
		{"empty clients", "      delay: {percentage: 5, fixed: 1s}\n      match: {clients: {}}", "list the tiers, api_keys, or cidrs"},
		{"unknown tier", "      delay: {percentage: 5, fixed: 1s}\n      match: {clients: {tiers: [gold]}}", "no rate_limit tier is called \"gold\""},
		{"empty api key", "      delay: {percentage: 5, fixed: 1s}\n      match: {clients: {api_keys: [\"\"]}}", "must not be empty"},
		{"bad cidr", "      delay: {percentage: 5, fixed: 1s}\n      match: {clients: {cidrs: [\"10.0.0.0/99\"]}}", "clients.cidrs[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, faultRoute("", tc.block))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "routes[0].fault_injection")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestFaultInjection_ValidTargeting(t *testing.T) {
	cfg, err := loadYAML(t, faultRoute("", `
      enabled: true
      abort: {percentage: 5, status: 503}
      match:
        header: {name: X-Gatekeeper-Fault, value: "true"}
        path_prefixes: [/api/orders]
        methods: [GET, POST]
        backends: ["http://b:9000"]
        clients: {tiers: [internal], api_keys: [test-key], cidrs: [10.0.0.0/8, 192.168.1.7]}
`))
	require.NoError(t, err)
	m := cfg.Routes[0].FaultInjection.Match
	assert.Equal(t, "X-Gatekeeper-Fault", m.Header.Name)
	assert.Equal(t, []string{"http://b:9000"}, m.Backends)
}

func TestFaultInjection_VariantTargeting(t *testing.T) {
	_, err := loadYAML(t, splitRoute(`
    fault_injection:
      delay: {percentage: 10, fixed: 200ms}
      match: {variants: [canary], backends: ["http://canary:9000"]}
`))
	require.NoError(t, err)

	_, err = loadYAML(t, splitRoute(`
    fault_injection:
      delay: {percentage: 10, fixed: 200ms}
      match: {variants: [blue]}
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no variant is called \"blue\"; the route has stable, canary")
}

func TestFaultInjection_FullAbortGuard(t *testing.T) {
	full := []string{
		"      abort: {percentage: 100, status: 503}",
		"      connection_reset: {percentage: 100}",
	}
	for _, block := range full {
		t.Run(strings.TrimSpace(block), func(t *testing.T) {
			for _, env := range []string{"", "  environment: production", "  environment: staging"} {
				_, err := loadYAML(t, faultRoute(env, block))
				require.Error(t, err, "refused in a production-like environment (%q)", env)
				assert.Contains(t, err.Error(), "allow_full_abort: true")

				_, err = loadYAML(t, faultRoute(env, block+"\n      allow_full_abort: true"))
				assert.NoError(t, err, "allowed when asked for explicitly")
			}
			for _, env := range []string{"  environment: development", "  environment: test"} {
				_, err := loadYAML(t, faultRoute(env, block))
				assert.NoError(t, err, "allowed outside production-like environments (%q)", env)
			}
		})
	}
	_, err := loadYAML(t, faultRoute("", "      abort: {percentage: 99.9, status: 503}"))
	assert.NoError(t, err, "anything short of 100 is fine")
}

func TestFaultInjection_GlobalSection(t *testing.T) {
	_, err := loadYAML(t, faultRoute("  environment: qa", "      delay: {percentage: 5, fixed: 1s}"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fault_injection.environment must be one of")

	_, err = loadYAML(t, faultRoute("  exempt_paths: [status]", "      delay: {percentage: 5, fixed: 1s}"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exempt_paths[0]")

	cfg, err := loadYAML(t, faultRoute("  exempt_paths: [/status, /internal/]", "      delay: {percentage: 5, fixed: 1s}"))
	require.NoError(t, err)
	assert.Equal(t, []string{"/status", "/internal/"}, cfg.FaultInjection.ExemptPaths)
}

func TestFaultInjection_CountAsBackendFailureOptOut(t *testing.T) {
	cfg, err := loadYAML(t, faultRoute("", `
      abort: {percentage: 5, status: 503}
      count_as_backend_failure: false
`))
	require.NoError(t, err)
	assert.False(t, cfg.Routes[0].FaultInjection.CountsAsBackendFailure())
}
