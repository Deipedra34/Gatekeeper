package config

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// validationRoute is a "/api" route with a validation block, indented to
// match.
func validationRoute(block string) string {
	return `
routes:
  - path_prefix: "/api"
    target: "http://localhost:9000"
    validation:
` + block
}

func TestValidation_LeftOutByDefault(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes)
	require.NoError(t, err)
	assert.Nil(t, cfg.Routes[0].Validation, "a route without the section has none")

	out, err := yaml.Marshal(cfg.Routes[0])
	require.NoError(t, err)
	assert.NotContains(t, string(out), "validation", "nothing shows up in a rendered route without it")
}

func TestValidation_Defaults(t *testing.T) {
	cfg, err := loadYAML(t, validationRoute(`
      enabled: true
      openapi_file: api.yaml
`))
	require.NoError(t, err)
	v := cfg.Routes[0].Validation
	require.NotNil(t, v)
	assert.True(t, v.Enabled)
	assert.Equal(t, ValidationModeEnforce, v.Mode, "enforce by default")
	assert.False(t, v.ReportOnly())
	assert.Equal(t, http.StatusBadRequest, v.RejectStatus)
	assert.EqualValues(t, 1<<20, v.MaxBodyBytes, "1 MiB")
	assert.Equal(t, 32, v.MaxJSONDepth)
	assert.Equal(t, 100*time.Millisecond, v.Timeout.Duration)
	assert.False(t, v.RejectUnknownOperations)
	assert.False(t, v.ValidateContentType)
	assert.False(t, v.ValidateNonJSONBodies)
}

func TestValidation_AllSettings(t *testing.T) {
	cfg, err := loadYAML(t, validationRoute(`
      enabled: true
      openapi_file: specs/api.json
      mode: report_only
      reject_status: 422
      reject_unknown_operations: true
      validate_content_type: true
      validate_non_json_bodies: true
      max_body_bytes: 2048
      max_json_depth: 8
      timeout: 250ms
`))
	require.NoError(t, err)
	v := cfg.Routes[0].Validation
	assert.Equal(t, "specs/api.json", v.OpenAPIFile)
	assert.True(t, v.ReportOnly())
	assert.Equal(t, http.StatusUnprocessableEntity, v.RejectStatus)
	assert.True(t, v.RejectUnknownOperations)
	assert.True(t, v.ValidateContentType)
	assert.True(t, v.ValidateNonJSONBodies)
	assert.EqualValues(t, 2048, v.MaxBodyBytes)
	assert.Equal(t, 8, v.MaxJSONDepth)
	assert.Equal(t, 250*time.Millisecond, v.Timeout.Duration)
}

func TestValidation_DisabledNeedsNoSpec(t *testing.T) {
	cfg, err := loadYAML(t, validationRoute(`
      enabled: false
`))
	require.NoError(t, err, "a disabled section may leave openapi_file out")
	assert.False(t, cfg.Routes[0].Validation.Enabled)
}

func TestValidation_RejectsBadSettings(t *testing.T) {
	for _, tc := range []struct {
		name, block, want string
	}{
		{"no spec", "      enabled: true\n", "routes[0].validation.openapi_file is required"},
		{"mode", "      enabled: true\n      openapi_file: a.yaml\n      mode: strict\n", "mode must be enforce or report_only"},
		{"status", "      enabled: true\n      openapi_file: a.yaml\n      reject_status: 403\n", "reject_status must be 400 or 422"},
		{"negative body", "      enabled: true\n      openapi_file: a.yaml\n      max_body_bytes: -1\n", "max_body_bytes must be between 1 and"},
		{"huge body", "      enabled: true\n      openapi_file: a.yaml\n      max_body_bytes: 1099511627776\n", "max_body_bytes must be between 1 and"},
		{"depth", "      enabled: true\n      openapi_file: a.yaml\n      max_json_depth: 100000\n", "max_json_depth must be between 1 and"},
		{"timeout", "      enabled: true\n      openapi_file: a.yaml\n      timeout: 1m\n", "timeout must be above 0 and at most 10s"},
		{"negative timeout", "      enabled: true\n      openapi_file: a.yaml\n      timeout: -1s\n", "timeout must be above 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, validationRoute(tc.block))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidation_WithDefaultsForRoutesBuiltInCode(t *testing.T) {
	v := RouteValidation{Enabled: true, OpenAPIFile: "a.yaml"}.WithDefaults()
	assert.Equal(t, ValidationModeEnforce, v.EffectiveMode())
	assert.Equal(t, DefaultValidationRejectStatus, v.RejectStatus)
	assert.EqualValues(t, DefaultValidationMaxBodyBytes, v.MaxBodyBytes)
	assert.Equal(t, DefaultValidationMaxJSONDepth, v.MaxJSONDepth)
	assert.Equal(t, DefaultValidationTimeout, v.Timeout.Duration)

	set := RouteValidation{Mode: ValidationModeReportOnly, MaxBodyBytes: 10}.WithDefaults()
	assert.True(t, set.ReportOnly(), "settings already made are kept")
	assert.EqualValues(t, 10, set.MaxBodyBytes)
}
