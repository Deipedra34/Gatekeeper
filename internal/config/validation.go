package config

import (
	"fmt"
	"net/http"
	"time"
)

// Request validation modes, for RouteValidation.Mode.
const (
	// ValidationModeEnforce rejects a request that doesn't match the
	// route's OpenAPI spec; it never reaches the backend.
	ValidationModeEnforce = "enforce"
	// ValidationModeReportOnly logs and counts a request that doesn't
	// match, then forwards it anyway.
	ValidationModeReportOnly = "report_only"
)

// Request validation defaults, applied to a route's validation section
// when the setting is left out.
const (
	DefaultValidationMaxBodyBytes = 1 << 20 // 1 MiB
	DefaultValidationMaxJSONDepth = 32
	DefaultValidationTimeout      = 100 * time.Millisecond
	DefaultValidationRejectStatus = http.StatusBadRequest
)

// Upper bounds on the validation settings, so a typo can't switch the
// safety limits off.
const (
	maxValidationBodyBytes = 64 << 20 // 64 MiB
	maxValidationJSONDepth = 1000
	maxValidationTimeout   = 10 * time.Second
)

// RouteValidation checks a route's requests against an OpenAPI 3.x spec
// before they're forwarded. A route without this section, or with
// enabled: false, is proxied exactly as before and pays nothing for it.
type RouteValidation struct {
	// Enabled turns validation on. Defaults to false.
	Enabled bool `yaml:"enabled"`

	// OpenAPIFile is the path of the OpenAPI 3.x spec, YAML or JSON. It's
	// loaded and checked at startup and on every reload; a missing or
	// invalid spec fails the load.
	OpenAPIFile string `yaml:"openapi_file"`

	// Mode is enforce (the default: reject invalid requests) or
	// report_only (log and count them, then forward them anyway).
	Mode string `yaml:"mode,omitempty"`

	// RejectStatus is the status enforce mode answers an invalid request
	// with: 400 (the default) or 422.
	RejectStatus int `yaml:"reject_status,omitempty"`

	// RejectUnknownOperations treats a request matching no operation in
	// the spec (an unknown path, or a method the path doesn't have) as
	// invalid. Defaults to false: such requests are forwarded unchecked.
	RejectUnknownOperations bool `yaml:"reject_unknown_operations,omitempty"`

	// ValidateContentType treats a body whose Content-Type the operation
	// doesn't declare (or a body without one) as invalid. Defaults to
	// false: such a body is forwarded without checking it.
	ValidateContentType bool `yaml:"validate_content_type,omitempty"`

	// ValidateNonJSONBodies also checks bodies that aren't JSON (form
	// data, plain text, ...) against the operation's schema, where
	// kin-openapi can decode them. Defaults to false: only JSON bodies
	// are checked, others are forwarded unread.
	ValidateNonJSONBodies bool `yaml:"validate_non_json_bodies,omitempty"`

	// MaxBodyBytes is the largest body validation reads. A larger one is
	// invalid (413 in enforce mode). Defaults to 1 MiB.
	MaxBodyBytes int64 `yaml:"max_body_bytes,omitempty"`

	// MaxJSONDepth is how deeply a JSON body's objects and arrays may
	// nest. A deeper one is invalid without being decoded. Defaults to 32.
	MaxJSONDepth int `yaml:"max_json_depth,omitempty"`

	// Timeout bounds how long checking one request may take, once its
	// body has been read. A request that takes longer is invalid.
	// Defaults to 100ms.
	Timeout Duration `yaml:"timeout,omitempty"`
}

// EffectiveMode returns the mode, applying the "enforce by default" rule
// for a route built without going through Load/applyDefaults.
func (v *RouteValidation) EffectiveMode() string {
	if v.Mode == "" {
		return ValidationModeEnforce
	}
	return v.Mode
}

// ReportOnly reports whether invalid requests are forwarded anyway.
func (v *RouteValidation) ReportOnly() bool {
	return v.EffectiveMode() == ValidationModeReportOnly
}

// WithDefaults returns v with every unset limit given its default, for a
// route built without going through Load/applyDefaults.
func (v RouteValidation) WithDefaults() RouteValidation {
	v.applyDefaults()
	return v
}

func (v *RouteValidation) applyDefaults() {
	if v.Mode == "" {
		v.Mode = ValidationModeEnforce
	}
	if v.RejectStatus == 0 {
		v.RejectStatus = DefaultValidationRejectStatus
	}
	if v.MaxBodyBytes == 0 {
		v.MaxBodyBytes = DefaultValidationMaxBodyBytes
	}
	if v.MaxJSONDepth == 0 {
		v.MaxJSONDepth = DefaultValidationMaxJSONDepth
	}
	if v.Timeout.Duration == 0 {
		v.Timeout.Duration = DefaultValidationTimeout
	}
}

// validate checks the section's settings; where names it in errors. The
// spec file itself is loaded and checked when the router is built.
func (v *RouteValidation) validate(where string) error {
	switch v.Mode {
	case ValidationModeEnforce, ValidationModeReportOnly:
	default:
		return fmt.Errorf("%s.mode must be enforce or report_only, got %q", where, v.Mode)
	}
	if v.Enabled && v.OpenAPIFile == "" {
		return fmt.Errorf("%s.openapi_file is required when validation is enabled", where)
	}
	if v.RejectStatus != http.StatusBadRequest && v.RejectStatus != http.StatusUnprocessableEntity {
		return fmt.Errorf("%s.reject_status must be 400 or 422, got %d", where, v.RejectStatus)
	}
	if v.MaxBodyBytes < 0 || v.MaxBodyBytes > maxValidationBodyBytes {
		return fmt.Errorf("%s.max_body_bytes must be between 1 and %d", where, int64(maxValidationBodyBytes))
	}
	if v.MaxJSONDepth < 0 || v.MaxJSONDepth > maxValidationJSONDepth {
		return fmt.Errorf("%s.max_json_depth must be between 1 and %d", where, maxValidationJSONDepth)
	}
	if v.Timeout.Duration < 0 || v.Timeout.Duration > maxValidationTimeout {
		return fmt.Errorf("%s.timeout must be above 0 and at most %s", where, maxValidationTimeout)
	}
	return nil
}

func (c *Config) applyValidationDefaults() {
	for i := range c.Routes {
		if v := c.Routes[i].Validation; v != nil {
			v.applyDefaults()
		}
	}
}

func (c *Config) validateValidation() error {
	for i, rt := range c.Routes {
		if v := rt.Validation; v != nil {
			if err := v.validate(fmt.Sprintf("routes[%d].validation", i)); err != nil {
				return err
			}
		}
	}
	return nil
}
