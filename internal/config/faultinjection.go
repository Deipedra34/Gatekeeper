package config

import (
	"fmt"
	"strings"
)

// Fault injection environments, for FaultInjectionConfig.Environment.
// Anything but development and test counts as production-like.
const (
	FaultEnvProduction  = "production"
	FaultEnvStaging     = "staging"
	FaultEnvDevelopment = "development"
	FaultEnvTest        = "test"
)

// FaultInjectionConfig is the global side of fault injection: the kill
// switch every rule is subject to, the environment that decides how
// strict the safety guards are, and paths that are never faulted. Each
// route opts in separately with its own fault_injection section; with
// this section left out nothing is ever faulted.
type FaultInjectionConfig struct {
	// GlobalEnabled is the kill switch. Faults are injected only while it
	// is true, whatever the routes and the admin API say. Defaults to
	// false.
	GlobalEnabled bool `yaml:"global_enabled"`

	// Environment is production (the default), staging, development, or
	// test. Every environment but development and test is production-like:
	// there, a rule that aborts or resets 100% of its requests is refused
	// unless it sets allow_full_abort: true.
	Environment string `yaml:"environment,omitempty"`

	// ExemptPaths are further request paths (exact, or a prefix ending in
	// "/") that are never faulted, on top of the built-in ones: the
	// metrics path and the usual health check paths. They can only add
	// exemptions, never remove the built-in ones.
	ExemptPaths []string `yaml:"exempt_paths,omitempty"`
}

// ProductionLike reports whether the environment gets the strict safety
// guards: every environment but development and test does.
func (f FaultInjectionConfig) ProductionLike() bool {
	return f.Environment != FaultEnvDevelopment && f.Environment != FaultEnvTest
}

func (f *FaultInjectionConfig) applyDefaults() {
	if f.Environment == "" {
		f.Environment = FaultEnvProduction
	}
}

func (f FaultInjectionConfig) validate() error {
	switch f.Environment {
	case FaultEnvProduction, FaultEnvStaging, FaultEnvDevelopment, FaultEnvTest:
	default:
		return fmt.Errorf("fault_injection.environment must be one of production, staging, development, test, got %q", f.Environment)
	}
	for i, p := range f.ExemptPaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("fault_injection.exempt_paths[%d]: %q must start with /", i, p)
		}
	}
	return nil
}

// RouteFaultConfig is one route's fault injection rule: which faults to
// inject, into what share of the route's requests. Faults are injected
// only when Enabled is set here and fault_injection.global_enabled is on.
// A route without this section is proxied exactly as before.
type RouteFaultConfig struct {
	// Enabled turns the rule on. Defaults to false.
	Enabled bool `yaml:"enabled"`

	// Delay holds requests back before they reach the backend.
	Delay *FaultDelay `yaml:"delay,omitempty"`

	// Abort answers requests with an error status instead of the
	// backend's response.
	Abort *FaultAbort `yaml:"abort,omitempty"`

	// ConnectionReset abruptly closes the client connection instead of
	// answering.
	ConnectionReset *FaultReset `yaml:"connection_reset,omitempty"`
}

// FaultDelay delays a percentage of requests by a fixed duration or by a
// random one between Min and Max.
type FaultDelay struct {
	// Percentage of the rule's requests to delay, 0 to 100.
	Percentage float64 `yaml:"percentage"`
	// Fixed is the delay; set either it or Min and Max.
	Fixed Duration `yaml:"fixed"`
	// Min and Max bound a random delay, picked uniformly per request.
	Min Duration `yaml:"min"`
	Max Duration `yaml:"max"`
}

// FaultAbort answers a percentage of requests with Status.
type FaultAbort struct {
	// Percentage of the rule's requests to abort, 0 to 100.
	Percentage float64 `yaml:"percentage"`
	// Status is the HTTP status to answer with, 400-599 (e.g. 500, 503).
	Status int `yaml:"status"`
}

// FaultReset abruptly closes the client connection for a percentage of
// requests.
type FaultReset struct {
	// Percentage of the rule's requests to reset, 0 to 100.
	Percentage float64 `yaml:"percentage"`
}

// Validate checks the rule. where prefixes every error (e.g.
// "routes[2].fault_injection"). A rule is checked even while it's
// disabled, so a typo surfaces at load rather than the day it's turned
// on.
func (f *RouteFaultConfig) Validate(where string) error {
	if f.Delay == nil && f.Abort == nil && f.ConnectionReset == nil {
		return fmt.Errorf("%s: set at least one of delay, abort, connection_reset", where)
	}
	if d := f.Delay; d != nil {
		if err := validPercentage(where+".delay", d.Percentage); err != nil {
			return err
		}
		fixed, ranged := d.Fixed.Duration != 0, d.Min.Duration != 0 || d.Max.Duration != 0
		switch {
		case fixed && ranged:
			return fmt.Errorf("%s.delay: set either fixed or min and max, not both", where)
		case !fixed && !ranged:
			return fmt.Errorf("%s.delay: set fixed (e.g. 500ms) or min and max", where)
		case fixed && d.Fixed.Duration < 0:
			return fmt.Errorf("%s.delay.fixed must be > 0", where)
		case ranged && (d.Min.Duration < 0 || d.Max.Duration <= 0):
			return fmt.Errorf("%s.delay: min must be >= 0 and max > 0", where)
		case ranged && d.Min.Duration > d.Max.Duration:
			return fmt.Errorf("%s.delay: min (%s) must not be greater than max (%s)", where, d.Min.Duration, d.Max.Duration)
		}
	}
	if a := f.Abort; a != nil {
		if err := validPercentage(where+".abort", a.Percentage); err != nil {
			return err
		}
		if a.Status < 400 || a.Status > 599 {
			return fmt.Errorf("%s.abort.status must be an HTTP error status, 400-599, got %d", where, a.Status)
		}
	}
	if r := f.ConnectionReset; r != nil {
		if err := validPercentage(where+".connection_reset", r.Percentage); err != nil {
			return err
		}
	}
	return nil
}

// validPercentage checks that p is a percentage, 0 to 100.
func validPercentage(where string, p float64) error {
	if p < 0 || p > 100 || p != p { // p != p: NaN
		return fmt.Errorf("%s.percentage must be between 0 and 100, got %v", where, p)
	}
	return nil
}
