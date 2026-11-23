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
