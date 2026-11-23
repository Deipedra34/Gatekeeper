package config

import (
	"errors"
	"fmt"
	"strings"

	"gatekeeper/internal/accesscontrol"
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

	// Match limits the rule to some of the route's requests. Left empty,
	// it applies to all of them.
	Match FaultMatch `yaml:"match"`

	// MaxDuration makes the rule expire on its own this long after it was
	// loaded; it then injects nothing until it's changed (or the gateway
	// restarts). 0, the default, means it never expires.
	MaxDuration Duration `yaml:"max_duration"`

	// AllowFullAbort permits an abort or connection_reset percentage of
	// 100 in a production-like environment, where it's refused otherwise:
	// it takes the route down for every request the rule matches.
	AllowFullAbort bool `yaml:"allow_full_abort,omitempty"`

	// CountAsBackendFailure makes injected faults count as failures of
	// the backend they stand in for: retried, and counted by its circuit
	// breaker and passive health check, so those can be tested. Defaults
	// to true; with false, a fault is answered right away and the backend
	// is left out of it.
	CountAsBackendFailure *bool `yaml:"count_as_backend_failure,omitempty"`
}

// CountsAsBackendFailure reports whether injected faults count as backend
// failures, applying the "true by default" rule.
func (f *RouteFaultConfig) CountsAsBackendFailure() bool {
	return f.CountAsBackendFailure == nil || *f.CountAsBackendFailure
}

// DefaultFaultHeader is the request header the README's examples use to
// ask for a fault: "X-Gatekeeper-Fault: true".
const DefaultFaultHeader = "X-Gatekeeper-Fault"

// FaultMatch limits a rule to requests meeting every condition set.
type FaultMatch struct {
	// Header limits the rule to requests carrying this header, with
	// Value if it's set (e.g. X-Gatekeeper-Fault: true).
	Header *ValueMatch `yaml:"header,omitempty"`
	// PathPrefixes limits the rule to request paths with one of these
	// prefixes.
	PathPrefixes []string `yaml:"path_prefixes,omitempty"`
	// Methods limits the rule to these request methods (GET, POST, ...).
	Methods []string `yaml:"methods,omitempty"`
	// Variants limits the rule to requests a split route sends to one of
	// these variants.
	Variants []string `yaml:"variants,omitempty"`
	// Backends limits the rule to attempts on these backends (their
	// targets, as configured): a retry on another backend isn't faulted.
	Backends []string `yaml:"backends,omitempty"`
	// Clients limits the rule to allowlisted clients.
	Clients *FaultClients `yaml:"clients,omitempty"`
}

// FaultClients lists the clients a rule applies to: a client matching
// any entry does.
type FaultClients struct {
	// Tiers are rate limit tiers.
	Tiers []string `yaml:"tiers,omitempty"`
	// APIKeys are raw API keys, compared with the auth header.
	APIKeys []string `yaml:"api_keys,omitempty"`
	// CIDRs are client addresses or ranges.
	CIDRs []string `yaml:"cidrs,omitempty"`
}

// FaultScope is what a rule is checked against: the rate limit tiers,
// the variants and backend targets of the rule's route, and whether the
// environment is production-like.
type FaultScope struct {
	Tiers          map[string]TierLimit
	Variants       []string
	Backends       []string
	ProductionLike bool
}

// FaultScope returns the scope rules on r are checked against.
func (r Route) FaultScope(tiers map[string]TierLimit) FaultScope {
	scope := FaultScope{Tiers: tiers}
	if ts := r.TrafficSplit; ts != nil {
		for i, v := range ts.Variants {
			scope.Variants = append(scope.Variants, v.Name)
			for _, b := range r.VariantRoute(i).EffectiveBackends() {
				scope.Backends = append(scope.Backends, b.Target)
			}
		}
		return scope
	}
	for _, b := range r.EffectiveBackends() {
		scope.Backends = append(scope.Backends, b.Target)
	}
	return scope
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
func (f *RouteFaultConfig) Validate(where string, scope FaultScope) error {
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
	if f.MaxDuration.Duration < 0 {
		return fmt.Errorf("%s.max_duration must be >= 0", where)
	}
	if scope.ProductionLike && !f.AllowFullAbort {
		if a := f.Abort; a != nil && a.Percentage >= 100 {
			return fmt.Errorf("%s.abort.percentage is 100, which fails every request the rule matches; in a production-like environment set allow_full_abort: true to mean it", where)
		}
		if r := f.ConnectionReset; r != nil && r.Percentage >= 100 {
			return fmt.Errorf("%s.connection_reset.percentage is 100, which fails every request the rule matches; in a production-like environment set allow_full_abort: true to mean it", where)
		}
	}
	return f.Match.validate(where+".match", scope)
}

func (m FaultMatch) validate(where string, scope FaultScope) error {
	if h := m.Header; h != nil && !validHeaderName(h.Name) {
		return fmt.Errorf("%s.header.name %q is not a valid header name", where, h.Name)
	}
	for i, p := range m.PathPrefixes {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("%s.path_prefixes[%d]: %q must start with /", where, i, p)
		}
	}
	for i, method := range m.Methods {
		if method == "" || method != strings.ToUpper(method) || !validHeaderName(method) {
			return fmt.Errorf("%s.methods[%d]: %q is not an upper-case HTTP method", where, i, method)
		}
	}
	for i, v := range m.Variants {
		if !contains(scope.Variants, v) {
			if len(scope.Variants) == 0 {
				return fmt.Errorf("%s.variants[%d]: the route has no traffic_split, so it has no variant %q", where, i, v)
			}
			return fmt.Errorf("%s.variants[%d]: no variant is called %q; the route has %s", where, i, v, strings.Join(scope.Variants, ", "))
		}
	}
	for i, b := range m.Backends {
		if !contains(scope.Backends, b) {
			return fmt.Errorf("%s.backends[%d]: %q is not one of the route's backends (%s)", where, i, b, strings.Join(scope.Backends, ", "))
		}
	}
	if c := m.Clients; c != nil {
		if len(c.Tiers) == 0 && len(c.APIKeys) == 0 && len(c.CIDRs) == 0 {
			return fmt.Errorf("%s.clients: list the tiers, api_keys, or cidrs the rule applies to", where)
		}
		for i, t := range c.Tiers {
			if _, ok := scope.Tiers[t]; !ok {
				return fmt.Errorf("%s.clients.tiers[%d]: no rate_limit tier is called %q", where, i, t)
			}
		}
		for i, k := range c.APIKeys {
			if k == "" {
				return fmt.Errorf("%s.clients.api_keys[%d] must not be empty", where, i)
			}
		}
		if _, err := accesscontrol.NewPrefixSet(c.CIDRs); err != nil {
			var ee *accesscontrol.EntryError
			if errors.As(err, &ee) {
				return fmt.Errorf("%s.clients.cidrs[%d]: %w", where, ee.Index, ee.Err)
			}
			return fmt.Errorf("%s.clients.cidrs: %w", where, err)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// validPercentage checks that p is a percentage, 0 to 100.
func validPercentage(where string, p float64) error {
	if p < 0 || p > 100 || p != p { // p != p: NaN
		return fmt.Errorf("%s.percentage must be between 0 and 100, got %v", where, p)
	}
	return nil
}
