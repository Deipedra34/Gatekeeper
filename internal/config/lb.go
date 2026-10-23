package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Load-balancing strategies for Route.LBStrategy.
const (
	LBRoundRobin         = "round_robin"
	LBLeastConnections   = "least_connections"
	LBWeightedRoundRobin = "weighted_round_robin"
	LBRandom             = "random"
	LBIPHash             = "ip_hash"
	LBConsistentHash     = "consistent_hash"
)

// Defaults for a route's backend pool.
const (
	DefaultDrainTimeout          = 30 * time.Second
	DefaultHealthCheckPath       = "/health"
	DefaultHealthCheckInterval   = 10 * time.Second
	DefaultHealthCheckTimeout    = 2 * time.Second
	DefaultHealthyThreshold      = 2
	DefaultUnhealthyThreshold    = 3
	DefaultPassiveFailures       = 5
	DefaultPassiveEjectionPeriod = 30 * time.Second
)

// BackendConfig is one entry of a route's backends list.
type BackendConfig struct {
	// Target is the backend's base URL, e.g. "http://10.0.0.5:9000".
	Target string `yaml:"target"`

	// Weight is the backend's relative share of traffic for the
	// weighted_round_robin, least_connections, random, and hash
	// strategies. Defaults to 1. round_robin ignores it.
	Weight int `yaml:"weight"`

	// BackendTLS, if set, replaces the route's backend_tls for this one
	// backend.
	BackendTLS *BackendTLSConfig `yaml:"backend_tls"`
}

// HealthCheckConfig controls active health checking: probing each
// backend in the background and taking it out of rotation while it
// fails.
type HealthCheckConfig struct {
	Enabled bool `yaml:"enabled"`

	// Path is requested with GET on each backend. Defaults to "/health".
	Path string `yaml:"path"`

	// Interval between probes (default 10s) and the timeout of each one
	// (default 2s).
	Interval Duration `yaml:"interval"`
	Timeout  Duration `yaml:"timeout"`

	// HealthyThreshold consecutive passing probes put an unhealthy
	// backend back into rotation (default 2); UnhealthyThreshold
	// consecutive failing probes take a healthy one out (default 3).
	HealthyThreshold   int `yaml:"healthy_threshold"`
	UnhealthyThreshold int `yaml:"unhealthy_threshold"`

	// ExpectedStatus lists the status codes that count as passing.
	// Empty (the default) means any 2xx or 3xx.
	ExpectedStatus []int `yaml:"expected_status"`
}

// PassiveHealthConfig controls passive health checking: taking a backend
// out of rotation for a while after consecutive real requests to it fail
// (timeout, connection error, or 5xx), without waiting for a probe.
type PassiveHealthConfig struct {
	// Enabled defaults to true for a route with two or more backends and
	// to false otherwise — with a single backend there's nowhere else to
	// send traffic, so ejecting it would only turn errors into 503s.
	Enabled *bool `yaml:"enabled"`

	// ConsecutiveFailures that eject a backend (default 5).
	ConsecutiveFailures int `yaml:"consecutive_failures"`

	// EjectionDuration is how long an ejected backend stays out of
	// rotation before getting traffic again (default 30s).
	EjectionDuration Duration `yaml:"ejection_duration"`
}

// EffectiveBackends returns the route's backends with defaults applied:
// its backends list, or — for a route configured with a single target —
// a one-entry list for that target. Each entry's BackendTLS is the
// effective one (its own, else the route's).
func (r Route) EffectiveBackends() []BackendConfig {
	if len(r.Backends) == 0 {
		bt := r.BackendTLS
		return []BackendConfig{{Target: r.Target, Weight: 1, BackendTLS: &bt}}
	}
	out := make([]BackendConfig, len(r.Backends))
	for i, b := range r.Backends {
		out[i] = b
		if out[i].Weight == 0 {
			out[i].Weight = 1
		}
		if out[i].BackendTLS == nil {
			bt := r.BackendTLS
			out[i].BackendTLS = &bt
		}
	}
	return out
}

// EffectiveLBStrategy returns LBStrategy, defaulting to round_robin.
func (r Route) EffectiveLBStrategy() string {
	if r.LBStrategy == "" {
		return LBRoundRobin
	}
	return r.LBStrategy
}

// PassiveHealthEnabled applies PassiveHealthConfig.Enabled's default.
func (r Route) PassiveHealthEnabled() bool {
	if r.PassiveHealthCheck.Enabled != nil {
		return *r.PassiveHealthCheck.Enabled
	}
	return len(r.Backends) > 1
}

// EffectiveDrainTimeout returns DrainTimeout, defaulting to 30s.
func (r Route) EffectiveDrainTimeout() time.Duration {
	if r.DrainTimeout.Duration <= 0 {
		return DefaultDrainTimeout
	}
	return r.DrainTimeout.Duration
}

// WithDefaults fills HealthCheckConfig's unset fields.
func (h HealthCheckConfig) WithDefaults() HealthCheckConfig {
	if h.Path == "" {
		h.Path = DefaultHealthCheckPath
	}
	if h.Interval.Duration == 0 {
		h.Interval.Duration = DefaultHealthCheckInterval
	}
	if h.Timeout.Duration == 0 {
		h.Timeout.Duration = DefaultHealthCheckTimeout
	}
	if h.HealthyThreshold == 0 {
		h.HealthyThreshold = DefaultHealthyThreshold
	}
	if h.UnhealthyThreshold == 0 {
		h.UnhealthyThreshold = DefaultUnhealthyThreshold
	}
	return h
}

// WithDefaults fills PassiveHealthConfig's unset numeric fields.
func (p PassiveHealthConfig) WithDefaults() PassiveHealthConfig {
	if p.ConsecutiveFailures == 0 {
		p.ConsecutiveFailures = DefaultPassiveFailures
	}
	if p.EjectionDuration.Duration == 0 {
		p.EjectionDuration.Duration = DefaultPassiveEjectionPeriod
	}
	return p
}

// validateBackends checks the route's target/backends, strategy, and
// health settings.
func (r Route) validateBackends() error {
	switch {
	case r.Target != "" && len(r.Backends) > 0:
		return fmt.Errorf("set either target or backends, not both")
	case r.Target == "" && len(r.Backends) == 0:
		return fmt.Errorf("target is required (or a backends list)")
	}

	seen := map[string]bool{}
	for j, b := range r.EffectiveBackends() {
		where := "target"
		if len(r.Backends) > 0 {
			where = fmt.Sprintf("backends[%d]", j)
		}
		if b.Target == "" {
			return fmt.Errorf("%s: target is required", where)
		}
		if len(r.Backends) > 0 {
			// A single target keeps its historical (lenient) parsing.
			u, err := url.Parse(b.Target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("%s: target %q must be an http:// or https:// URL with a host", where, b.Target)
			}
		}
		if r.Backends != nil && r.Backends[j].Weight < 0 {
			return fmt.Errorf("%s: weight must be >= 0", where)
		}
		if seen[b.Target] {
			return fmt.Errorf("%s: target %q is listed twice", where, b.Target)
		}
		seen[b.Target] = true
		if err := b.BackendTLS.validate(b.Target); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	}

	switch r.EffectiveLBStrategy() {
	case LBRoundRobin, LBLeastConnections, LBWeightedRoundRobin, LBRandom, LBIPHash:
		if r.LBHashHeader != "" {
			return fmt.Errorf("lb_hash_header only applies to lb_strategy consistent_hash")
		}
	case LBConsistentHash:
		if strings.ContainsAny(r.LBHashHeader, " \t:") {
			return fmt.Errorf("lb_hash_header %q is not a valid header name", r.LBHashHeader)
		}
	default:
		return fmt.Errorf("lb_strategy must be one of round_robin, least_connections, weighted_round_robin, random, ip_hash, consistent_hash, got %q", r.LBStrategy)
	}

	if r.HealthCheck.Enabled {
		h := r.HealthCheck.WithDefaults()
		switch {
		case !strings.HasPrefix(h.Path, "/"):
			return fmt.Errorf("health_check.path must start with /")
		case h.Interval.Duration <= 0 || h.Timeout.Duration <= 0:
			return fmt.Errorf("health_check.interval and health_check.timeout must be > 0")
		case h.Timeout.Duration > h.Interval.Duration:
			return fmt.Errorf("health_check.timeout must not exceed health_check.interval")
		case h.HealthyThreshold < 1 || h.UnhealthyThreshold < 1:
			return fmt.Errorf("health_check thresholds must be >= 1")
		}
		for _, s := range h.ExpectedStatus {
			if s < 100 || s > 599 {
				return fmt.Errorf("health_check.expected_status: %d is not an HTTP status code", s)
			}
		}
	}

	p := r.PassiveHealthCheck
	if p.ConsecutiveFailures < 0 || p.EjectionDuration.Duration < 0 {
		return fmt.Errorf("passive_health_check values must be >= 0")
	}
	if r.DrainTimeout.Duration < 0 {
		return fmt.Errorf("drain_timeout must be >= 0")
	}
	return nil
}
