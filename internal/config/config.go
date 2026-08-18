// Package config loads and validates Gatekeeper's startup configuration
// from a YAML file: backend routes, rate-limit rules, client tiers, and
// the middleware/storage settings that wire everything together.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so config values can be written as human
// strings ("5s", "500ms") instead of raw nanosecond integers.
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}

// Config is the root of the configuration file.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Storage   StorageConfig   `yaml:"storage"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Auth      AuthConfig      `yaml:"auth"`
	CORS      CORSConfig      `yaml:"cors"`
	Routes    []Route         `yaml:"routes"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

// ServerConfig controls the HTTP listener Gatekeeper itself exposes.
type ServerConfig struct {
	ListenAddr   string   `yaml:"listen_addr"`
	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	IdleTimeout  Duration `yaml:"idle_timeout"`
}

// StorageConfig selects and configures the rate-limit counter backend.
type StorageConfig struct {
	// Backend is "memory" or "redis". If "redis" is picked but the server
	// turns out to be unreachable — whether that's right at startup or
	// sometime later — Gatekeeper falls back to an in-memory store and
	// logs a warning instead of refusing to serve traffic.
	Backend string      `yaml:"backend"`
	Redis   RedisConfig `yaml:"redis"`
}

// RedisConfig holds go-redis client options.
type RedisConfig struct {
	Addr        string   `yaml:"addr"`
	Password    string   `yaml:"password"`
	DB          int      `yaml:"db"`
	DialTimeout Duration `yaml:"dial_timeout"`
}

// RateLimitConfig defines which algorithm to run, how clients are
// identified, and the limits available to each client tier.
type RateLimitConfig struct {
	// Algorithm is one of "token_bucket", "sliding_window_log", or
	// "fixed_window".
	Algorithm string `yaml:"algorithm"`

	// Scope determines how a request is attributed to a client:
	// "api_key", "ip", or "header".
	Scope string `yaml:"scope"`

	// HeaderName is the header to key on when Scope is "header".
	HeaderName string `yaml:"header_name"`

	// Tiers maps a tier name (e.g. "free", "premium") to the limit
	// applied to clients in that tier.
	Tiers map[string]TierLimit `yaml:"tiers"`

	// Clients maps a client identifier (API key, IP, or header value,
	// depending on Scope) to the tier it belongs to. Clients not listed
	// here fall back to the "default" tier.
	Clients map[string]string `yaml:"clients"`
}

// TierLimit is the rate/burst allowance for one client tier.
type TierLimit struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int64   `yaml:"burst"`
}

// AuthConfig controls the API-key authentication middleware.
type AuthConfig struct {
	Enabled bool     `yaml:"enabled"`
	Header  string   `yaml:"header"`
	APIKeys []string `yaml:"api_keys"`
}

// CORSConfig controls the CORS middleware.
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"`
}

// Route maps incoming requests to a backend target, either by path
// prefix or by hostname. At least one of PathPrefix / Host must be set.
type Route struct {
	PathPrefix string `yaml:"path_prefix"`
	Host       string `yaml:"host"`
	Target     string `yaml:"target"`
}

// MetricsConfig controls the Prometheus-compatible metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// Load reads and parses the YAML config file at path, applies defaults
// for any unset fields, and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = ":8080"
	}
	if c.Server.ReadTimeout.Duration == 0 {
		c.Server.ReadTimeout.Duration = 10 * time.Second
	}
	if c.Server.WriteTimeout.Duration == 0 {
		c.Server.WriteTimeout.Duration = 10 * time.Second
	}
	if c.Server.IdleTimeout.Duration == 0 {
		c.Server.IdleTimeout.Duration = 60 * time.Second
	}

	if c.Storage.Backend == "" {
		c.Storage.Backend = "memory"
	}
	if c.Storage.Redis.DialTimeout.Duration == 0 {
		c.Storage.Redis.DialTimeout.Duration = 2 * time.Second
	}

	if c.RateLimit.Algorithm == "" {
		c.RateLimit.Algorithm = "token_bucket"
	}
	if c.RateLimit.Scope == "" {
		c.RateLimit.Scope = "ip"
	}
	if c.RateLimit.Tiers == nil {
		c.RateLimit.Tiers = map[string]TierLimit{}
	}
	if _, ok := c.RateLimit.Tiers["default"]; !ok {
		c.RateLimit.Tiers["default"] = TierLimit{RequestsPerSecond: 1, Burst: 1}
	}
	if c.RateLimit.Clients == nil {
		c.RateLimit.Clients = map[string]string{}
	}

	if c.Auth.Header == "" {
		c.Auth.Header = "X-API-Key"
	}

	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
}

func (c *Config) validate() error {
	switch c.Storage.Backend {
	case "memory", "redis":
	default:
		return fmt.Errorf("storage.backend must be \"memory\" or \"redis\", got %q", c.Storage.Backend)
	}
	if c.Storage.Backend == "redis" && c.Storage.Redis.Addr == "" {
		return fmt.Errorf("storage.redis.addr is required when storage.backend is \"redis\"")
	}

	switch c.RateLimit.Algorithm {
	case "token_bucket", "sliding_window_log", "fixed_window":
	default:
		return fmt.Errorf("rate_limit.algorithm must be one of token_bucket, sliding_window_log, fixed_window, got %q", c.RateLimit.Algorithm)
	}

	switch c.RateLimit.Scope {
	case "api_key", "ip", "header":
	default:
		return fmt.Errorf("rate_limit.scope must be one of api_key, ip, header, got %q", c.RateLimit.Scope)
	}
	if c.RateLimit.Scope == "header" && c.RateLimit.HeaderName == "" {
		return fmt.Errorf("rate_limit.header_name is required when rate_limit.scope is \"header\"")
	}

	for name, tier := range c.RateLimit.Tiers {
		if tier.RequestsPerSecond <= 0 {
			return fmt.Errorf("rate_limit.tiers.%s.requests_per_second must be > 0", name)
		}
		if tier.Burst <= 0 {
			return fmt.Errorf("rate_limit.tiers.%s.burst must be > 0", name)
		}
	}

	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route must be configured")
	}
	for i, r := range c.Routes {
		if r.PathPrefix == "" && r.Host == "" {
			return fmt.Errorf("routes[%d]: either path_prefix or host must be set", i)
		}
		if r.Target == "" {
			return fmt.Errorf("routes[%d]: target is required", i)
		}
	}

	if c.Auth.Enabled && len(c.Auth.APIKeys) == 0 {
		return fmt.Errorf("auth.enabled is true but auth.api_keys is empty")
	}

	return nil
}
