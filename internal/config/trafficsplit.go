package config

// TrafficSplitConfig splits a route's traffic between named variants
// (for example "stable" and "canary"), each with its own backend group.
// A route without it is proxied exactly as before.
type TrafficSplitConfig struct {
	// Variants are the backend groups traffic is split between, in the
	// order their shares are laid out (see the ADR): list the stable
	// variant first, so growing a canary only ever moves clients from
	// stable to canary.
	Variants []VariantConfig `yaml:"variants"`

	// Baseline names the variant auto_rollback compares the others
	// with, and the one that receives a rolled-back variant's share.
	// Defaults to the first variant.
	Baseline string `yaml:"baseline,omitempty"`

	// Sticky keeps each client on the same variant.
	Sticky StickyConfig `yaml:"sticky"`

	// Override lets selected clients pick a variant with a request
	// header.
	Override OverrideConfig `yaml:"override"`

	// Rules send matching requests (by header, cookie, or path prefix)
	// to a fixed variant, before weights are consulted.
	Rules []SplitRule `yaml:"rules,omitempty"`

	// Rollout, if set, raises one variant's weight in steps over time.
	Rollout *RolloutConfig `yaml:"rollout,omitempty"`

	// ResponseHeader, if set, names a response header that tells the
	// client which variant served it. Empty (the default) adds nothing.
	ResponseHeader string `yaml:"response_header,omitempty"`
}

// VariantConfig is one variant of a split route: a name, a share of the
// traffic, and a backend group configured exactly like a route's own
// (target or backends, lb_strategy, health checks).
type VariantConfig struct {
	Name string `yaml:"name"`

	// Weight is the variant's percentage of the route's traffic. The
	// weights of a route's variants must add up to 100.
	Weight int `yaml:"weight"`

	Target             string              `yaml:"target,omitempty"`
	Backends           []BackendConfig     `yaml:"backends,omitempty"`
	LBStrategy         string              `yaml:"lb_strategy,omitempty"`
	LBHashHeader       string              `yaml:"lb_hash_header,omitempty"`
	HealthCheck        HealthCheckConfig   `yaml:"health_check"`
	PassiveHealthCheck PassiveHealthConfig `yaml:"passive_health_check"`

	// AutoRollback, if set, takes the variant's traffic away when it
	// does measurably worse than the baseline.
	AutoRollback *AutoRollbackConfig `yaml:"auto_rollback,omitempty"`
}

// Ways to keep a client on the same variant, for StickyConfig.By.
const (
	StickyClientIP   = "client_ip"
	StickyAPIKey     = "api_key"
	StickyJWTSubject = "jwt_subject"
	StickyClientCert = "client_cert"
	StickyCookie     = "cookie"
)

// StickyConfig picks what identifies a client for variant assignment.
type StickyConfig struct {
	// By is client_ip (the default), api_key, jwt_subject, client_cert
	// (the verified certificate's identity), or cookie. A request
	// without the chosen identity falls back to its client IP.
	By string `yaml:"by,omitempty"`

	// Salt is mixed into the hash. Changing it reshuffles every client;
	// it's there so two routes splitting the same clients don't put the
	// same clients on their canaries. Defaults to the route's label.
	Salt string `yaml:"salt,omitempty"`

	// Cookie configures by: cookie.
	Cookie StickyCookieConfig `yaml:"cookie"`
}

// StickyCookieConfig is the cookie that remembers a client's place.
type StickyCookieConfig struct {
	// Name defaults to "gk_variant".
	Name string `yaml:"name,omitempty"`
	// TTL is the cookie's lifetime. Defaults to 24h.
	TTL Duration `yaml:"ttl"`
	// Secret signs the cookie, so a client can't forge one to pick a
	// variant; SecretEnv names an environment variable holding it. Set
	// at most one. With neither, a random secret is generated at
	// startup: cookies then don't survive a restart or carry over to
	// other instances (clients are simply reassigned).
	Secret    string `yaml:"secret,omitempty"`
	SecretEnv string `yaml:"secret_env,omitempty"`
	// Path defaults to "/".
	Path string `yaml:"path,omitempty"`
	// Secure marks the cookie Secure.
	Secure bool `yaml:"secure,omitempty"`
}

// OverrideConfig lets a client force a variant with a header.
type OverrideConfig struct {
	Enabled bool `yaml:"enabled"`
	// Header defaults to "X-Gatekeeper-Variant".
	Header string `yaml:"header,omitempty"`
	// Allow restricts who may override. Leaving it empty lets every
	// client choose, which is refused at load: see validation.
	Allow OverrideAllow `yaml:"allow"`
	// ForwardHeader passes the override header on to the backend. By
	// default it's removed before forwarding.
	ForwardHeader bool `yaml:"forward_header,omitempty"`
}

// OverrideAllow lists who may use the override header: a client
// matching any entry may.
type OverrideAllow struct {
	// Tiers are rate limit tiers.
	Tiers []string `yaml:"tiers,omitempty"`
	// APIKeys are raw API keys, compared with the auth header.
	APIKeys []string `yaml:"api_keys,omitempty"`
	// CIDRs are client addresses or ranges.
	CIDRs []string `yaml:"cidrs,omitempty"`
	// Anyone allows every client: only for non-public routes.
	Anyone bool `yaml:"anyone,omitempty"`
}

// SplitRule sends requests matching every condition of Match to Variant.
type SplitRule struct {
	Variant string     `yaml:"variant"`
	Match   SplitMatch `yaml:"match"`
}

// SplitMatch is a rule's conditions; at least one must be set, and every
// set condition must hold.
type SplitMatch struct {
	Header     *ValueMatch `yaml:"header,omitempty"`
	Cookie     *ValueMatch `yaml:"cookie,omitempty"`
	PathPrefix string      `yaml:"path_prefix,omitempty"`
}

// ValueMatch matches a named header or cookie: present with Value, or
// present at all when Value is empty.
type ValueMatch struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value,omitempty"`
}

// RolloutConfig raises Variant's weight through Steps, one step every
// Interval, starting when the config is loaded.
type RolloutConfig struct {
	Variant  string   `yaml:"variant"`
	Steps    []int    `yaml:"steps"`
	Interval Duration `yaml:"interval"`
}

// AutoRollbackConfig sets a variant's guardrails, compared with the
// baseline over a rolling window.
type AutoRollbackConfig struct {
	// Window is the rolling window the rates and latencies cover.
	// Defaults to 5m.
	Window Duration `yaml:"window"`
	// MinRequests is the fewest requests the variant must have served in
	// the window before it can be judged. Defaults to 100.
	MinRequests int `yaml:"min_requests"`
	// MaxErrorRateIncrease rolls back when the variant's 5xx rate exceeds
	// the baseline's by more than this (0.05 = five percentage points).
	// 0 disables the check.
	MaxErrorRateIncrease float64 `yaml:"max_error_rate_increase"`
	// MaxP95LatencyRatio rolls back when the variant's p95 latency is
	// more than this multiple of the baseline's (1.5 = 50% slower). 0
	// disables the check.
	MaxP95LatencyRatio float64 `yaml:"max_p95_latency_ratio"`
	// Cooldown is how long after a rollback the variant's traffic can't
	// be raised again (by a rollout resume or a weight change) without
	// forcing it. Defaults to 10m.
	Cooldown Duration `yaml:"cooldown"`
}
