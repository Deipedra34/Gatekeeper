package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"gatekeeper/internal/accesscontrol"
)

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

// VariantRoute returns the route as variant i sees it: the route's own
// settings (auth, cache, circuit breaker, backend TLS, transforms, ...)
// with the variant's backend group in place of the route's. LB and
// health check settings the variant leaves unset are the route's.
func (r Route) VariantRoute(i int) Route {
	v := r.TrafficSplit.Variants[i]
	out := r
	out.TrafficSplit = nil
	out.Target, out.Backends = v.Target, v.Backends
	if v.LBStrategy != "" {
		out.LBStrategy = v.LBStrategy
		out.LBHashHeader = v.LBHashHeader
	} else if v.LBHashHeader != "" {
		out.LBHashHeader = v.LBHashHeader
	}
	if !reflect.DeepEqual(v.HealthCheck, HealthCheckConfig{}) {
		out.HealthCheck = v.HealthCheck
	}
	if !reflect.DeepEqual(v.PassiveHealthCheck, PassiveHealthConfig{}) {
		out.PassiveHealthCheck = v.PassiveHealthCheck
	}
	return out
}

// validVariantName reports whether name can be used as a variant name:
// it ends up in metrics labels, headers, and log lines.
func validVariantName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// validateSplitBackends checks a split route's variants and their
// backend groups. The route itself must then have no target or backends.
func (r Route) validateSplitBackends() error {
	ts := r.TrafficSplit
	if r.Target != "" || len(r.Backends) > 0 {
		return fmt.Errorf("traffic_split: a split route takes its backends from its variants; remove the route's target/backends")
	}
	if len(ts.Variants) < 2 {
		return fmt.Errorf("traffic_split.variants: at least two variants are needed")
	}
	names := map[string]bool{}
	targets := map[string]string{}
	for i, v := range ts.Variants {
		where := fmt.Sprintf("traffic_split.variants[%d]", i)
		if !validVariantName(v.Name) {
			return fmt.Errorf("%s: name %q must be 1-64 letters, digits, '-', '_' or '.'", where, v.Name)
		}
		if names[v.Name] {
			return fmt.Errorf("%s: variant %q is listed twice", where, v.Name)
		}
		names[v.Name] = true
		vr := r.VariantRoute(i)
		if err := vr.validateBackends(); err != nil {
			return fmt.Errorf("%s (%s): %w", where, v.Name, err)
		}
		for _, b := range vr.EffectiveBackends() {
			if other, ok := targets[b.Target]; ok {
				return fmt.Errorf("%s (%s): target %q is also used by variant %q; variants need separate backends", where, v.Name, b.Target, other)
			}
			targets[b.Target] = v.Name
		}
	}
	return nil
}

// validateTrafficSplit checks everything about a split route except its
// backend groups (see validateSplitBackends).
func (r Route) validateTrafficSplit(tiers map[string]TierLimit) error {
	ts := r.TrafficSplit
	if ts == nil {
		return nil
	}
	if err := ts.validateWeights(); err != nil {
		return err
	}
	if err := ts.validateSticky(); err != nil {
		return err
	}
	if err := ts.validateOverride(tiers); err != nil {
		return err
	}
	return ts.validateRules()
}

// validateWeights checks that every weight is a percentage and that they
// add up to exactly 100.
func (ts *TrafficSplitConfig) validateWeights() error {
	sum := 0
	for i, v := range ts.Variants {
		if v.Weight < 0 || v.Weight > 100 {
			return fmt.Errorf("traffic_split.variants[%d] (%s): weight must be between 0 and 100, got %d", i, v.Name, v.Weight)
		}
		sum += v.Weight
	}
	if sum != 100 {
		return fmt.Errorf("traffic_split: variant weights must add up to 100, got %d", sum)
	}
	return nil
}

// Traffic split defaults.
const (
	DefaultVariantHeader       = "X-Gatekeeper-Variant"
	DefaultStickyCookieName    = "gk_variant"
	DefaultStickyCookieTTL     = 24 * time.Hour
	DefaultRollbackWindow      = 5 * time.Minute
	DefaultRollbackMinRequests = 100
	DefaultRollbackCooldown    = 10 * time.Minute
)

// applyTrafficSplitDefaults fills unset traffic split fields on every
// split route.
func (c *Config) applyTrafficSplitDefaults() {
	for i := range c.Routes {
		ts := c.Routes[i].TrafficSplit
		if ts == nil {
			continue
		}
		if ts.Baseline == "" && len(ts.Variants) > 0 {
			ts.Baseline = ts.Variants[0].Name
		}
		if ts.Sticky.By == "" {
			ts.Sticky.By = StickyClientIP
		}
		ck := &ts.Sticky.Cookie
		if ck.Name == "" {
			ck.Name = DefaultStickyCookieName
		}
		if ck.TTL.Duration == 0 {
			ck.TTL.Duration = DefaultStickyCookieTTL
		}
		if ck.Path == "" {
			ck.Path = "/"
		}
		if ts.Override.Header == "" {
			ts.Override.Header = DefaultVariantHeader
		}
		for j := range ts.Variants {
			if ar := ts.Variants[j].AutoRollback; ar != nil {
				ar.applyDefaults()
			}
		}
	}
}

func (ar *AutoRollbackConfig) applyDefaults() {
	if ar.Window.Duration == 0 {
		ar.Window.Duration = DefaultRollbackWindow
	}
	if ar.MinRequests == 0 {
		ar.MinRequests = DefaultRollbackMinRequests
	}
	if ar.Cooldown.Duration == 0 {
		ar.Cooldown.Duration = DefaultRollbackCooldown
	}
}

// variantIndex returns the index of the variant called name, or -1.
func (ts *TrafficSplitConfig) variantIndex(name string) int {
	for i, v := range ts.Variants {
		if v.Name == name {
			return i
		}
	}
	return -1
}

// validateSticky checks the baseline and the stickiness settings.
func (ts *TrafficSplitConfig) validateSticky() error {
	if ts.variantIndex(ts.Baseline) < 0 {
		return fmt.Errorf("traffic_split.baseline: no variant is called %q", ts.Baseline)
	}
	switch ts.Sticky.By {
	case StickyClientIP, StickyAPIKey, StickyJWTSubject, StickyClientCert, StickyCookie:
	default:
		return fmt.Errorf("traffic_split.sticky.by must be one of client_ip, api_key, jwt_subject, client_cert, cookie, got %q", ts.Sticky.By)
	}
	ck := ts.Sticky.Cookie
	if !validHeaderName(ck.Name) {
		return fmt.Errorf("traffic_split.sticky.cookie.name %q is not a valid cookie name", ck.Name)
	}
	if ck.TTL.Duration < 0 {
		return fmt.Errorf("traffic_split.sticky.cookie.ttl must be >= 0")
	}
	if !strings.HasPrefix(ck.Path, "/") {
		return fmt.Errorf("traffic_split.sticky.cookie.path must start with /")
	}
	if ts.Sticky.By == StickyCookie {
		if _, err := ck.SigningSecret(); err != nil {
			return err
		}
	}
	return nil
}

// SigningSecret returns the cookie signing secret: Secret, or the
// environment variable SecretEnv names. Nil (with no error) means
// neither is set and the caller should generate one. Errors never
// include the secret.
func (ck StickyCookieConfig) SigningSecret() ([]byte, error) {
	switch {
	case ck.Secret != "" && ck.SecretEnv != "":
		return nil, fmt.Errorf("traffic_split.sticky.cookie: set only one of secret and secret_env")
	case ck.SecretEnv != "":
		s := os.Getenv(ck.SecretEnv)
		if s == "" {
			return nil, fmt.Errorf("traffic_split.sticky.cookie: environment variable %s named by secret_env is empty or unset", ck.SecretEnv)
		}
		return checkCookieSecret([]byte(s))
	case ck.Secret != "":
		return checkCookieSecret([]byte(ck.Secret))
	}
	return nil, nil
}

func checkCookieSecret(s []byte) ([]byte, error) {
	if len(s) < 16 {
		return nil, fmt.Errorf("traffic_split.sticky.cookie: the signing secret must be at least 16 bytes")
	}
	return s, nil
}

// validateOverride checks the override header settings. An enabled
// override must say who may use it: an empty allowlist would let any
// client pick the canary, so that has to be asked for with anyone: true.
func (ts *TrafficSplitConfig) validateOverride(tiers map[string]TierLimit) error {
	o := ts.Override
	if !validHeaderName(o.Header) {
		return fmt.Errorf("traffic_split.override.header %q is not a valid header name", o.Header)
	}
	if !o.Enabled {
		return nil
	}
	a := o.Allow
	if !a.Anyone && len(a.Tiers) == 0 && len(a.APIKeys) == 0 && len(a.CIDRs) == 0 {
		return fmt.Errorf("traffic_split.override.allow: list the tiers, api_keys, or cidrs that may pick a variant (or set anyone: true, for routes the public can't reach)")
	}
	for j, t := range a.Tiers {
		if _, ok := tiers[t]; !ok {
			return fmt.Errorf("traffic_split.override.allow.tiers[%d]: no rate_limit tier is called %q", j, t)
		}
	}
	for j, k := range a.APIKeys {
		if k == "" {
			return fmt.Errorf("traffic_split.override.allow.api_keys[%d] must not be empty", j)
		}
	}
	if _, err := accesscontrol.NewPrefixSet(a.CIDRs); err != nil {
		var ee *accesscontrol.EntryError
		if errors.As(err, &ee) {
			return fmt.Errorf("traffic_split.override.allow.cidrs[%d]: %w", ee.Index, ee.Err)
		}
		return fmt.Errorf("traffic_split.override.allow.cidrs: %w", err)
	}
	return nil
}

// validateRules checks the match rules.
func (ts *TrafficSplitConfig) validateRules() error {
	for j, rule := range ts.Rules {
		where := fmt.Sprintf("traffic_split.rules[%d]", j)
		if ts.variantIndex(rule.Variant) < 0 {
			return fmt.Errorf("%s: no variant is called %q", where, rule.Variant)
		}
		m := rule.Match
		if m.Header == nil && m.Cookie == nil && m.PathPrefix == "" {
			return fmt.Errorf("%s: match needs a header, cookie, or path_prefix", where)
		}
		if m.Header != nil && !validHeaderName(m.Header.Name) {
			return fmt.Errorf("%s: match.header.name %q is not a valid header name", where, m.Header.Name)
		}
		if m.Cookie != nil && !validHeaderName(m.Cookie.Name) {
			return fmt.Errorf("%s: match.cookie.name %q is not a valid cookie name", where, m.Cookie.Name)
		}
		if m.PathPrefix != "" && !strings.HasPrefix(m.PathPrefix, "/") {
			return fmt.Errorf("%s: match.path_prefix must start with /", where)
		}
	}
	return nil
}
