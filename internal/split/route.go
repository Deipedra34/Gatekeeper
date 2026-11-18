package split

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/config"
)

// How a request's variant was chosen, reported in Decision.Source.
const (
	// SourceWeight: the client's bucket, by the current weights.
	SourceWeight = "weight"
	// SourceOverride: the override header, from an allowed client.
	SourceOverride = "override"
	// SourceRule: a match rule.
	SourceRule = "rule"
)

// Client is what the gateway knows about a request's client, for sticky
// assignment and override checks. Empty fields are unknown.
type Client struct {
	// IP is the client's address as access control (or, without it, the
	// connection) resolved it.
	IP string
	// APIKey is the raw API key the request carried.
	APIKey string
	// JWTSubject is the client id claim of a verified JWT.
	JWTSubject string
	// CertID is the identity of a verified client certificate.
	CertID string
	// Tier is the client's rate limit tier.
	Tier string
}

// Decision is the variant chosen for one request.
type Decision struct {
	// Index is the variant's position in the config, Name its name.
	Index int
	Name  string
	// Source says how it was chosen: SourceWeight, SourceOverride, or
	// SourceRule.
	Source string
	// SetCookie, when non-nil, is a sticky cookie to send the client: it
	// had none (or an invalid one) on a cookie-sticky route.
	SetCookie *http.Cookie
	// OverrideRefused is set when the request asked for a variant with
	// the override header but wasn't allowed to (or named no variant):
	// the header was ignored.
	OverrideRefused bool
}

// Route is a split route's compiled traffic split and its live state:
// the current weights. It outlives config reloads that leave the split
// unchanged (see Registry), so its state does too.
type Route struct {
	label    string
	cfg      config.TrafficSplitConfig
	names    []string
	baseline int
	salt     string
	now      func() time.Time
	signer   *CookieSigner
	override overrideAllow

	onEvent func(Event)

	// state is what changes while the route serves: shared with the
	// route that replaces this one on a reload, if that one's weights,
	// rollout, and guardrails are configured the same (see Adopt).
	*state
}

// state is a route's live state.
type state struct {
	configured Weights // the weights in the config

	guards   []*guard
	lastEval atomic.Int64 // unix nanos of the last guardrail evaluation

	mu       sync.Mutex
	base     Weights           // the weights, before any running rollout
	ro       *rollout          // nil without a rollout
	manual   bool              // an operator or a rollback set base
	last     *Rollback         // the most recent rollback
	cooldown map[int]time.Time // variant -> end of its post-rollback cooldown
}

// Event reports a change to a route's weights, for logs and metrics.
type Event struct {
	Route string
	// Kind is EventRolloutStep, EventPause, EventResume, EventSet,
	// EventPromote, or EventRollback.
	Kind string
	// Variant is the variant the event is about, if any.
	Variant string
	// Weights are the route's weights after the event.
	Weights map[string]int
	// Reason explains a rollback; Trigger says what caused it:
	// TriggerErrorRate, TriggerLatency, or TriggerManual.
	Reason  string
	Trigger string
	// Auto is set for changes nobody asked for: rollout steps and
	// automatic rollbacks.
	Auto bool
}

// Event kinds.
const (
	EventRolloutStep = "rollout_step"
	EventPause       = "pause"
	EventResume      = "resume"
	EventSet         = "set"
	EventPromote     = "promote"
	EventRollback    = "rollback"
)

// Option customises a Route.
type Option func(*Route)

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Route) { r.now = now }
}

// WithEvents calls fn after every change to the route's weights. It's
// called without the route's lock held, so it may read the route.
func WithEvents(fn func(Event)) Option {
	return func(r *Route) { r.onEvent = fn }
}

// NewRoute compiles cfg, a validated traffic split, for the route
// labelled label.
func NewRoute(label string, cfg config.TrafficSplitConfig, opts ...Option) (*Route, error) {
	if len(cfg.Variants) == 0 {
		return nil, fmt.Errorf("split: route %s has no variants", label)
	}
	r := &Route{label: label, cfg: cfg, now: time.Now, baseline: -1, state: &state{cooldown: map[int]time.Time{}}}
	for _, opt := range opts {
		opt(r)
	}
	w := make(Weights, len(cfg.Variants))
	for i, v := range cfg.Variants {
		r.names = append(r.names, v.Name)
		w[i] = v.Weight
		if v.Name == cfg.Baseline {
			r.baseline = i
		}
	}
	if r.baseline < 0 {
		r.baseline = 0
	}
	r.base, r.configured = w, w.Clone()
	r.guards = newGuards(cfg)
	if ro := cfg.Rollout; ro != nil {
		i, ok := r.Index(ro.Variant)
		if !ok {
			return nil, fmt.Errorf("split: route %s: rollout of unknown variant %q", label, ro.Variant)
		}
		r.ro = newRollout(i, ro.Steps, ro.Interval.Duration, r.now())
	}
	r.salt = cfg.Sticky.Salt
	if r.salt == "" {
		r.salt = label
	}
	if cfg.Override.Enabled {
		var err error
		if r.override, err = newOverrideAllow(cfg.Override.Allow); err != nil {
			return nil, fmt.Errorf("split: route %s: %w", label, err)
		}
	}
	if cfg.Sticky.By == config.StickyCookie {
		secret, err := cfg.Sticky.Cookie.SigningSecret()
		if err != nil {
			return nil, err
		}
		if secret == nil {
			r.signer = processSigner()
		} else {
			r.signer = NewCookieSigner(secret)
		}
	}
	return r, nil
}

var (
	processSignerOnce sync.Once
	processSignerVal  *CookieSigner
)

// processSigner is the signer for cookie-sticky routes without a secret
// of their own: one random secret for the whole process, so a reload
// doesn't invalidate every cookie.
func processSigner() *CookieSigner {
	processSignerOnce.Do(func() { processSignerVal = NewCookieSigner(nil) })
	return processSignerVal
}

// RandomCookieSecret reports whether the route signs sticky cookies with
// a secret generated at startup (so they don't survive a restart or
// reach other instances).
func (r *Route) RandomCookieSecret() bool {
	return r.signer != nil && r.signer == processSignerVal
}

// Label returns the route's label.
func (r *Route) Label() string { return r.label }

// Names returns the variant names in config order.
func (r *Route) Names() []string { return append([]string(nil), r.names...) }

// Index returns the position of the variant called name.
func (r *Route) Index(name string) (int, bool) {
	for i, n := range r.names {
		if n == name {
			return i, true
		}
	}
	return 0, false
}

// Baseline returns the baseline variant's index.
func (r *Route) Baseline() int { return r.baseline }

// Weights returns the current weights, advancing a running rollout
// first.
func (r *Route) Weights() Weights {
	r.mu.Lock()
	moved := r.advanceLocked()
	w := r.currentLocked()
	variant := r.rolloutVariantLocked()
	r.mu.Unlock()
	if moved {
		r.emit(Event{Kind: EventRolloutStep, Variant: variant, Auto: true}, w)
	}
	return w
}

// advanceLocked advances a running rollout to now, reporting whether it
// moved.
// rolloutVariantLocked names the rollout's variant ("" without one).
func (r *Route) rolloutVariantLocked() string {
	if r.ro == nil {
		return ""
	}
	return r.names[r.ro.variant]
}

func (r *Route) advanceLocked() bool {
	return r.ro != nil && r.ro.advance(r.now()) > 0
}

// currentLocked returns the weights in force: the rollout's share for
// its variant (the others splitting the rest as in base) while a rollout
// is in charge, base otherwise.
func (r *Route) currentLocked() Weights {
	if r.ro == nil || r.ro.state == RolloutStopped {
		return r.base.Clone()
	}
	return r.base.WithShare(r.ro.variant, r.ro.share(), r.baseline)
}

// emit reports e, with weights w, to the event hook.
func (r *Route) emit(e Event, w Weights) {
	if r.onEvent == nil {
		return
	}
	e.Route = r.label
	e.Weights = r.named(w)
	r.onEvent(e)
}

// named returns w keyed by variant name.
func (r *Route) named(w Weights) map[string]int {
	m := make(map[string]int, len(w))
	for i, n := range r.names {
		m[n] = w[i]
	}
	return m
}

// Pause freezes a running rollout at its current step.
func (r *Route) Pause() error {
	r.mu.Lock()
	r.advanceLocked()
	if r.ro == nil {
		r.mu.Unlock()
		return ErrNoRollout
	}
	err := r.ro.pause(r.now())
	w, variant := r.currentLocked(), r.rolloutVariantLocked()
	r.mu.Unlock()
	if err == nil {
		r.emit(Event{Kind: EventPause, Variant: variant}, w)
	}
	return err
}

// Rollout returns the route's rollout status, or nil without one.
func (r *Route) Rollout() *RolloutStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked()
	if r.ro == nil {
		return nil
	}
	return r.ro.status(r.names[r.ro.variant])
}

// Select chooses req's variant.
func (r *Route) Select(req *http.Request, c Client) Decision {
	refused := false
	if v := req.Header.Get(r.cfg.Override.Header); v != "" && r.cfg.Override.Enabled {
		if i, ok := r.Index(v); ok && r.override.allows(c) {
			return r.decide(i, SourceOverride)
		}
		refused = true
	}
	for _, rule := range r.cfg.Rules {
		if matches(rule.Match, req) {
			i, _ := r.Index(rule.Variant)
			d := r.decide(i, SourceRule)
			d.OverrideRefused = refused
			return d
		}
	}
	d := r.byWeight(req, c)
	d.OverrideRefused = refused
	return d
}

// byWeight places the client by its bucket and the current weights.
func (r *Route) byWeight(req *http.Request, c Client) Decision {
	w := r.Weights()
	if r.signer == nil {
		return r.decide(w.Pick(r.bucket(c)), SourceWeight)
	}
	bucket, fresh := r.cookieBucket(req)
	d := r.decide(w.Pick(bucket), SourceWeight)
	if fresh {
		d.SetCookie = r.cookie(bucket)
	}
	return d
}

// cookieBucket returns the bucket the request's sticky cookie holds, or
// a new random one (fresh) when it has no valid cookie.
func (r *Route) cookieBucket(req *http.Request) (bucket int, fresh bool) {
	if ck, err := req.Cookie(r.cfg.Sticky.Cookie.Name); err == nil {
		if b, ok := r.signer.Verify(r.salt, ck.Value); ok {
			return b, false
		}
	}
	return RandomBucket(), true
}

// cookie is the sticky cookie holding bucket. It's HttpOnly: scripts have
// no business with it.
func (r *Route) cookie(bucket int) *http.Cookie {
	ck := r.cfg.Sticky.Cookie
	return &http.Cookie{
		Name:     ck.Name,
		Value:    r.signer.Sign(r.salt, bucket),
		Path:     ck.Path,
		MaxAge:   int(ck.TTL.Seconds()),
		Secure:   ck.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (r *Route) decide(i int, source string) Decision {
	if i < 0 {
		i = r.baseline
	}
	return Decision{Index: i, Name: r.names[i], Source: source}
}

// identity returns what the client is known by for sticky assignment:
// the configured identity, or its address when the request doesn't
// carry that identity. Prefixes keep an API key from ever hashing like
// an IP that happens to be the same string.
func (r *Route) identity(c Client) string {
	switch r.cfg.Sticky.By {
	case config.StickyAPIKey:
		if c.APIKey != "" {
			return "key:" + c.APIKey
		}
	case config.StickyJWTSubject:
		if c.JWTSubject != "" {
			return "jwt:" + c.JWTSubject
		}
	case config.StickyClientCert:
		if c.CertID != "" {
			return "cert:" + c.CertID
		}
	}
	if c.IP != "" {
		return "ip:" + c.IP
	}
	return ""
}

// bucket returns the client's bucket: its identity's hash, or a random
// bucket for a client with no identity at all (it can't be kept sticky).
func (r *Route) bucket(c Client) int {
	id := r.identity(c)
	if id == "" {
		return RandomBucket()
	}
	return Bucket(r.salt, id)
}

// ResponseHeader names the response header that tells clients which
// variant served them; "" when off.
func (r *Route) ResponseHeader() string { return r.cfg.ResponseHeader }

// OverrideHeader returns the override header's name, which the proxy
// strips before forwarding unless forward_header is set.
func (r *Route) OverrideHeader() string { return r.cfg.Override.Header }

// ForwardOverrideHeader reports whether the override header is passed
// on to the backend.
func (r *Route) ForwardOverrideHeader() bool { return r.cfg.Override.ForwardHeader }

// overrideAllow is a compiled override allowlist.
type overrideAllow struct {
	anyone bool
	tiers  map[string]bool
	keys   [][]byte
	cidrs  *accesscontrol.PrefixSet
}

func newOverrideAllow(a config.OverrideAllow) (overrideAllow, error) {
	o := overrideAllow{anyone: a.Anyone, tiers: map[string]bool{}}
	for _, t := range a.Tiers {
		o.tiers[t] = true
	}
	for _, k := range a.APIKeys {
		o.keys = append(o.keys, []byte(k))
	}
	set, err := accesscontrol.NewPrefixSet(a.CIDRs)
	if err != nil {
		return o, fmt.Errorf("override.allow.cidrs: %w", err)
	}
	o.cidrs = set
	return o, nil
}

// allows reports whether c may pick a variant: any listed tier, API key
// (compared in constant time), or address will do.
func (o overrideAllow) allows(c Client) bool {
	if o.anyone || (c.Tier != "" && o.tiers[c.Tier]) {
		return true
	}
	if c.APIKey != "" {
		for _, k := range o.keys {
			if subtle.ConstantTimeCompare(k, []byte(c.APIKey)) == 1 {
				return true
			}
		}
	}
	if addr, err := netip.ParseAddr(c.IP); err == nil && o.cidrs != nil {
		return o.cidrs.Contains(addr)
	}
	return false
}

// matches reports whether req meets every condition m sets.
func matches(m config.SplitMatch, req *http.Request) bool {
	if m.PathPrefix != "" && !strings.HasPrefix(req.URL.Path, m.PathPrefix) {
		return false
	}
	if h := m.Header; h != nil {
		vals := req.Header.Values(h.Name)
		if len(vals) == 0 || (h.Value != "" && !contains(vals, h.Value)) {
			return false
		}
	}
	if ck := m.Cookie; ck != nil {
		c, err := req.Cookie(ck.Name)
		if err != nil || (ck.Value != "" && c.Value != ck.Value) {
			return false
		}
	}
	return true
}

func contains(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

// stateKey is the part of a traffic split its live state depends on:
// the variants and their weights, the baseline, the rollout, and the
// guardrails. Stickiness, overrides, rules, the response header, and
// each variant's backends can change without touching it.
func stateKey(cfg config.TrafficSplitConfig) string {
	type variant struct {
		Name         string
		Weight       int
		AutoRollback *config.AutoRollbackConfig
	}
	key := struct {
		Variants []variant
		Baseline string
		Rollout  *config.RolloutConfig
	}{Baseline: cfg.Baseline, Rollout: cfg.Rollout}
	for _, v := range cfg.Variants {
		key.Variants = append(key.Variants, variant{v.Name, v.Weight, v.AutoRollback})
	}
	b, _ := json.Marshal(key)
	return string(b)
}

// Adopt makes r share prev's live state — weights an operator set, the
// rollout's progress, the last rollback, cooldowns, and the guardrails'
// windows — when both are configured alike (see stateKey). It reports
// whether it did; otherwise r keeps the fresh state built from its
// config. Call it before r serves anything.
func (r *Route) Adopt(prev *Route) bool {
	if prev == nil || stateKey(prev.cfg) != stateKey(r.cfg) {
		return false
	}
	r.state = prev.state
	return true
}
