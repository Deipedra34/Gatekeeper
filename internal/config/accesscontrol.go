package config

import (
	"errors"
	"fmt"
	"time"

	"gatekeeper/internal/accesscontrol"
)

// Access control modes, set via AccessControlConfig.Mode and
// RouteAccessControl.Mode.
const (
	// AccessModeOff applies no list restriction (the default). Bans
	// still apply.
	AccessModeOff = "off"
	// AccessModeDenylist rejects only addresses on the deny list.
	AccessModeDenylist = "denylist"
	// AccessModeAllowlistOnly rejects every address not on the allow
	// list, and addresses on the deny list even if they are.
	AccessModeAllowlistOnly = "allowlist_only"
)

// Auto-ban triggers, listed in AutoBanConfig.Triggers.
const (
	AutoBanTriggerRateLimit   = "rate_limit"   // a 429 from the rate limiter
	AutoBanTriggerAuthFailure = "auth_failure" // a 401 from the auth middleware
	AutoBanTriggerDenied      = "denied"       // a request rejected by the allow/deny lists
)

// Defaults for the access_control section.
const (
	DefaultAccessDenyStatus     = 403
	DefaultAutoBanThreshold     = 20
	DefaultAutoBanWindow        = time.Minute
	DefaultAutoBanDuration      = 10 * time.Minute
	DefaultAutoBanMultiplier    = 2.0
	DefaultAutoBanMaxDuration   = 24 * time.Hour
	DefaultAutoBanEscalateReset = 24 * time.Hour
)

// AccessControlConfig is the optional access_control section: IP allow
// and deny lists applied to every route, the proxies trusted to report
// the client address, and automatic temporary bans. Without the section
// (and without any route-level access_control) no access control
// middleware runs at all, so behaviour is exactly as before.
type AccessControlConfig struct {
	// Mode is off (the default), denylist, or allowlist_only.
	Mode string `yaml:"mode"`

	// Allow and Deny hold single IPv4/IPv6 addresses and CIDR ranges.
	// Deny always wins over Allow.
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`

	// DenyStatus is the HTTP status a rejected request gets. Defaults
	// to 403.
	DenyStatus int `yaml:"deny_status"`

	// TrustedProxies lists the addresses (or ranges) of proxies in front
	// of the gateway. Only when the connection's peer is one of them are
	// X-Forwarded-For and X-Real-IP believed; the client is then the
	// right-most X-Forwarded-For address that isn't itself a trusted
	// proxy. Empty means the peer address is always the client.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// AutoBan temporarily bans an address that misbehaves repeatedly.
	AutoBan AutoBanConfig `yaml:"auto_ban"`
}

// RouteAccessControl overrides the global allow/deny settings for one
// route. Every field left unset inherits the global value; a set field
// replaces it (an explicit empty list replaces it with nothing).
type RouteAccessControl struct {
	Mode       string   `yaml:"mode"`
	Allow      []string `yaml:"allow"`
	Deny       []string `yaml:"deny"`
	DenyStatus int      `yaml:"deny_status"`
}

// AutoBanConfig controls automatic bans.
type AutoBanConfig struct {
	// Enabled turns automatic bans on. Off by default.
	Enabled bool `yaml:"enabled"`

	// Threshold is how many triggering events from one client address
	// within Window get it banned. Defaults to 20.
	Threshold int `yaml:"threshold"`

	// Window is the counting window. Defaults to 1m.
	Window Duration `yaml:"window"`

	// BanDuration is how long a first ban lasts. Defaults to 10m.
	BanDuration Duration `yaml:"ban_duration"`

	// Triggers lists the events that count: rate_limit, auth_failure,
	// denied. Defaults to all three.
	Triggers []string `yaml:"triggers"`

	// NeverBan lists addresses and ranges that are never banned,
	// automatically or through the admin API. Trusted proxies are never
	// banned either.
	NeverBan []string `yaml:"never_ban"`

	// Escalation lengthens the bans of repeat offenders.
	Escalation AutoBanEscalation `yaml:"escalation"`
}

// AutoBanEscalation multiplies the ban duration for each further ban of
// the same address: BanDuration, then BanDuration*Multiplier, and so on,
// capped at MaxDuration. An address that goes ResetAfter without a new
// ban starts from BanDuration again.
type AutoBanEscalation struct {
	Enabled     bool     `yaml:"enabled"`
	Multiplier  float64  `yaml:"multiplier"`
	MaxDuration Duration `yaml:"max_duration"`
	ResetAfter  Duration `yaml:"reset_after"`
}

// AccessControlEnabled reports whether any access control is configured,
// globally or on a route — and so whether the middleware runs at all.
func (c *Config) AccessControlEnabled() bool {
	if c.AccessControl != nil {
		return true
	}
	for _, rt := range c.Routes {
		if rt.AccessControl != nil {
			return true
		}
	}
	return false
}

func (c *Config) applyAccessControlDefaults() {
	ac := c.AccessControl
	if ac == nil {
		return
	}
	if ac.Mode == "" {
		ac.Mode = AccessModeOff
	}
	if ac.DenyStatus == 0 {
		ac.DenyStatus = DefaultAccessDenyStatus
	}
	ab := &ac.AutoBan
	if ab.Threshold == 0 {
		ab.Threshold = DefaultAutoBanThreshold
	}
	if ab.Window.Duration == 0 {
		ab.Window.Duration = DefaultAutoBanWindow
	}
	if ab.BanDuration.Duration == 0 {
		ab.BanDuration.Duration = DefaultAutoBanDuration
	}
	if ab.Triggers == nil {
		ab.Triggers = []string{AutoBanTriggerRateLimit, AutoBanTriggerAuthFailure, AutoBanTriggerDenied}
	}
	esc := &ab.Escalation
	if esc.Multiplier == 0 {
		esc.Multiplier = DefaultAutoBanMultiplier
	}
	if esc.MaxDuration.Duration == 0 {
		esc.MaxDuration.Duration = max(DefaultAutoBanMaxDuration, ab.BanDuration.Duration)
	}
	if esc.ResetAfter.Duration == 0 {
		esc.ResetAfter.Duration = DefaultAutoBanEscalateReset
	}
}

// validateAccessControl checks the global section and every route
// override, compiling each list so a bad entry fails the load (and a
// SIGHUP reload) with the entry's exact location.
func (c *Config) validateAccessControl() error {
	ac := c.AccessControl
	global := AccessControlConfig{Mode: AccessModeOff}
	if ac != nil {
		global = *ac
		if err := validateMode("access_control.mode", ac.Mode); err != nil {
			return err
		}
		if err := validateDenyStatus("access_control.deny_status", ac.DenyStatus); err != nil {
			return err
		}
		for _, l := range []struct {
			name    string
			entries []string
		}{
			{"access_control.allow", ac.Allow},
			{"access_control.deny", ac.Deny},
			{"access_control.trusted_proxies", ac.TrustedProxies},
			{"access_control.auto_ban.never_ban", ac.AutoBan.NeverBan},
		} {
			if err := validateEntries(l.name, l.entries); err != nil {
				return err
			}
		}
		if ac.Mode == AccessModeOff && (len(ac.Allow) > 0 || len(ac.Deny) > 0) {
			return fmt.Errorf("access_control: allow or deny entries are set but mode is off; set mode to denylist or allowlist_only")
		}
		if ac.Mode == AccessModeAllowlistOnly && len(ac.Allow) == 0 {
			return fmt.Errorf("access_control: mode allowlist_only with an empty allow list would reject every request")
		}
		if err := ac.AutoBan.validate(); err != nil {
			return err
		}
	}

	for i, rt := range c.Routes {
		rac := rt.AccessControl
		if rac == nil {
			continue
		}
		prefix := fmt.Sprintf("routes[%d].access_control", i)
		if rac.Mode != "" {
			if err := validateMode(prefix+".mode", rac.Mode); err != nil {
				return err
			}
		}
		if rac.DenyStatus != 0 {
			if err := validateDenyStatus(prefix+".deny_status", rac.DenyStatus); err != nil {
				return err
			}
		}
		if err := validateEntries(prefix+".allow", rac.Allow); err != nil {
			return err
		}
		if err := validateEntries(prefix+".deny", rac.Deny); err != nil {
			return err
		}
		eff := EffectiveAccessControl(global, rac)
		if eff.Mode == AccessModeOff && (len(rac.Allow) > 0 || len(rac.Deny) > 0) {
			return fmt.Errorf("%s: allow or deny entries are set but the effective mode is off; set mode to denylist or allowlist_only", prefix)
		}
		if eff.Mode == AccessModeAllowlistOnly && len(eff.Allow) == 0 {
			return fmt.Errorf("%s: mode allowlist_only with an empty allow list would reject every request", prefix)
		}
	}
	return nil
}

// EffectiveAccessControl merges a route's override onto the global
// settings: each field the route sets replaces the global one. A nil
// override returns the global settings unchanged.
func EffectiveAccessControl(global AccessControlConfig, rac *RouteAccessControl) RouteAccessControl {
	eff := RouteAccessControl{Mode: global.Mode, Allow: global.Allow, Deny: global.Deny, DenyStatus: global.DenyStatus}
	if eff.Mode == "" {
		eff.Mode = AccessModeOff
	}
	if eff.DenyStatus == 0 {
		eff.DenyStatus = DefaultAccessDenyStatus
	}
	if rac == nil {
		return eff
	}
	if rac.Mode != "" {
		eff.Mode = rac.Mode
	}
	if rac.Allow != nil {
		eff.Allow = rac.Allow
	}
	if rac.Deny != nil {
		eff.Deny = rac.Deny
	}
	if rac.DenyStatus != 0 {
		eff.DenyStatus = rac.DenyStatus
	}
	return eff
}

func (ab AutoBanConfig) validate() error {
	if ab.Threshold < 1 {
		return fmt.Errorf("access_control.auto_ban.threshold must be >= 1")
	}
	if ab.Window.Duration <= 0 {
		return fmt.Errorf("access_control.auto_ban.window must be > 0")
	}
	if ab.BanDuration.Duration <= 0 {
		return fmt.Errorf("access_control.auto_ban.ban_duration must be > 0")
	}
	if ab.Enabled && len(ab.Triggers) == 0 {
		return fmt.Errorf("access_control.auto_ban.triggers must list at least one of rate_limit, auth_failure, denied")
	}
	for i, t := range ab.Triggers {
		switch t {
		case AutoBanTriggerRateLimit, AutoBanTriggerAuthFailure, AutoBanTriggerDenied:
		default:
			return fmt.Errorf("access_control.auto_ban.triggers[%d] must be one of rate_limit, auth_failure, denied, got %q", i, t)
		}
	}
	esc := ab.Escalation
	if esc.Multiplier < 1 {
		return fmt.Errorf("access_control.auto_ban.escalation.multiplier must be >= 1")
	}
	if esc.MaxDuration.Duration < ab.BanDuration.Duration {
		return fmt.Errorf("access_control.auto_ban.escalation.max_duration must be >= access_control.auto_ban.ban_duration")
	}
	if esc.ResetAfter.Duration <= 0 {
		return fmt.Errorf("access_control.auto_ban.escalation.reset_after must be > 0")
	}
	return nil
}

func validateMode(field, mode string) error {
	switch mode {
	case AccessModeOff, AccessModeDenylist, AccessModeAllowlistOnly:
		return nil
	}
	return fmt.Errorf("%s must be one of off, denylist, allowlist_only, got %q", field, mode)
}

func validateDenyStatus(field string, status int) error {
	if status < 400 || status > 599 {
		return fmt.Errorf("%s must be an HTTP error status (400-599), got %d", field, status)
	}
	return nil
}

func validateEntries(field string, entries []string) error {
	if _, err := accesscontrol.NewPrefixSet(entries); err != nil {
		var ee *accesscontrol.EntryError
		if errors.As(err, &ee) {
			return fmt.Errorf("%s[%d]: %v", field, ee.Index, ee.Err)
		}
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}
