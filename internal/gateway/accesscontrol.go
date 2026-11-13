package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/config"
	"gatekeeper/internal/ratelimiter/store"
)

// buildAccessControl compiles cfg's access control, or returns nil when
// none is configured — in which case no access control middleware is
// installed at all and requests are handled exactly as before.
// Bans live in st, the store shared with the rate limiter.
func buildAccessControl(cfg *config.Config, st store.Store) (*accesscontrol.Controller, error) {
	if !cfg.AccessControlEnabled() {
		return nil, nil
	}
	global := config.AccessControlConfig{Mode: config.AccessModeOff}
	if cfg.AccessControl != nil {
		global = *cfg.AccessControl
	}
	s := accesscontrol.Settings{
		Global:         policySettings(config.EffectiveAccessControl(global, nil)),
		Routes:         map[string]accesscontrol.PolicySettings{},
		TrustedProxies: global.TrustedProxies,
		Store:          st,
		NeverBan:       global.AutoBan.NeverBan,
	}
	if ab := global.AutoBan; cfg.AccessControl != nil && ab.Enabled {
		s.AutoBan = &accesscontrol.AutoBanSettings{
			Threshold:   ab.Threshold,
			Window:      ab.Window.Duration,
			BanDuration: ab.BanDuration.Duration,
			Escalation: accesscontrol.EscalationSettings{
				Enabled:     ab.Escalation.Enabled,
				Multiplier:  ab.Escalation.Multiplier,
				MaxDuration: ab.Escalation.MaxDuration.Duration,
				ResetAfter:  ab.Escalation.ResetAfter.Duration,
			},
		}
		for _, t := range ab.Triggers {
			s.AutoBan.Triggers = append(s.AutoBan.Triggers, accesscontrol.Offense(t))
		}
	}
	for _, rt := range cfg.Routes {
		if rt.AccessControl != nil {
			s.Routes[rt.Label()] = policySettings(config.EffectiveAccessControl(global, rt.AccessControl))
		}
	}
	return accesscontrol.NewController(s)
}

func policySettings(eff config.RouteAccessControl) accesscontrol.PolicySettings {
	return accesscontrol.PolicySettings{
		Mode:       accesscontrol.Mode(eff.Mode),
		Allow:      eff.Allow,
		Deny:       eff.Deny,
		DenyStatus: eff.DenyStatus,
	}
}

// Access control logs at most accessLogBurst lines at once, then one
// per accessLogInterval; the rest are counted and dropped.
const (
	accessLogInterval = time.Second
	accessLogBurst    = 10
)

// activeBansTimeout bounds how long a /metrics scrape waits for the
// store to count active bans.
const activeBansTimeout = time.Second

// activeBans counts active bans for the /metrics gauge. It reports
// nothing without access control, or when the store can't be read.
func (g *Gateway) activeBans() (int, bool) {
	c := g.access.Load()
	if c == nil || c.Bans() == nil {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), activeBansTimeout)
	defer cancel()
	n, err := c.Bans().Count(ctx)
	if err != nil {
		return 0, false
	}
	return n, true
}

// logAccessControl summarises cfg's access control when it's loaded at
// startup or by a reload, so the log shows which lists are in force.
// Bans are kept in the store, so a reload neither lifts nor resets them.
func (g *Gateway) logAccessControl(cfg *config.Config) {
	if !cfg.AccessControlEnabled() {
		return
	}
	global := config.EffectiveAccessControl(config.AccessControlConfig{}, nil)
	var proxies int
	autoBan := "off"
	if ac := cfg.AccessControl; ac != nil {
		global = config.EffectiveAccessControl(*ac, nil)
		proxies = len(ac.TrustedProxies)
		if ac.AutoBan.Enabled {
			autoBan = fmt.Sprintf("on (%d offenses in %s -> %s)", ac.AutoBan.Threshold, ac.AutoBan.Window, ac.AutoBan.BanDuration)
		}
	}
	var overrides []string
	for _, rt := range cfg.Routes {
		if rt.AccessControl != nil {
			overrides = append(overrides, rt.Label())
		}
	}
	g.logger.Printf("access_control: mode=%s allow=%d deny=%d trusted_proxies=%d route_overrides=[%s] auto_ban=%s",
		global.Mode, len(global.Allow), len(global.Deny), proxies, strings.Join(overrides, " "), autoBan)
	if cfg.Transform.TrustForwardedHeaders && proxies == 0 {
		g.logger.Printf("access_control: transform.trust_forwarded_headers is on but access_control.trusted_proxies is empty, so access control ignores X-Forwarded-For and uses the connection's peer address")
	}
}
