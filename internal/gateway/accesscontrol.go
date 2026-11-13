package gateway

import (
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
