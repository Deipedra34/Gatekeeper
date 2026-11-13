package admin

import (
	"net/http"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/config"
)

// accessPolicy is one policy in GET /admin/v1/access-control.
type accessPolicy struct {
	Route      string   `json:"route,omitempty"`
	Mode       string   `json:"mode"`
	Allow      []string `json:"allow"`
	Deny       []string `json:"deny"`
	DenyStatus int      `json:"deny_status"`
}

func newAccessPolicy(route string, eff config.RouteAccessControl) accessPolicy {
	p := accessPolicy{Route: route, Mode: eff.Mode, Allow: eff.Allow, Deny: eff.Deny, DenyStatus: eff.DenyStatus}
	if p.Allow == nil {
		p.Allow = []string{}
	}
	if p.Deny == nil {
		p.Deny = []string{}
	}
	return p
}

type autoBanInfo struct {
	Enabled     bool           `json:"enabled"`
	Threshold   int            `json:"threshold"`
	Window      string         `json:"window"`
	BanDuration string         `json:"ban_duration"`
	Triggers    []string       `json:"triggers"`
	NeverBan    []string       `json:"never_ban"`
	Escalation  escalationInfo `json:"escalation"`
}

type escalationInfo struct {
	Enabled     bool    `json:"enabled"`
	Multiplier  float64 `json:"multiplier"`
	MaxDuration string  `json:"max_duration"`
	ResetAfter  string  `json:"reset_after"`
}

// accessControl serves GET /admin/v1/access-control: the lists in force
// (the global policy and every route override, merged as requests see
// them), the trusted proxies, the auto-ban settings, and every active
// ban across the fleet.
func (s *Server) accessControl(w http.ResponseWriter, r *http.Request) {
	cfg := s.gw.Config()
	c := s.gw.AccessControl()
	if c == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "bans": []accesscontrol.Ban{}})
		return
	}

	global := config.AccessControlConfig{}
	if cfg.AccessControl != nil {
		global = *cfg.AccessControl
	}
	routes := []accessPolicy{}
	for _, rt := range cfg.Routes {
		if rt.AccessControl != nil {
			routes = append(routes, newAccessPolicy(rt.Label(), config.EffectiveAccessControl(global, rt.AccessControl)))
		}
	}
	ab := global.AutoBan
	resp := map[string]any{
		"enabled":         true,
		"global":          newAccessPolicy("", config.EffectiveAccessControl(global, nil)),
		"routes":          routes,
		"trusted_proxies": nonNil(global.TrustedProxies),
		"auto_ban": autoBanInfo{
			Enabled: ab.Enabled, Threshold: ab.Threshold, Window: ab.Window.String(),
			BanDuration: ab.BanDuration.String(), Triggers: nonNil(ab.Triggers), NeverBan: nonNil(ab.NeverBan),
			Escalation: escalationInfo{
				Enabled: ab.Escalation.Enabled, Multiplier: ab.Escalation.Multiplier,
				MaxDuration: ab.Escalation.MaxDuration.String(), ResetAfter: ab.Escalation.ResetAfter.String(),
			},
		},
	}

	bans := []accesscontrol.Ban{}
	var err error
	if c.Bans() != nil {
		bans, err = c.Bans().List(r.Context())
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, codeInternal, "reading bans failed (is the store reachable?)")
		return
	}
	resp["bans"] = bans
	resp["active_bans"] = len(bans)
	writeJSON(w, http.StatusOK, resp)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
