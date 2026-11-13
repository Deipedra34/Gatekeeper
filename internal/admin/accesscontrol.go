package admin

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

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

// maxBanReason caps the operator-supplied reason stored with a ban.
const maxBanReason = 200

// banRequest is the body of POST /admin/v1/bans.
type banRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g. "30m"; default: auto_ban.ban_duration, or 1h
	Reason   string `json:"reason"`
}

// accessController returns the live access control, answering 409 if
// none is configured.
func (s *Server) accessController(w http.ResponseWriter) (*accesscontrol.Controller, bool) {
	c := s.gw.AccessControl()
	if c == nil || c.Bans() == nil {
		writeError(w, http.StatusConflict, codeConflict, "access control is not configured: add an access_control section (or a route-level one) and reload")
		return nil, false
	}
	return c, true
}

// parseBanAddr parses a single address to ban or unban. Ranges are
// refused: bans are per address; ranges belong in access_control.deny.
func parseBanAddr(w http.ResponseWriter, raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		writeError(w, http.StatusBadRequest, codeBadRequest, "bans are per address; put ranges in access_control.deny instead")
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, "ip must be a single IPv4 or IPv6 address")
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// createBan serves POST /admin/v1/bans: ban one address for a while,
// shared with every instance through the store. ?dry_run=true reports
// the ban without issuing it.
func (s *Server) createBan(w http.ResponseWriter, r *http.Request) {
	var req banRequest
	if !decodeBody(w, r, &req) {
		return
	}
	c, ok := s.accessController(w)
	if !ok {
		return
	}
	if req.IP == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, `say which address to ban: {"ip": "203.0.113.7", "duration": "1h"}`)
		return
	}
	addr, ok := parseBanAddr(w, req.IP)
	if !ok {
		return
	}
	d := c.DefaultBanDuration()
	if req.Duration != "" {
		parsed, err := time.ParseDuration(req.Duration)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, codeBadRequest, `duration must be a positive Go duration such as "30m" or "24h"`)
			return
		}
		d = parsed
	}
	if len(req.Reason) > maxBanReason {
		req.Reason = req.Reason[:maxBanReason]
	}
	if c.Protected(addr) {
		writeError(w, http.StatusConflict, codeConflict, addr.String()+" is on access_control.auto_ban.never_ban or is a trusted proxy, so it can't be banned")
		return
	}

	dry := dryRun(r)
	if dry {
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{
			"action": "ban", "dry_run": true,
			"ban": accesscontrol.Ban{IP: addr.String(), Source: accesscontrol.SourceManual, Reason: req.Reason, BannedAt: now, ExpiresAt: now.Add(d)},
		})
		return
	}
	ban, err := c.Ban(r.Context(), addr, d, req.Reason)
	switch {
	case errors.Is(err, accesscontrol.ErrProtected):
		writeError(w, http.StatusConflict, codeConflict, addr.String()+" is on access_control.auto_ban.never_ban or is a trusted proxy, so it can't be banned")
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, codeInternal, "storing the ban failed (is the store reachable?)")
		return
	}
	if s.metrics != nil {
		s.metrics.BansIssued.WithLabelValues(accesscontrol.SourceManual).Inc()
	}
	writeJSON(w, http.StatusCreated, map[string]any{"action": "ban", "dry_run": false, "ban": ban})
}

// deleteBan serves DELETE /admin/v1/bans/{ip}: lift a ban, automatic or
// manual, on every instance. ?dry_run=true reports whether there is one
// without lifting it.
func (s *Server) deleteBan(w http.ResponseWriter, r *http.Request) {
	c, ok := s.accessController(w)
	if !ok {
		return
	}
	addr, ok := parseBanAddr(w, r.PathValue("ip"))
	if !ok {
		return
	}
	dry := dryRun(r)
	var found bool
	var err error
	if dry {
		_, found, err = c.Bans().Get(r.Context(), addr)
	} else {
		found, err = c.Unban(r.Context(), addr)
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, codeInternal, "updating bans failed (is the store reachable?)")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, codeNotFound, addr.String()+" is not banned")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": "unban", "dry_run": dry, "ip": addr.String()})
}
