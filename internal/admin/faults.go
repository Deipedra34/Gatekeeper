package admin

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/fault"
	"gatekeeper/internal/middleware"
)

// maxFaultTTL caps how long a rule created through the admin API stays
// in force: a forgotten experiment ends on its own within a day.
const maxFaultTTL = 24 * time.Hour

// faultRuleID is what a runtime rule's ID may look like. "config-" is
// kept for config rules.
var faultRuleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// faultRuleRequest is the body of POST /admin/v1/faults: a rule in the
// same shape as a route's fault_injection section, plus the route it's
// for, an optional ID, and a required TTL.
type faultRuleRequest struct {
	// ID names the rule; a rule by that ID is replaced. Generated when
	// left out.
	ID string `json:"id"`
	// Route is the route's id (see GET /admin/v1/routes), its label, or
	// its path prefix without the leading slash.
	Route string `json:"route"`
	// TTL is how long the rule stays in force ("15m"), up to 24h.
	TTL string `json:"ttl"`

	Delay                 *faultDelayJSON `json:"delay"`
	Abort                 *faultAbortJSON `json:"abort"`
	ConnectionReset       *faultResetJSON `json:"connection_reset"`
	Match                 *faultMatchJSON `json:"match"`
	CountAsBackendFailure *bool           `json:"count_as_backend_failure"`
	AllowFullAbort        bool            `json:"allow_full_abort"`
}

type faultDelayJSON struct {
	Percentage float64 `json:"percentage"`
	Fixed      string  `json:"fixed,omitempty"`
	Min        string  `json:"min,omitempty"`
	Max        string  `json:"max,omitempty"`
}

type faultAbortJSON struct {
	Percentage float64 `json:"percentage"`
	Status     int     `json:"status"`
}

type faultResetJSON struct {
	Percentage float64 `json:"percentage"`
}

type faultHeaderJSON struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type faultClientsJSON struct {
	Tiers   []string `json:"tiers,omitempty"`
	APIKeys []string `json:"api_keys,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
}

type faultMatchJSON struct {
	Header       *faultHeaderJSON  `json:"header,omitempty"`
	PathPrefixes []string          `json:"path_prefixes,omitempty"`
	Methods      []string          `json:"methods,omitempty"`
	Variants     []string          `json:"variants,omitempty"`
	Backends     []string          `json:"backends,omitempty"`
	Clients      *faultClientsJSON `json:"clients,omitempty"`
}

// faultRuleView is a rule as the admin API shows it. API keys it
// targets are shown as fingerprints.
type faultRuleView struct {
	ID      string `json:"id"`
	Route   string `json:"route"`
	RouteID string `json:"route_id"`
	Source  string `json:"source"`
	// InForce: the kill switch is on and the rule hasn't expired.
	InForce bool `json:"in_force"`
	Expired bool `json:"expired"`
	// StartedAt is when the rule came into force; ExpiresAt when it
	// stops, and RemainingSeconds how long that is from now — both null
	// for a config rule without max_duration.
	StartedAt        time.Time  `json:"started_at"`
	ExpiresAt        *time.Time `json:"expires_at"`
	RemainingSeconds *float64   `json:"remaining_seconds"`
	Summary          string     `json:"summary"`

	Delay                 *faultDelayJSON `json:"delay,omitempty"`
	Abort                 *faultAbortJSON `json:"abort,omitempty"`
	ConnectionReset       *faultResetJSON `json:"connection_reset,omitempty"`
	Match                 *faultMatchJSON `json:"match,omitempty"`
	CountAsBackendFailure bool            `json:"count_as_backend_failure"`
	AllowFullAbort        bool            `json:"allow_full_abort,omitempty"`
}

// listFaults serves GET /admin/v1/faults: the kill switch, and every
// rule held — config and runtime, in force or expired — with its
// remaining time.
func (s *Server) listFaults(w http.ResponseWriter, _ *http.Request) {
	reg := s.gw.Faults()
	cfg := s.gw.Config().FaultInjection
	now := time.Now()
	enabled := reg.Enabled()
	rules := []faultRuleView{}
	active := 0
	for _, r := range reg.Rules() {
		v := viewFaultRule(r, enabled, now)
		if v.InForce {
			active++
		}
		rules = append(rules, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"global_enabled":  enabled,
		"environment":     cfg.Environment,
		"production_like": cfg.ProductionLike(),
		"active":          active > 0,
		"rules_in_force":  active,
		"rules":           rules,
	})
}

// createFault serves POST /admin/v1/faults: create the rule, or replace
// the runtime rule with the same ID, in force for its TTL.
// ?dry_run=true validates it and shows it, changing nothing.
func (s *Server) createFault(w http.ResponseWriter, r *http.Request) {
	var req faultRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Route == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, `say which route: {"route": "<id from GET /admin/v1/routes>"}`)
		return
	}
	cfg := s.gw.Config()
	route, ok := findRoute(cfg, req.Route)
	if !ok {
		writeError(w, http.StatusNotFound, codeNotFound, "no route "+req.Route+"; use a route's id from GET /admin/v1/routes, its label, or its path prefix")
		return
	}
	id := req.ID
	switch {
	case id == "":
		id = newFaultRuleID()
	case !faultRuleID.MatchString(id):
		writeError(w, http.StatusBadRequest, codeBadRequest, "id must be 1-64 letters, digits, '.', '_', or '-', starting with a letter or digit")
		return
	case strings.HasPrefix(id, "config-"):
		writeError(w, http.StatusBadRequest, codeBadRequest, `ids starting with "config-" belong to config rules; pick another`)
		return
	}
	if req.TTL == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, `say how long the rule stays in force: {"ttl": "15m"} (up to 24h)`)
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > maxFaultTTL {
		writeError(w, http.StatusBadRequest, codeBadRequest, "ttl must be a duration above 0 and at most 24h, e.g. \"15m\"")
		return
	}
	fc, msg := req.ruleConfig()
	if msg != "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, msg)
		return
	}
	scope := route.FaultScope(cfg.RateLimit.Tiers)
	scope.ProductionLike = cfg.FaultInjection.ProductionLike()
	if err := fc.Validate("rule", scope); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, err.Error())
		return
	}

	label := route.Label()
	noteAuditTarget(w, "fault rule "+id+" on route "+label)
	reg := s.gw.Faults()
	enabled := reg.Enabled()
	body := map[string]any{"dry_run": dryRun(r)}
	if !enabled {
		body["warning"] = "fault_injection.global_enabled is false: the rule is kept, but nothing is injected until it's turned on"
	}
	now := time.Now()
	if dryRun(r) {
		_, exists := reg.Get(id)
		body["replaced"] = exists
		body["rule"] = viewFaultRule(fault.NewRule(id, label, fault.SourceRuntime, withTTL(fc, ttl), now), enabled, now)
		writeJSON(w, http.StatusOK, body)
		return
	}
	if prev, ok := reg.Get(id); ok && prev.Source == fault.SourceConfig {
		writeError(w, http.StatusConflict, codeConflict, "rule "+id+" is a config rule; pick another id")
		return
	}
	rule, replaced := reg.Put(id, label, fc, ttl)
	verb := "created"
	if replaced {
		verb = "replaced"
	}
	s.logger.Printf("fault_injection: WARNING: runtime rule %s %s on route %s through the admin API: %s; expires in %s", id, verb, label, rule.Summary(), ttl)
	body["replaced"] = replaced
	body["rule"] = viewFaultRule(rule, enabled, now)
	status := http.StatusCreated
	if replaced {
		status = http.StatusOK
	}
	writeJSON(w, status, body)
}

// deleteFault serves DELETE /admin/v1/faults/{id}: take the rule out of
// force. A config rule comes back on the next reload or restart, which
// reads it from the config file again. ?dry_run=true shows the rule,
// changing nothing.
func (s *Server) deleteFault(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reg := s.gw.Faults()
	rule, ok := reg.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, codeNotFound, "no fault rule "+id+"; see GET /admin/v1/faults")
		return
	}
	noteAuditTarget(w, "fault rule "+id+" on route "+rule.Route)
	now := time.Now()
	body := map[string]any{"dry_run": dryRun(r), "rule": viewFaultRule(rule, reg.Enabled(), now)}
	if rule.Source == fault.SourceConfig {
		body["note"] = "a config rule is only removed until the next reload or restart; edit the config file to remove it for good"
	}
	if dryRun(r) {
		writeJSON(w, http.StatusOK, body)
		return
	}
	if _, ok := reg.Delete(id); !ok {
		writeError(w, http.StatusNotFound, codeNotFound, "no fault rule "+id+"; see GET /admin/v1/faults")
		return
	}
	s.logger.Printf("fault_injection: rule %s (%s) on route %s removed through the admin API", id, rule.Source, rule.Route)
	writeJSON(w, http.StatusOK, body)
}

// findRoute resolves name to a configured route: its id, its label, or
// its path prefix without the leading slash.
func findRoute(cfg *config.Config, name string) (config.Route, bool) {
	for _, rt := range cfg.Routes {
		if l := rt.Label(); l == name || l == "/"+name || routeID(l) == name {
			return rt, true
		}
	}
	return config.Route{}, false
}

func newFaultRuleID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "fault-" + hex.EncodeToString(b)
}

func withTTL(c config.RouteFaultConfig, ttl time.Duration) config.RouteFaultConfig {
	c.Enabled = true
	c.MaxDuration = config.Duration{Duration: ttl}
	return c
}

// ruleConfig turns the request into a rule config, or says what's wrong
// with its durations.
func (req *faultRuleRequest) ruleConfig() (config.RouteFaultConfig, string) {
	c := config.RouteFaultConfig{
		Enabled:               true,
		CountAsBackendFailure: req.CountAsBackendFailure,
		AllowFullAbort:        req.AllowFullAbort,
	}
	if d := req.Delay; d != nil {
		fd := &config.FaultDelay{Percentage: d.Percentage}
		for _, f := range []struct {
			name, value string
			dst         *config.Duration
		}{{"delay.fixed", d.Fixed, &fd.Fixed}, {"delay.min", d.Min, &fd.Min}, {"delay.max", d.Max, &fd.Max}} {
			if f.value == "" {
				continue
			}
			v, err := time.ParseDuration(f.value)
			if err != nil {
				return c, f.name + " must be a duration, e.g. \"500ms\""
			}
			f.dst.Duration = v
		}
		c.Delay = fd
	}
	if a := req.Abort; a != nil {
		c.Abort = &config.FaultAbort{Percentage: a.Percentage, Status: a.Status}
	}
	if rs := req.ConnectionReset; rs != nil {
		c.ConnectionReset = &config.FaultReset{Percentage: rs.Percentage}
	}
	if m := req.Match; m != nil {
		c.Match = config.FaultMatch{
			PathPrefixes: m.PathPrefixes, Methods: m.Methods,
			Variants: m.Variants, Backends: m.Backends,
		}
		if h := m.Header; h != nil {
			c.Match.Header = &config.ValueMatch{Name: h.Name, Value: h.Value}
		}
		if cl := m.Clients; cl != nil {
			c.Match.Clients = &config.FaultClients{Tiers: cl.Tiers, APIKeys: cl.APIKeys, CIDRs: cl.CIDRs}
		}
	}
	return c, ""
}

// viewFaultRule renders r for the admin API at now; enabled is the kill
// switch.
func viewFaultRule(r *fault.Rule, enabled bool, now time.Time) faultRuleView {
	c := r.Config
	v := faultRuleView{
		ID: r.ID, Route: r.Route, RouteID: routeID(r.Route), Source: r.Source,
		Expired:               r.ExpiredAt(now),
		StartedAt:             r.Start.UTC(),
		Summary:               r.Summary(),
		CountAsBackendFailure: c.CountsAsBackendFailure(),
		AllowFullAbort:        c.AllowFullAbort,
	}
	v.InForce = enabled && !v.Expired
	if !r.Expires.IsZero() {
		at := r.Expires.UTC()
		left := r.Remaining(now).Seconds()
		v.ExpiresAt, v.RemainingSeconds = &at, &left
	}
	if d := c.Delay; d != nil {
		v.Delay = &faultDelayJSON{Percentage: d.Percentage}
		if d.Fixed.Duration > 0 {
			v.Delay.Fixed = d.Fixed.Duration.String()
		} else {
			v.Delay.Min, v.Delay.Max = d.Min.Duration.String(), d.Max.Duration.String()
		}
	}
	if a := c.Abort; a != nil {
		v.Abort = &faultAbortJSON{Percentage: a.Percentage, Status: a.Status}
	}
	if rs := c.ConnectionReset; rs != nil {
		v.ConnectionReset = &faultResetJSON{Percentage: rs.Percentage}
	}
	m := c.Match
	mv := &faultMatchJSON{PathPrefixes: m.PathPrefixes, Methods: m.Methods, Variants: m.Variants, Backends: m.Backends}
	if h := m.Header; h != nil {
		mv.Header = &faultHeaderJSON{Name: h.Name, Value: h.Value}
		if sensitiveName(h.Name) && h.Value != "" {
			mv.Header.Value = redacted
		}
	}
	if cl := m.Clients; cl != nil {
		mv.Clients = &faultClientsJSON{Tiers: cl.Tiers, CIDRs: cl.CIDRs}
		for _, k := range cl.APIKeys {
			mv.Clients.APIKeys = append(mv.Clients.APIKeys, middleware.APIKeyFingerprint(k))
		}
	}
	if mv.Header != nil || mv.PathPrefixes != nil || mv.Methods != nil || mv.Variants != nil || mv.Backends != nil || mv.Clients != nil {
		v.Match = mv
	}
	return v
}
