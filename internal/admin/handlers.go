package admin

import (
	"math"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gatekeeper/internal/cache"
	"gatekeeper/internal/config"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/version"
)

// routes registers every endpoint. GETs only read; every POST changes
// gateway state, and the destructive ones (marked) accept ?dry_run=true
// to report what they would do without doing it.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /admin/v1/status", s.status)
	s.mux.HandleFunc("GET /admin/v1/config", s.config)
	s.mux.HandleFunc("GET /admin/v1/routes", s.listRoutes)
	s.mux.HandleFunc("GET /admin/v1/backends", s.listBackends)
	s.mux.HandleFunc("GET /admin/v1/ratelimits/{client}", s.getRateLimit)
	s.mux.HandleFunc("GET /admin/v1/cache/stats", s.cacheStats)

	s.mux.HandleFunc("POST /admin/v1/reload", s.reloadConfig)                 // dry_run
	s.mux.HandleFunc("POST /admin/v1/cache/purge", s.purgeCache)              // destructive, dry_run
	s.mux.HandleFunc("POST /admin/v1/ratelimits/{client}/reset", s.resetRate) // destructive, dry_run
	s.mux.HandleFunc("POST /admin/v1/backends/{id}/drain", s.drainBackend)    // destructive, dry_run
	s.mux.HandleFunc("POST /admin/v1/backends/{id}/enable", s.enableBackend)
	s.mux.HandleFunc("POST /admin/v1/circuit-breakers/{id}/reset", s.resetBreaker) // dry_run
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	cfg := s.gw.Config()
	now := time.Now()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":             version.Version,
		"commit":              version.Commit,
		"build_date":          version.Date,
		"go_version":          runtime.Version(),
		"started_at":          s.started.UTC(),
		"uptime_seconds":      math.Round(now.Sub(s.started).Seconds()),
		"config_path":         s.gw.ConfigPath(),
		"config_loaded_at":    s.gw.ConfigLoadedAt().UTC(),
		"routes":              len(cfg.Routes),
		"storage_backend":     cfg.Storage.Backend,
		"rate_limit":          map[string]string{"algorithm": cfg.RateLimit.Algorithm, "scope": cfg.RateLimit.Scope},
		"tracing_enabled":     s.gw.Tracer().Enabled(),
		"tls_enabled":         cfg.TLS.Enabled,
		"admin_tls_enabled":   s.TLSEnabled(),
		"backends_registered": len(s.gw.Backends()),
	})
}

func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	tree, err := redactedConfig(s.gw.Config())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not render the config")
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

type routeInfo struct {
	Label          string          `json:"label"`
	PathPrefix     string          `json:"path_prefix,omitempty"`
	Host           string          `json:"host,omitempty"`
	AuthMode       string          `json:"auth_mode"`
	LBStrategy     string          `json:"lb_strategy"`
	Backends       []routeBackend  `json:"backends"`
	Cache          routeCache      `json:"cache"`
	CircuitBreaker routeCBSettings `json:"circuit_breaker"`
	WebSocket      bool            `json:"websocket"`
}

type routeBackend struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Weight int    `json:"weight"`
}

type routeCache struct {
	Enabled bool   `json:"enabled"`
	TTL     string `json:"ttl"`
}

type routeCBSettings struct {
	Enabled          bool   `json:"enabled"`
	FailureThreshold int    `json:"failure_threshold"`
	OpenDuration     string `json:"open_duration"`
}

func (s *Server) listRoutes(w http.ResponseWriter, _ *http.Request) {
	cfg := s.gw.Config()
	routes := make([]routeInfo, 0, len(cfg.Routes))
	for _, rt := range cfg.Routes {
		info := routeInfo{
			Label: rt.Label(), PathPrefix: rt.PathPrefix, Host: rt.Host,
			AuthMode: rt.EffectiveAuthMode(), LBStrategy: rt.EffectiveLBStrategy(),
			Backends:  []routeBackend{},
			Cache:     routeCache{Enabled: rt.Cache.IsEnabled(), TTL: rt.Cache.TTL.String()},
			WebSocket: rt.WebSocketEnabled(),
			CircuitBreaker: routeCBSettings{
				Enabled:          rt.CircuitBreaker.IsEnabled() && rt.CircuitBreaker.FailureThreshold > 0,
				FailureThreshold: rt.CircuitBreaker.FailureThreshold,
				OpenDuration:     rt.CircuitBreaker.OpenDuration.String(),
			},
		}
		for _, bc := range rt.EffectiveBackends() {
			target := bc.Target
			if u, err := url.Parse(bc.Target); err == nil {
				target = lb.Label(u) // never echo credentials in a target
			}
			info.Backends = append(info.Backends, routeBackend{
				ID: lb.BackendID(rt.Label(), target), Target: target, Weight: max(bc.Weight, 1),
			})
		}
		routes = append(routes, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": routes})
}

type backendInfo struct {
	ID             string `json:"id"`
	Route          string `json:"route"`
	Target         string `json:"target"`
	Weight         int    `json:"weight"`
	Healthy        bool   `json:"healthy"`
	InRotation     bool   `json:"in_rotation"`
	Disabled       bool   `json:"disabled"`
	Draining       bool   `json:"draining"`
	InFlight       int64  `json:"in_flight"`
	CircuitBreaker string `json:"circuit_breaker"`
}

func describeBackend(b *lb.Backend) backendInfo {
	breaker := "disabled"
	if cb := b.Breaker(); cb != nil {
		breaker = cb.State().String()
	}
	return backendInfo{
		ID: b.ID(), Route: b.Route(), Target: b.Label(), Weight: b.Settings().Weight,
		Healthy: b.Healthy(), InRotation: b.Available(), Disabled: b.Disabled(), Draining: b.Draining(),
		InFlight: b.InFlight(), CircuitBreaker: breaker,
	}
}

func (s *Server) listBackends(w http.ResponseWriter, _ *http.Request) {
	backends := s.gw.Backends()
	out := make([]backendInfo, 0, len(backends))
	for _, b := range backends {
		out = append(out, describeBackend(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"backends": out})
}

// findBackends returns the live backends with id: normally one, but a
// backend can briefly exist twice while a reload drains the old copy.
// Copies a reload is draining away are skipped.
func (s *Server) findBackends(id string) []*lb.Backend {
	var out []*lb.Backend
	for _, b := range s.gw.Backends() {
		if b.ID() == id && !b.Draining() {
			out = append(out, b)
		}
	}
	return out
}

func (s *Server) drainBackend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	matches := s.findBackends(id)
	if len(matches) == 0 {
		writeError(w, http.StatusNotFound, codeNotFound, "no backend with id "+id+"; see GET /admin/v1/backends")
		return
	}
	b := matches[0]

	// Refuse to empty a route by accident.
	others := 0
	for _, o := range s.gw.Backends() {
		if o.Route() == b.Route() && o.ID() != id && o.Available() {
			others++
		}
	}
	force, _ := strconv.ParseBool(r.URL.Query().Get("force"))
	if others == 0 && b.Available() && !force {
		writeError(w, http.StatusConflict, codeConflict,
			"backend "+id+" is the last one in rotation for route "+b.Route()+"; draining it would fail every request on that route with 503. Pass force=true to drain it anyway")
		return
	}

	dry := dryRun(r)
	if !dry {
		for _, m := range matches {
			m.SetDisabled(true)
		}
	}
	info := describeBackend(b)
	if dry {
		info.Disabled, info.InRotation = true, false
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": "backend.drain", "dry_run": dry, "backend": info,
		"route_backends_in_rotation": others,
	})
}

func (s *Server) enableBackend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	matches := s.findBackends(id)
	if len(matches) == 0 {
		writeError(w, http.StatusNotFound, codeNotFound, "no backend with id "+id+"; see GET /admin/v1/backends")
		return
	}
	for _, m := range matches {
		m.SetDisabled(false)
	}
	info := describeBackend(matches[0])
	resp := map[string]any{"action": "backend.enable", "backend": info}
	if !info.Healthy {
		resp["note"] = "enabled, but the backend is failing health checks, so it stays out of rotation until it recovers"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) resetBreaker(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	matches := s.findBackends(id)
	if len(matches) == 0 {
		writeError(w, http.StatusNotFound, codeNotFound, "no backend with id "+id+"; circuit breakers are per backend, see GET /admin/v1/backends")
		return
	}
	cb := matches[0].Breaker()
	if cb == nil {
		writeError(w, http.StatusConflict, codeConflict, "the circuit breaker is disabled for backend "+id)
		return
	}
	dry := dryRun(r)
	prev := cb.State()
	if !dry {
		prev = cb.Reset()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": "circuit_breaker.reset", "dry_run": dry,
		"id": id, "route": matches[0].Route(), "target": matches[0].Label(),
		"previous_state": prev.String(), "state": "closed",
	})
}

// rateLimitClient is a client resolved from the {client} path segment.
type rateLimitClient struct {
	label string // as given: never a raw API key
	key   string // what the limiter keys on
	tier  string
}

// resolveClient maps the {client} path segment to the limiter's key and
// the client's tier. Clients are named the way /metrics names them: an
// API key by its fingerprint ("key:<12 hex>"), so a key never has to
// appear in a URL; "jwt:<id>" or "mtls:<identity>" for token and
// certificate clients; otherwise the IP or header value itself.
// ?tier= overrides the tier, which matters for JWT and certificate
// clients whose tier comes from the credential.
func resolveClient(cfg *config.Config, label, tierParam string) (rateLimitClient, int, string) {
	c := rateLimitClient{label: label, key: label, tier: "default"}
	switch {
	case strings.HasPrefix(label, "jwt:"), strings.HasPrefix(label, "mtls:"):
	case cfg.RateLimit.Scope == "api_key":
		if !strings.HasPrefix(label, "key:") {
			return c, http.StatusBadRequest, "with rate_limit.scope api_key, name the client by its API key fingerprint (key:<12 hex chars>, as in /metrics), never the key itself"
		}
		found := false
		for _, k := range knownAPIKeys(cfg) {
			if middleware.APIKeyFingerprint(k) == label {
				c.key, found = k, true
				break
			}
		}
		if !found {
			return c, http.StatusNotFound, "no configured API key has fingerprint " + label
		}
		if t, ok := cfg.RateLimit.Clients[c.key]; ok {
			c.tier = t
		}
	default:
		if t, ok := cfg.RateLimit.Clients[label]; ok {
			c.tier = t
		}
	}
	if tierParam != "" {
		if _, ok := cfg.RateLimit.Tiers[tierParam]; !ok {
			return c, http.StatusBadRequest, "no rate_limit tier named " + tierParam
		}
		c.tier = tierParam
	}
	return c, 0, ""
}

func knownAPIKeys(cfg *config.Config) []string {
	keys := append([]string(nil), cfg.Auth.APIKeys...)
	for k := range cfg.RateLimit.Clients {
		keys = append(keys, k)
	}
	return keys
}

func (s *Server) inspector(w http.ResponseWriter, r *http.Request) (rateLimitClient, ratelimiter.Inspector, bool) {
	c, status, msg := resolveClient(s.gw.Config(), r.PathValue("client"), r.URL.Query().Get("tier"))
	if status != 0 {
		code := codeBadRequest
		if status == http.StatusNotFound {
			code = codeNotFound
		}
		writeError(w, status, code, msg)
		return c, nil, false
	}
	l, ok := s.gw.Limiter(c.tier)
	if !ok {
		l, _ = s.gw.Limiter("default")
	}
	in, err := ratelimiter.Inspect(l)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "this rate limiter can't be inspected")
		return c, nil, false
	}
	return c, in, true
}

func quota(c rateLimitClient, algorithm string, res ratelimiter.Result) map[string]any {
	return map[string]any{
		"client": c.label, "tier": c.tier, "algorithm": algorithm,
		"limit": res.Limit, "remaining": res.Remaining, "allowed": res.Allowed,
		"retry_after_seconds": math.Ceil(res.RetryAfter.Seconds()),
	}
}

func (s *Server) getRateLimit(w http.ResponseWriter, r *http.Request) {
	c, in, ok := s.inspector(w, r)
	if !ok {
		return
	}
	res, err := in.Peek(r.Context(), c.key)
	if err != nil {
		writeError(w, http.StatusBadGateway, codeInternal, "reading rate limit state failed (is the store reachable?)")
		return
	}
	writeJSON(w, http.StatusOK, quota(c, s.gw.Config().RateLimit.Algorithm, res))
}

func (s *Server) resetRate(w http.ResponseWriter, r *http.Request) {
	c, in, ok := s.inspector(w, r)
	if !ok {
		return
	}
	dry := dryRun(r)
	if !dry {
		if err := in.Reset(r.Context(), c.key); err != nil {
			writeError(w, http.StatusBadGateway, codeInternal, "resetting rate limit state failed (is the store reachable?)")
			return
		}
	}
	res, err := in.Peek(r.Context(), c.key)
	if err != nil {
		writeError(w, http.StatusBadGateway, codeInternal, "reading rate limit state failed (is the store reachable?)")
		return
	}
	resp := quota(c, s.gw.Config().RateLimit.Algorithm, res)
	resp["action"], resp["dry_run"] = "ratelimit.reset", dry
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) cacheStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.gw.Cache().Stats())
}

// purgeRequest is the body of POST /admin/v1/cache/purge. Purging
// everything has to be asked for explicitly with "all": true, so an
// empty body can never wipe the cache.
type purgeRequest struct {
	All       bool   `json:"all"`
	Route     string `json:"route"`
	URLPrefix string `json:"url_prefix"`
}

func (s *Server) purgeCache(w http.ResponseWriter, r *http.Request) {
	var req purgeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	filtered := req.Route != "" || req.URLPrefix != ""
	switch {
	case req.All && filtered:
		writeError(w, http.StatusBadRequest, codeBadRequest, `"all" can't be combined with "route" or "url_prefix"`)
		return
	case !req.All && !filtered:
		writeError(w, http.StatusBadRequest, codeBadRequest, `say what to purge: {"route": ...}, {"url_prefix": ...}, or {"all": true}`)
		return
	}
	dry := dryRun(r)
	n, err := s.gw.Cache().Purge(r.Context(), cache.PurgeFilter{Route: req.Route, URLPrefix: req.URLPrefix}, dry)
	if err != nil {
		writeError(w, http.StatusBadGateway, codeInternal, "purge stopped after "+strconv.Itoa(n)+" entries: the store failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": "cache.purge", "dry_run": dry, "purged": n,
		"filter": req,
	})
}

func (s *Server) reloadConfig(w http.ResponseWriter, r *http.Request) {
	if dryRun(r) {
		if err := s.gw.ValidateConfigFile(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, codeInvalidConfig, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"action": "reload", "dry_run": true, "valid": true})
		return
	}
	err := s.reload()
	// Like SIGHUP, re-read the admin certificate whether or not the
	// config was accepted; a failure keeps the old one (and is logged).
	_ = s.ReloadCertificates()
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeInvalidConfig, "reload rejected, still serving the previous config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": "reload", "dry_run": false, "reloaded": true,
		"config_loaded_at": s.gw.ConfigLoadedAt().UTC(), "routes": len(s.gw.Config().Routes),
	})
}
