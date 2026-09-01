// Package gateway assembles Gatekeeper's request-handling pipeline —
// routes, rate-limit rules, client tiers, algorithm selection, auth and
// CORS settings — from a config.Config, and lets that pipeline be rebuilt
// and swapped atomically at runtime. A SIGHUP-triggered config reload
// therefore takes effect without dropping in-flight requests or
// restarting the process.
package gateway

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/proxy"
	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/ratelimiter/store"
)

// Gateway is an http.Handler whose behaviour is derived from a
// config.Config that can be reloaded at runtime. The live pipeline is
// held in an atomic pointer: ServeHTTP reads it without locking, and
// Reload swaps in a freshly built one with a single store, so every
// request runs entirely on the old config or entirely on the new one —
// never a mix of the two.
type Gateway struct {
	store   store.Store
	metrics *metrics.Metrics
	logger  *log.Logger

	configPath string

	reloadMu sync.Mutex // serialises Reload against itself
	pipeline atomic.Pointer[http.Handler]
	current  atomic.Pointer[config.Config]
}

// New builds a Gateway serving cfg, which must already have been loaded
// (and validated) from configPath. The store and metrics collectors are
// created once by the caller and reused across every reload — only the
// config-derived pieces (router, limiters, middleware chain) are rebuilt
// when Reload runs.
func New(cfg *config.Config, configPath string, st store.Store, m *metrics.Metrics, logger *log.Logger) (*Gateway, error) {
	if logger == nil {
		logger = log.Default()
	}
	g := &Gateway{
		store:      st,
		metrics:    m,
		logger:     logger,
		configPath: configPath,
	}
	h, err := g.build(cfg)
	if err != nil {
		return nil, err
	}
	g.pipeline.Store(&h)
	g.current.Store(cfg)
	return g, nil
}

// ServeHTTP dispatches the request to the currently active pipeline.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*g.pipeline.Load()).ServeHTTP(w, r)
}

// Config returns the config the gateway is currently serving. The
// returned value must not be mutated.
func (g *Gateway) Config() *config.Config {
	return g.current.Load()
}

// Reload re-reads and validates the config file the gateway was started
// with, then atomically swaps the resulting pipeline into place. If the
// file is missing, malformed, or fails validation, the active pipeline is
// left untouched and the error is returned; callers should log it and
// keep serving with the existing config.
func (g *Gateway) Reload() error {
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()

	cfg, err := config.Load(g.configPath)
	if err != nil {
		return err
	}
	h, err := g.build(cfg)
	if err != nil {
		return err
	}
	g.pipeline.Store(&h)
	g.current.Store(cfg)
	return nil
}

// build assembles the reverse proxy and middleware chain for cfg. It
// touches nothing on g, so a failure part-way through leaves the active
// pipeline untouched.
func (g *Gateway) build(cfg *config.Config) (http.Handler, error) {
	router, err := proxy.NewRouter(cfg.Routes)
	if err != nil {
		return nil, err
	}

	limiters, err := buildLimiters(cfg, g.store)
	if err != nil {
		return nil, err
	}

	h := middleware.Chain(router,
		middleware.RequestLogger(g.logger),
		middleware.CORS(cfg.CORS),
		middleware.APIKeyAuth(cfg.Auth),
		middleware.RateLimit(cfg.RateLimit, limiters, g.metrics),
	)
	return h, nil
}

// buildLimiters creates one Limiter per configured tier, all sharing st
// so client counter state survives a reload instead of resetting.
func buildLimiters(cfg *config.Config, st store.Store) (map[string]ratelimiter.Limiter, error) {
	limiters := make(map[string]ratelimiter.Limiter, len(cfg.RateLimit.Tiers))
	for name, tier := range cfg.RateLimit.Tiers {
		rule := ratelimiter.Rule{Rate: tier.RequestsPerSecond, Burst: tier.Burst}
		limiter, err := ratelimiter.New(cfg.RateLimit.Algorithm, st, rule)
		if err != nil {
			return nil, fmt.Errorf("gateway: tier %q: %w", name, err)
		}
		limiters[name] = limiter
	}
	return limiters, nil
}
