// Package gateway assembles Gatekeeper's request-handling pipeline —
// routes, rate-limit rules, client tiers, algorithm selection, auth and
// CORS settings — from a config.Config, and lets that pipeline be rebuilt
// and swapped atomically at runtime. A SIGHUP-triggered config reload
// therefore takes effect without dropping in-flight requests or
// restarting the process.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/cache"
	"gatekeeper/internal/config"
	"gatekeeper/internal/fault"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/proxy"
	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/split"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket"
)

// Gateway is an http.Handler whose behaviour is derived from a
// config.Config that can be reloaded at runtime. The live pipeline is
// held in an atomic pointer: ServeHTTP reads it without locking, and
// Reload swaps in a freshly built one with a single store, so every
// request runs entirely on the old config or entirely on the new one —
// never a mix of the two.
type Gateway struct {
	store   store.Store
	cache   *cache.Cache
	metrics *metrics.Metrics
	logger  *log.Logger

	// wsHub tracks proxied WebSocket connections. Like the store, it
	// outlives every reload: a connection opened under one config keeps
	// counting toward its route's limits after the next, and Shutdown
	// reaches it either way.
	wsHub *websocket.Hub

	// backends tracks every load-balanced backend for /metrics; like
	// wsHub it outlives reloads. router is the live router, kept so the
	// next reload can share unchanged backends with it and drain the
	// removed ones.
	backends *lb.Registry
	router   atomic.Pointer[proxy.Router]

	// splits holds the live traffic splits. Like backends it outlives
	// reloads, so weights an operator set, a rollout's progress, and
	// rollbacks survive a reload that leaves a route's split alone.
	splits *split.Registry

	// faults holds the fault injection rules. It outlives reloads, so a
	// rule's max_duration counts from when it came into force, not from
	// the last reload, and rules added through the admin API survive one.
	faults *fault.Registry

	configPath string

	reloadMu sync.Mutex // serialises Reload against itself
	pipeline atomic.Pointer[http.Handler]
	current  atomic.Pointer[config.Config]
	limiters atomic.Pointer[map[string]ratelimiter.Limiter]
	loadedAt atomic.Pointer[time.Time] // when current was loaded

	// access is the current config's compiled access control; nil when
	// none is configured.
	access atomic.Pointer[accesscontrol.Controller]
	// accessLog rate limits access control log lines. It outlives
	// reloads, so a reload mid-flood doesn't reset the limit.
	accessLog *accesscontrol.LogThrottle
	// validationLog does the same for the log lines of requests that
	// fail OpenAPI validation.
	validationLog *accesscontrol.LogThrottle

	// tracer is the tracing pipeline the current request pipeline uses.
	// It's rebuilt on Reload only when the tracing section changed.
	tracer      atomic.Pointer[tracing.Provider]
	tracingOpts []tracing.Option

	retiringMu sync.Mutex
	retiring   map[*tracing.Provider]*time.Timer
}

// Option customises a Gateway.
type Option func(*Gateway)

// WithTracingOptions passes options to every tracing provider the
// gateway builds — used by tests to attach an in-memory span recorder.
func WithTracingOptions(opts ...tracing.Option) Option {
	return func(g *Gateway) { g.tracingOpts = append(g.tracingOpts, opts...) }
}

// retireDelay is how long a tracing provider replaced by a reload keeps
// running, so requests already in flight on the old pipeline can still
// finish and export their spans.
const retireDelay = 15 * time.Second

// New builds a Gateway serving cfg, which must already have been loaded
// (and validated) from configPath. The store and metrics collectors are
// created once by the caller and reused across every reload — only the
// config-derived pieces (router, limiters, middleware chain) are rebuilt
// when Reload runs.
func New(cfg *config.Config, configPath string, st store.Store, m *metrics.Metrics, logger *log.Logger, opts ...Option) (*Gateway, error) {
	if logger == nil {
		logger = log.Default()
	}
	g := &Gateway{
		store:      st,
		cache:      cache.New(st),
		metrics:    m,
		logger:     logger,
		configPath: configPath,
		wsHub:      websocket.NewHub(m),
		backends:   lb.NewRegistry(),
		retiring:   map[*tracing.Provider]*time.Timer{},
		accessLog:  accesscontrol.NewLogThrottle(logger, accessLogInterval, accessLogBurst),

		validationLog: accesscontrol.NewLogThrottle(logger, accessLogInterval, accessLogBurst),
	}
	g.splits = split.NewRegistry(split.WithEvents(g.onSplitEvent))
	g.faults = fault.NewRegistry(fault.WithEvents(g.onFaultEvent))
	if m != nil {
		m.SetBackendSource(g.backends.Snapshot)
		m.SetActiveBansSource(g.activeBans)
		m.SetVariantWeightSource(g.variantWeights)
		m.SetFaultSource(g.faultRoutes)
	}
	for _, opt := range opts {
		opt(g)
	}
	tp, err := g.newTracer(cfg)
	if err != nil {
		return nil, err
	}
	b, err := g.build(cfg, tp, nil)
	if err != nil {
		_ = tp.Shutdown(context.Background())
		return nil, err
	}
	g.install(cfg, b, tp)
	return g, nil
}

// install makes b, built from cfg, the live pipeline.
func (g *Gateway) install(cfg *config.Config, b *built, tp *tracing.Provider) {
	g.pipeline.Store(&b.handler)
	g.router.Store(b.router)
	g.current.Store(cfg)
	g.limiters.Store(&b.limiters)
	g.access.Store(b.access)
	g.splits.Commit(b.router.SplitRoutes())
	g.configureFaults(cfg)
	g.tracer.Store(tp)
	now := time.Now()
	g.loadedAt.Store(&now)
}

// Close stops background work tied to the current config — active
// health checks on backends, and fault rules' expiry timer. Call it on
// shutdown.
func (g *Gateway) Close() {
	if r := g.router.Load(); r != nil {
		r.Close()
	}
	g.faults.Close()
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

// ConfigPath returns the path of the config file Reload reads.
func (g *Gateway) ConfigPath() string { return g.configPath }

// ConfigLoadedAt returns when the config currently served was loaded:
// startup, or the last successful Reload.
func (g *Gateway) ConfigLoadedAt() time.Time { return *g.loadedAt.Load() }

// ValidateConfigFile loads and validates the config file Reload would
// read, without applying it.
func (g *Gateway) ValidateConfigFile() error {
	_, err := config.Load(g.configPath)
	return err
}

// Limiter returns the live rate limiter for tier.
func (g *Gateway) Limiter(tier string) (ratelimiter.Limiter, bool) {
	l, ok := (*g.limiters.Load())[tier]
	return l, ok
}

// AccessControl returns the current config's compiled access control,
// or nil when none is configured.
func (g *Gateway) AccessControl() *accesscontrol.Controller { return g.access.Load() }

// Cache returns the response cache, shared by every config.
func (g *Gateway) Cache() *cache.Cache { return g.cache }

// Backends returns every load-balanced backend, including any still
// draining after a reload removed them.
func (g *Gateway) Backends() []*lb.Backend { return g.backends.Backends() }

// Tracer returns the tracing provider the current pipeline uses (a
// disabled one when tracing is off).
func (g *Gateway) Tracer() *tracing.Provider { return g.tracer.Load() }

// ShutdownWebSockets closes every proxied WebSocket connection
// gracefully — a Close frame to both sides, then up to ctx's deadline for
// the closing handshake — and refuses new ones from then on.
// http.Server.Shutdown doesn't cover these: once upgraded, a connection
// is hijacked and no longer tracked by the server. Connections still open
// when ctx is done are dropped, and ctx's error is returned.
func (g *Gateway) ShutdownWebSockets(ctx context.Context) error {
	return g.wsHub.Shutdown(ctx)
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

	old := g.tracer.Load()
	tp := old
	if !reflect.DeepEqual(cfg.Tracing, old.Config()) {
		if tp, err = g.newTracer(cfg); err != nil {
			return err
		}
	}
	oldRouter := g.router.Load()
	b, err := g.build(cfg, tp, oldRouter)
	if err != nil {
		if tp != old {
			_ = tp.Shutdown(context.Background())
		}
		return err
	}
	// Backends shared with the old router pick up their new settings now,
	// right before the swap; backends the new config dropped drain behind
	// it — in-flight requests finish, new ones go elsewhere.
	b.router.Activate()
	g.install(cfg, b, tp)
	oldRouter.Retire(b.router)
	if tp != old {
		g.retire(old)
	}
	return nil
}

// ShutdownTracing flushes buffered spans and stops every tracing
// provider (including any a reload replaced and is about to retire),
// waiting at most until ctx is done. Call it after the HTTP server has
// drained, so the last requests' spans are exported too.
func (g *Gateway) ShutdownTracing(ctx context.Context) error {
	g.retiringMu.Lock()
	providers := []*tracing.Provider{g.tracer.Load()}
	for p, timer := range g.retiring {
		timer.Stop()
		providers = append(providers, p)
	}
	g.retiring = map[*tracing.Provider]*time.Timer{}
	g.retiringMu.Unlock()

	var errs []error
	for _, p := range providers {
		errs = append(errs, p.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

func (g *Gateway) newTracer(cfg *config.Config) (*tracing.Provider, error) {
	tp, err := tracing.New(context.Background(), cfg.Tracing, g.logger, g.tracingOpts...)
	if err != nil {
		return nil, err
	}
	if tp.Enabled() {
		g.logger.Printf("tracing: enabled (%s)", tp.Description())
	}
	return tp, nil
}

// retire shuts p down after retireDelay.
func (g *Gateway) retire(p *tracing.Provider) {
	if !p.Enabled() {
		return
	}
	g.retiringMu.Lock()
	defer g.retiringMu.Unlock()
	g.retiring[p] = time.AfterFunc(retireDelay, func() {
		g.retiringMu.Lock()
		delete(g.retiring, p)
		g.retiringMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
}

// build assembles the reverse proxy and middleware chain for cfg. It
// touches nothing on g, so a failure part-way through leaves the active
// pipeline untouched.
// prev, if non-nil, is the live router being replaced; the new router is
// then built to share its unchanged backends and isn't live until
// Activate. On error, nothing live has been touched.
func (g *Gateway) build(cfg *config.Config, tp *tracing.Provider, prev *proxy.Router) (*built, error) {
	opts := []proxy.Option{
		proxy.WithWebSocketHub(g.wsHub), proxy.WithBackendRegistry(g.backends), proxy.WithTransformConfig(cfg.Transform),
		proxy.WithSplitRegistry(g.splits), proxy.WithAPIKeyHeader(cfg.Auth.Header),
		proxy.WithFaultRegistry(g.faults), proxy.WithMetricsPath(cfg.Metrics.Path),
		proxy.WithValidationLog(g.validationLog),
	}
	if prev != nil {
		opts = append(opts, proxy.WithPrevious(prev))
	}
	router, err := proxy.NewRouter(cfg.Routes, cfg.Proxy, g.metrics, g.cache, opts...)
	if err != nil {
		return nil, err
	}

	limiters, err := buildLimiters(cfg, g.store)
	if err != nil {
		router.Discard()
		return nil, err
	}

	auth, err := middleware.Auth(cfg.Auth, router.AuthModeFor, g.metrics)
	if err != nil {
		router.Discard()
		return nil, err
	}
	if !cfg.Auth.Enabled && routesAcceptJWT(cfg.Routes) {
		g.logger.Printf("auth: auth.enabled is false, so routes with auth_mode jwt or either are NOT protected")
	}

	access, err := buildAccessControl(cfg, g.store)
	if err != nil {
		router.Discard()
		return nil, err
	}
	g.logAccessControl(cfg)
	g.logTrafficSplits(router.SplitRoutes())

	mws := []middleware.Middleware{middleware.RequestMetrics(g.metrics, router.RouteLabelFor)}
	if access != nil {
		// As early as possible, so a blocked address costs one list
		// lookup: no request ID, no per-request log line, and nothing
		// from auth, the rate limiter (no tokens), the cache, the circuit
		// breaker, or a backend.
		mws = append(mws, middleware.AccessControl(access, router.RouteLabelFor,
			middleware.WithAccessMetrics(g.metrics), middleware.WithAccessLog(g.accessLog)))
	}
	h := middleware.Chain(router, append(mws,
		// Early, so every response — 401s and 429s included — carries it.
		middleware.RequestID(cfg.Transform.RequestID),
		middleware.RequestLogger(g.logger),
		middleware.WebSocketHandshake(router.RouteLabelFor),
		middleware.CORS(cfg.CORS),
		auth,
		middleware.RateLimit(cfg.RateLimit, limiters, g.metrics, middleware.WithStoreType(cfg.Storage.Backend)),
	)...)
	// Outermost, so the server span covers the whole request and every
	// stage below can start its span from it. A no-op when disabled.
	h = tp.Handler(h, router.RouteLabelFor)
	return &built{handler: h, router: router, limiters: limiters, access: access}, nil
}

// built is everything build derives from one config.
type built struct {
	handler  http.Handler
	router   *proxy.Router
	limiters map[string]ratelimiter.Limiter
	access   *accesscontrol.Controller
}

func routesAcceptJWT(routes []config.Route) bool {
	for _, rt := range routes {
		if mode := rt.EffectiveAuthMode(); mode == config.AuthModeJWT || mode == config.AuthModeEither {
			return true
		}
	}
	return false
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
