// Package proxy implements Gatekeeper's reverse-proxy core: routing
// incoming requests to configured backend services by path prefix or
// hostname and forwarding them with net/http/httputil.ReverseProxy, or —
// for WebSocket upgrade requests — through a frame relay (see
// websocket.go).
package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/cache"
	"gatekeeper/internal/circuitbreaker"
	"gatekeeper/internal/config"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket"
)

// route is a config.Route compiled into a ready-to-use reverse proxy
// over its pool of backends.
type route struct {
	pathPrefix string
	host       string
	proxy      *httputil.ReverseProxy
	label      string

	// pool holds the route's backends — exactly one for a route
	// configured with a single target — and picks one per attempt.
	pool *lb.Pool

	// cacheTarget identifies the route's backends in response cache keys:
	// for a single target, the target exactly as before load balancing
	// existed (so cached entries stay valid across the upgrade); for a
	// pool, every target.
	cacheTarget string

	cacheEnabled bool
	cacheTTL     time.Duration

	authMode string

	// handshakeTimeout bounds the WebSocket handshake with the backend
	// (dial + upgrade request + 101 response): proxy.timeout, applied
	// once, since an upgrade is never retried.
	handshakeTimeout time.Duration

	ws wsSettings
}

// Router dispatches requests to the backend whose route matches, based
// on hostname first and then longest-matching path prefix.
type Router struct {
	routes   []route
	cache    *cache.Cache
	metrics  *metrics.Metrics
	hub      *websocket.Hub
	registry *lb.Registry
	backends *lb.Set
	prev     *Router
}

// Option customises a Router built by NewRouter.
type Option func(*Router)

// WithWebSocketHub makes the router track its WebSocket connections in
// hub instead of a private one. The gateway passes one long-lived hub to
// every router it builds, so connection limits and graceful shutdown
// span config reloads.
func WithWebSocketHub(hub *websocket.Hub) Option {
	return func(r *Router) { r.hub = hub }
}

// WithBackendRegistry records the router's backends in reg, which feeds
// the per-backend /metrics gauges. The gateway passes one long-lived
// registry to every router it builds.
func WithBackendRegistry(reg *lb.Registry) Option {
	return func(r *Router) { r.registry = reg }
}

// WithPrevious builds the router as the replacement for prev (a config
// reload). Backends whose route and target are unchanged are shared with
// prev — keeping their health, circuit breaker, and in-flight count —
// and the new router isn't live until Activate; see also Discard and
// Retire.
func WithPrevious(prev *Router) Option {
	return func(r *Router) { r.prev = prev }
}

// NewRouter compiles cfg's routes into a Router. It fails fast on a
// malformed target URL, so a typo in config shows up at startup instead
// of on whatever request happens to hit it first.
//
// proxyCfg controls the per-attempt timeout and retry/backoff policy
// applied to every backend call. m, if non-nil, receives retry-attempt,
// outcome, cache hit/miss, and per-backend metrics; it may be nil in
// tests that don't care about metrics.
//
// respCache, if non-nil, backs GET response caching for routes whose
// config enables it (see config.RouteCache); a nil respCache disables
// caching entirely regardless of per-route config, which is what tests
// that don't care about caching should pass.
//
// Each route's backends form a load-balanced pool (a single target is a
// pool of one). Without WithPrevious the router is live immediately —
// active health checks start — and should be Closed when discarded.
//
// WebSocket upgrade requests are proxied too (see websocket.go); without
// WithWebSocketHub, the router tracks them in a hub of its own.
func NewRouter(routes []config.Route, proxyCfg config.ProxyConfig, m *metrics.Metrics, respCache *cache.Cache, opts ...Option) (*Router, error) {
	r := &Router{cache: respCache, metrics: m}
	for _, opt := range opts {
		opt(r)
	}
	if r.hub == nil {
		r.hub = websocket.NewHub(m)
	}
	if r.registry == nil {
		r.registry = lb.NewRegistry()
		if m != nil {
			m.SetBackendSource(r.registry.Snapshot)
		}
	}
	var prevSet *lb.Set
	if r.prev != nil {
		prevSet = r.prev.backends
	}
	r.backends = lb.NewSet(r.registry, prevSet, log.Default())

	for _, rt := range routes {
		label := routeLabel(rt)
		pool, cacheTarget, err := r.buildPool(rt, label, m)
		if err != nil {
			r.backends.Discard()
			return nil, err
		}
		proxy := &httputil.ReverseProxy{
			Director:     director,
			ErrorHandler: errorHandler(label),
			Transport:    newRetryTransport(proxyCfg, m, label, pool),
		}
		r.routes = append(r.routes, route{
			pathPrefix:       rt.PathPrefix,
			host:             rt.Host,
			proxy:            proxy,
			label:            label,
			pool:             pool,
			cacheTarget:      cacheTarget,
			cacheEnabled:     rt.Cache.IsEnabled(),
			cacheTTL:         rt.Cache.TTL.Duration,
			authMode:         rt.EffectiveAuthMode(),
			handshakeTimeout: proxyCfg.Timeout.Duration,
			ws:               newWSSettings(rt),
		})
	}
	if r.prev == nil {
		r.backends.Activate()
	}
	r.prev = nil
	return r, nil
}

// buildPool builds rt's backend pool, reusing backends from the router
// being replaced where possible.
func (r *Router) buildPool(rt config.Route, label string, m *metrics.Metrics) (*lb.Pool, string, error) {
	single := len(rt.Backends) == 0
	var backends []*lb.Backend
	var targets []string
	for _, bc := range rt.EffectiveBackends() {
		target, err := url.Parse(bc.Target)
		if err != nil {
			return nil, "", fmt.Errorf("proxy: invalid target %q: %w", bc.Target, err)
		}
		bc := bc
		b, err := r.backends.Backend(label, target, func(prev *lb.Settings) (lb.Settings, error) {
			tlsCfg, err := newBackendTLSConfig(label, bc.Target, *bc.BackendTLS)
			if err != nil {
				return lb.Settings{}, err
			}
			var transport http.RoundTripper = http.DefaultTransport
			if tlsCfg != nil {
				// Only the innermost transport changes, so retries,
				// timeouts, and the circuit breaker wrap TLS backends
				// exactly as plain ones.
				transport = newBackendTransport(tlsCfg)
			}
			cb, key := newBreaker(rt, label, single, m, prev)
			return lb.Settings{
				Weight: bc.Weight, Transport: transport, TLSConfig: tlsCfg,
				Breaker: cb, BreakerKey: key, DrainTimeout: rt.EffectiveDrainTimeout(),
			}, nil
		})
		if err != nil {
			return nil, "", err
		}
		backends = append(backends, b)
		targets = append(targets, target.String())
	}

	hc := rt.HealthCheck
	if hc.Enabled {
		hc = hc.WithDefaults()
	}
	pool := lb.NewPool(lb.PoolConfig{
		Route:          label,
		Strategy:       rt.EffectiveLBStrategy(),
		HashHeader:     rt.LBHashHeader,
		PassiveEnabled: rt.PassiveHealthEnabled(),
		Passive:        rt.PassiveHealthCheck.WithDefaults(),
		HealthCheck:    hc,
	}, backends, m, log.Default())
	r.backends.AddPool(pool)
	return pool, strings.Join(targets, ","), nil
}

// Activate puts a router built WithPrevious into service: settings
// staged for shared backends take effect and health checks start. Call
// it right before swapping the router in.
func (r *Router) Activate() { r.backends.Activate() }

// Discard abandons a router built WithPrevious that never went live
// (the rest of a reload failed). Shared backends are left untouched.
func (r *Router) Discard() { r.backends.Discard() }

// Retire takes the router out of service in favour of next: its health
// checks stop, and every backend next doesn't share drains — it gets no
// new requests, and in-flight ones get the route's drain_timeout to
// finish before being cancelled.
func (r *Router) Retire(next *Router) {
	var nextSet *lb.Set
	if next != nil {
		nextSet = next.backends
	}
	r.backends.Retire(nextSet)
}

// Close stops the router's health checks and forgets its backends
// (shutdown).
func (r *Router) Close() { r.backends.Close() }

// routeLabel identifies a route for metrics purposes: its path prefix,
// or its host if it has no path prefix.
func routeLabel(rt config.Route) string {
	if rt.PathPrefix != "" {
		return rt.PathPrefix
	}
	return rt.Host
}

// newBreaker returns the circuit breaker for one of rt's backends (nil
// if circuit breaking shouldn't apply) and a key identifying its
// configuration. A backend reused across a reload keeps its breaker —
// and so its state — when that key is unchanged.
//
// Besides the route's own opt-out, a zero FailureThreshold also disables
// it — which is what a config.Route built directly in a test (bypassing
// config.Load's defaulting) gets by default, so existing tests that don't
// care about circuit breaking see no behavior change without having to
// opt out explicitly.
//
// Breakers are per backend, so one failing backend never trips its
// siblings. For a single-target route the breaker also keeps reporting
// gatekeeper_circuit_breaker_state{route}, as it always has; pooled
// backends report gatekeeper_backend_circuit_breaker_state instead.
func newBreaker(rt config.Route, label string, single bool, m *metrics.Metrics, prev *lb.Settings) (*circuitbreaker.CircuitBreaker, string) {
	cb := rt.CircuitBreaker
	if !cb.IsEnabled() || cb.FailureThreshold <= 0 {
		return nil, ""
	}
	cfg := circuitbreaker.Config{
		FailureThreshold:    cb.FailureThreshold,
		OpenDuration:        cb.OpenDuration.Duration,
		HalfOpenMaxRequests: cb.HalfOpenMaxRequests,
		SuccessesToClose:    cb.HalfOpenSuccessesToClose,
		FailuresToReopen:    cb.HalfOpenFailuresToReopen,
	}
	key := fmt.Sprintf("%+v single=%t", cfg, single)
	if prev != nil && prev.Breaker != nil && prev.BreakerKey == key {
		return prev.Breaker, key
	}
	var routeGauge *metrics.Metrics
	if single {
		routeGauge = m
	}
	return circuitbreaker.New(cfg, routeGauge, label), key
}

// director prepares the outgoing request without choosing a backend:
// the path and query stay as the client sent them, and the retry
// transport points each attempt at the backend it picks (see
// rewriteToBackend).
func director(req *http.Request) {
	if _, ok := req.Header["User-Agent"]; !ok {
		// Stop net/http from adding its default User-Agent.
		req.Header.Set("User-Agent", "")
	}
}

// rewriteToBackend points req at target the same way
// httputil.NewSingleHostReverseProxy does: target's scheme and host,
// target's base path joined with the request path, and target's query
// merged with the request's.
func rewriteToBackend(req *http.Request, target *url.URL) {
	targetQuery := target.RawQuery
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
	if targetQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = targetQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	apath := a.EscapedPath()
	bpath := b.EscapedPath()
	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

// ServeHTTP implements http.Handler, dispatching to the first matching
// route's reverse proxy.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rt := r.match(req)
	if rt == nil {
		http.Error(w, "no backend route configured for this request", http.StatusNotFound)
		return
	}

	// Checked before caching and before the retry transport: an upgrade
	// is never served from (or stored in) the cache and never retried.
	if websocket.IsUpgrade(req) {
		r.serveWebSocket(w, req, rt)
		return
	}

	if r.cacheableRequest(rt, req) {
		r.serveWithCache(w, req, rt)
		return
	}
	rt.proxy.ServeHTTP(w, req)
}

// AuthModeFor returns the auth mode of the route req will be dispatched
// to, using the same matching rules as ServeHTTP so the auth middleware
// and the router can never disagree about which route applies. A request
// that matches no route gets the default api_key mode; the router will
// answer it with 404 anyway once it's past auth.
func (r *Router) AuthModeFor(req *http.Request) string {
	if rt := r.match(req); rt != nil {
		return rt.authMode
	}
	return config.AuthModeAPIKey
}

// RouteLabelFor returns the metrics label of the route req will be
// dispatched to, using the same matching rules as ServeHTTP. ok is false
// if no route matches.
func (r *Router) RouteLabelFor(req *http.Request) (label string, ok bool) {
	if rt := r.match(req); rt != nil {
		return rt.label, true
	}
	return "", false
}

// cacheableRequest reports whether req against rt should even consult
// the cache: a response cache is configured, the route hasn't opted
// out, only GET is ever cached (a write verb has no business being
// served stale), and the caller hasn't asked to bypass it.
func (r *Router) cacheableRequest(rt *route, req *http.Request) bool {
	return r.cache != nil && rt.cacheEnabled && req.Method == http.MethodGet && !cache.Bypass(req)
}

// serveWithCache serves req from the cache when possible, falling back
// to the backend on a miss (or on a cache read failure — a store
// problem degrades to "always go to the backend", never to a crash) and
// storing the fresh response for next time, unless the backend marked it
// Cache-Control: no-store.
func (r *Router) serveWithCache(w http.ResponseWriter, req *http.Request, rt *route) {
	ctx := req.Context()
	key := cache.Key(rt.label, rt.cacheTarget, req)

	_, span := tracing.Start(ctx, tracing.SpanCacheLookup, trace.WithAttributes(tracing.AttrHTTPRoute.String(rt.label)))
	entry, hit, err := r.cache.Get(ctx, key)
	span.SetAttributes(tracing.AttrCacheHit.Bool(hit))
	if err != nil {
		span.SetAttributes(tracing.AttrErrorType.String("store_error"))
		tracing.Fail(span, "cache read failed")
		log.Printf("cache: read failed for route %s, bypassing cache: %v", rt.label, err)
	}
	span.End()
	if hit {
		r.recordCache(rt.label, true)
		writeCachedEntry(w, entry)
		return
	}
	r.recordCache(rt.label, false)

	rec := newResponseRecorder()
	rt.proxy.ServeHTTP(rec, req)

	if rec.statusCode == http.StatusOK && cache.Storable(rec.Header()) {
		fresh := &cache.Entry{
			StatusCode: rec.statusCode,
			Header:     rec.Header().Clone(),
			Body:       rec.body,
		}
		if err := r.cache.Set(ctx, key, fresh, rt.cacheTTL); err != nil {
			log.Printf("cache: write failed for route %s: %v", rt.label, err)
		}
	}

	rec.header.Set("X-Cache", "MISS")
	rec.flushTo(w)
}

func (r *Router) recordCache(routeLabel string, hit bool) {
	if r.metrics == nil {
		return
	}
	if hit {
		r.metrics.CacheHits.WithLabelValues(routeLabel).Inc()
	} else {
		r.metrics.CacheMisses.WithLabelValues(routeLabel).Inc()
	}
}

// writeCachedEntry replays a cached entry onto w exactly as captured.
func writeCachedEntry(w http.ResponseWriter, e *cache.Entry) {
	dst := w.Header()
	for k, v := range e.Header {
		dst[k] = v
	}
	dst.Set("X-Cache", "HIT")
	w.WriteHeader(e.StatusCode)
	_, _ = w.Write(e.Body)
}

// responseRecorder buffers a backend response in full so it can be
// inspected (status, headers, Cache-Control) before deciding whether to
// cache it and before writing anything to the real client connection.
type responseRecorder struct {
	header      http.Header
	body        []byte
	statusCode  int
	wroteHeader bool
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header), statusCode: http.StatusOK}
}

func (rec *responseRecorder) Header() http.Header { return rec.header }

func (rec *responseRecorder) WriteHeader(statusCode int) {
	if rec.wroteHeader {
		return
	}
	rec.statusCode = statusCode
	rec.wroteHeader = true
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	rec.body = append(rec.body, b...)
	return len(b), nil
}

// flushTo writes the buffered response to w, once the caller has
// decided (and, if applicable, finished acting on) what to do with it.
func (rec *responseRecorder) flushTo(w http.ResponseWriter) {
	dst := w.Header()
	for k, v := range rec.header {
		dst[k] = v
	}
	w.WriteHeader(rec.statusCode)
	_, _ = w.Write(rec.body)
}

// match picks the route to use for req. Hostname routes take priority
// over path-prefix routes; among path-prefix routes, the longest
// matching prefix wins so a more specific route (e.g. "/api/users/vip")
// beats a more general one (e.g. "/api/users").
func (r *Router) match(req *http.Request) *route {
	for i := range r.routes {
		if r.routes[i].host != "" && r.routes[i].host == req.Host {
			return &r.routes[i]
		}
	}

	var best *route
	for i := range r.routes {
		rt := &r.routes[i]
		if rt.pathPrefix == "" {
			continue
		}
		if !pathHasPrefix(req.URL.Path, rt.pathPrefix) {
			continue
		}
		if best == nil || len(rt.pathPrefix) > len(best.pathPrefix) {
			best = rt
		}
	}
	return best
}

func pathHasPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	return path[:len(prefix)] == prefix
}

// errCircuitOpen is returned by retryTransport.RoundTrip when every
// healthy backend's circuit breaker is Open (or its Half-Open trial
// slots are full) instead of ever calling a backend, so errorHandler can
// tell a fail-fast rejection apart from a real backend failure and
// answer 503 instead of 502.
var errCircuitOpen = errors.New("proxy: circuit breaker open")

// errNoHealthyBackend is returned when every backend of the route is
// unhealthy or draining: the request fails fast with 503 rather than
// waiting on a backend known to be down.
var errNoHealthyBackend = errors.New("proxy: no healthy backend available")

// backendError tags a transport error with the backend it came from.
type backendError struct {
	backend string
	err     error
}

func (e *backendError) Error() string { return "backend " + e.backend + ": " + e.err.Error() }
func (e *backendError) Unwrap() error { return e.err }

// errorHandler returns a ReverseProxy.ErrorHandler that logs the
// backend failure and answers with 502 instead of ReverseProxy's default
// bare "connection refused" text — callers get a stable, documented
// response for a backend outage instead of whatever the transport error
// happened to say. Fail-fast rejections, where no backend was contacted
// at all, get a 503 instead: an open circuit, or no healthy backend.
func errorHandler(routeLabel string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		switch {
		case errors.Is(err, errCircuitOpen):
			http.Error(w, "circuit breaker open: backend temporarily unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, errNoHealthyBackend):
			http.Error(w, "no healthy backend available", http.StatusServiceUnavailable)
			return
		}
		backend, cause := routeLabel, err
		var be *backendError
		if errors.As(err, &be) {
			backend, cause = be.backend, be.err
		}
		log.Printf("proxy: backend %s unreachable for %s %s: %v", backend, req.Method, req.URL.Path, cause)
		http.Error(w, "backend service unavailable", http.StatusBadGateway)
	}
}

// retryTransport sends each request to a backend of the route's pool
// with a per-attempt timeout, retries with exponential backoff and
// jitter, and per-backend circuit breakers. It retries on
// transport-level failures (timeouts, connection errors) and 5xx
// responses; a 4xx response is returned to the caller immediately since
// no amount of retrying fixes a client error. The same failure/success
// classification feeds the backend's circuit breaker and passive health
// check, so a persistently failing backend trips them the same way it
// would exhaust retries.
//
// The backend is chosen per attempt, and a retry prefers a healthy
// backend it hasn't tried yet — with a single backend, it simply tries
// that one again, as before load balancing existed.
//
// A single incoming request may cause several backend attempts, but
// this transport sits below the rate limiter middleware — it is only
// ever invoked once per admitted request — so retries (and circuit-open
// rejections) never cost the client extra rate-limit budget. See
// ProxyRetries / ProxyOutcomes / CircuitBreakerRejections for how these
// are reflected in /metrics separately from the raw allowed/rejected
// request counts.
type retryTransport struct {
	timeout time.Duration
	retry   config.RetryConfig
	metrics *metrics.Metrics
	route   string
	pool    *lb.Pool
}

func newRetryTransport(cfg config.ProxyConfig, m *metrics.Metrics, routeLabel string, pool *lb.Pool) *retryTransport {
	return &retryTransport{
		timeout: cfg.Timeout.Duration,
		retry:   cfg.Retry,
		metrics: m,
		route:   routeLabel,
		pool:    pool,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	bodyBytes, err := drainBody(req)
	if err != nil {
		return nil, err
	}

	maxAttempts := t.retry.MaxRetries + 1
	tried := make(map[*lb.Backend]bool, maxAttempts)
	var resp *http.Response
	var rtErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Chosen before backoff so a circuit that trips mid-retry (or is
		// already open on every backend) fails this and every remaining
		// attempt fast, without sleeping first and without ever reaching
		// a backend again — retrying into an already-open circuit
		// defeats the point of having one.
		b, err := t.pickBackend(req, tried, attempt)
		if err != nil {
			if errors.Is(err, errCircuitOpen) {
				t.recordCircuitRejection()
			}
			return nil, err
		}
		breaker := b.Breaker()

		if attempt > 1 {
			t.incRetries()
			if werr := waitBackoff(req.Context(), t.retry, attempt-1); werr != nil {
				if breaker != nil {
					breaker.Release()
				}
				t.recordOutcome(false)
				return nil, werr
			}
		}

		tried[b] = true
		release := b.Acquire()
		attemptReq := cloneRequestWithBody(req, bodyBytes)
		rewriteToBackend(attemptReq, b.Target())
		ctx, cancel := context.WithTimeout(req.Context(), t.timeout)
		// A backend removed by a reload cancels what's still running on
		// it once its drain timeout is up.
		stopDrainCancel := context.AfterFunc(b.Context(), cancel)
		// One client span per attempt, so retries show up in the trace;
		// the backend gets this attempt's span as its parent.
		ctx, span := tracing.Start(ctx, tracing.SpanBackendAttempt,
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(t.attemptAttributes(attemptReq, attempt, b)...))
		attemptReq = attemptReq.WithContext(ctx)
		tracing.Inject(ctx, attemptReq.Header)
		finish := func() {
			stopDrainCancel()
			cancel()
			release()
		}

		resp, rtErr = b.Settings().Transport.RoundTrip(attemptReq)
		last := attempt == maxAttempts

		if rtErr != nil {
			errType := tracing.ErrorType(rtErr)
			span.SetAttributes(tracing.AttrErrorType.String(errType))
			tracing.Fail(span, errType)
			span.End()
			finish()
			t.report(b, false)
			if last || req.Context().Err() != nil {
				t.recordOutcome(false)
				return nil, &backendError{backend: b.Label(), err: rtErr}
			}
			continue
		}

		span.SetAttributes(tracing.AttrHTTPStatus.Int(resp.StatusCode))
		if isRetryableStatus(resp.StatusCode) {
			span.SetAttributes(tracing.AttrErrorType.String(strconv.Itoa(resp.StatusCode)))
			tracing.Fail(span, http.StatusText(resp.StatusCode))
		}

		if isRetryableStatus(resp.StatusCode) && !last {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			span.End()
			finish()
			t.report(b, false)
			continue
		}

		// This is the response we're returning to the caller (success,
		// a 4xx we never retry, or a 5xx after exhausting retries).
		// ReverseProxy reads and closes resp.Body after RoundTrip
		// returns, so the attempt's context — its span, and its claim on
		// the backend — must stay alive until then.
		resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, finish: finish, span: span}
		t.report(b, !isRetryableStatus(resp.StatusCode))
		t.recordOutcome(resp.StatusCode < 500)
		return resp, nil
	}

	return resp, rtErr
}

// pickBackend chooses the backend for attempt, preferring one not
// already tried and skipping any whose circuit breaker refuses it.
func (t *retryTransport) pickBackend(req *http.Request, tried map[*lb.Backend]bool, attempt int) (*lb.Backend, error) {
	refused := map[*lb.Backend]bool{}
	for {
		b, err := t.pool.Pick(req,
			func(b *lb.Backend) bool { return tried[b] },
			func(b *lb.Backend) bool { return refused[b] })
		switch {
		case errors.Is(err, lb.ErrAllCircuitsOpen):
			return nil, errCircuitOpen
		case err != nil:
			return nil, errNoHealthyBackend
		}
		if b.Breaker() == nil || t.checkBreaker(req.Context(), attempt, b) {
			return b, nil
		}
		refused[b] = true
	}
}

// report records an attempt's outcome with the backend's circuit breaker
// (whose Allow it passed) and its passive health check.
func (t *retryTransport) report(b *lb.Backend, success bool) {
	if cb := b.Breaker(); cb != nil {
		cb.Report(success)
	}
	t.pool.Report(b, success)
}

func (t *retryTransport) recordCircuitRejection() {
	if t.metrics == nil {
		return
	}
	t.metrics.CircuitBreakerRejections.WithLabelValues(t.route).Inc()
}

func (t *retryTransport) incRetries() {
	if t.metrics == nil {
		return
	}
	t.metrics.ProxyRetries.WithLabelValues(t.route).Inc()
}

func (t *retryTransport) recordOutcome(success bool) {
	if t.metrics == nil {
		return
	}
	outcome := "failure"
	if success {
		outcome = "success"
	}
	t.metrics.ProxyOutcomes.WithLabelValues(t.route, outcome).Inc()
}

// isRetryableStatus reports whether status is a server error worth
// retrying. 4xx client errors are deliberately excluded.
func isRetryableStatus(status int) bool {
	return status >= 500 && status <= 599
}

// drainBody reads req's body fully into memory and closes the original,
// so it can be replayed unchanged on every retry attempt. Incoming
// request bodies generally can't be re-read from the network directly,
// so buffering is the price of being able to retry a request with a
// body at all.
func drainBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	defer req.Body.Close()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("proxy: reading request body for retry buffering: %w", err)
	}
	return b, nil
}

// cloneRequestWithBody clones req and attaches a fresh, independent
// reader over body so each retry attempt gets its own unconsumed copy.
func cloneRequestWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	if body == nil {
		clone.Body = http.NoBody
		clone.ContentLength = 0
		return clone
	}
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	clone.ContentLength = int64(len(body))
	return clone
}

// waitBackoff sleeps for the backoff delay before retry number
// retryNum (1 for the first retry, 2 for the second, ...), returning
// early with an error if ctx is cancelled first.
func waitBackoff(ctx context.Context, cfg config.RetryConfig, retryNum int) error {
	delay := backoffDelay(cfg, retryNum)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// backoffDelay computes the exponential backoff delay before retry
// number retryNum, doubling each time up to cfg.MaxBackoff, then
// applies full jitter (a random value between 0 and that cap) so many
// clients retrying at once don't hammer the backend in lockstep.
func backoffDelay(cfg config.RetryConfig, retryNum int) time.Duration {
	base := cfg.BaseBackoff.Duration
	max := cfg.MaxBackoff.Duration
	if base <= 0 {
		return 0
	}

	d := base
	for i := 1; i < retryNum && d < max; i++ {
		d *= 2
		if d <= 0 { // overflowed
			d = max
			break
		}
	}
	if d > max {
		d = max
	}
	if d <= 0 {
		return 0
	}

	return time.Duration(rand.Int63n(int64(d) + 1))
}

// cancelOnCloseBody wraps a response body so the per-attempt timeout
// context is cancelled when (and only when) the body is closed, once
// the caller has finished reading the response.
type cancelOnCloseBody struct {
	io.ReadCloser
	finish func()
	span   trace.Span
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.finish()
	b.span.End()
	return err
}

// checkBreaker asks b's circuit breaker whether attempt may proceed,
// recording the decision in a circuit_breaker.check span.
func (t *retryTransport) checkBreaker(ctx context.Context, attempt int, b *lb.Backend) bool {
	_, span := tracing.Start(ctx, tracing.SpanCircuitBreaker, trace.WithAttributes(
		tracing.AttrHTTPRoute.String(t.route),
		tracing.AttrBackend.String(b.Label()),
		tracing.AttrAttempt.Int(attempt),
	))
	defer span.End()
	allowed, state := b.Breaker().AllowState()
	span.SetAttributes(tracing.AttrBreakerState.String(state.String()), tracing.AttrBreakerAllowed.Bool(allowed))
	if !allowed {
		tracing.Fail(span, "circuit open")
	}
	return allowed
}

// attemptAttributes are the backend.attempt span's attributes: which
// backend the attempt goes to (scheme, host, port — never the path or
// query) and which attempt it is.
func (t *retryTransport) attemptAttributes(req *http.Request, attempt int, b *lb.Backend) []attribute.KeyValue {
	port := req.URL.Port()
	if port == "" {
		port = "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
	}
	portNum, _ := strconv.Atoi(port)
	return []attribute.KeyValue{
		tracing.AttrHTTPRoute.String(t.route),
		tracing.AttrBackend.String(b.Label()),
		tracing.AttrHTTPMethod.String(tracing.Method(req.Method)),
		tracing.AttrURLScheme.String(req.URL.Scheme),
		tracing.AttrServerAddress.String(req.URL.Hostname()),
		tracing.AttrServerPort.Int(portNum),
		tracing.AttrAttempt.Int(attempt),
		tracing.AttrRetry.Bool(attempt > 1),
	}
}
