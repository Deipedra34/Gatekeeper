package proxy

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/split"
	"gatekeeper/internal/transform"
)

// variant is one variant of a split route, compiled: its own backend
// pool, and a reverse proxy whose retries stay inside that pool.
type variant struct {
	name        string
	proxy       *httputil.ReverseProxy
	pool        *lb.Pool
	cacheTarget string
}

// WithSplitRegistry builds split routes through reg, so they carry their
// live state (weights, rollout, rollbacks) across config reloads. The
// gateway passes one long-lived registry to every router it builds and
// commits the router's split routes to it once the router is live.
func WithSplitRegistry(reg *split.Registry) Option {
	return func(r *Router) { r.splits = reg }
}

// WithAPIKeyHeader names the header API keys arrive in (auth.header),
// for traffic split stickiness by API key and override allowlists.
// Defaults to X-API-Key.
func WithAPIKeyHeader(name string) Option {
	return func(r *Router) { r.apiKeyHeader = name }
}

// buildVariants compiles a split route's variants: each is a pool of its
// own, built exactly like an unsplit route's, and a reverse proxy over
// it.
func (r *Router) buildVariants(rt config.Route, label string, proxyCfg config.ProxyConfig, m *metrics.Metrics) (*split.Route, []variant, error) {
	sr, err := r.splits.Build(label, *rt.TrafficSplit)
	if err != nil {
		return nil, nil, err
	}
	variants := make([]variant, len(rt.TrafficSplit.Variants))
	for i, vc := range rt.TrafficSplit.Variants {
		pool, cacheTarget, err := r.buildPool(rt.VariantRoute(i), label, m)
		if err != nil {
			return nil, nil, err
		}
		variants[i] = variant{
			name:        vc.Name,
			pool:        pool,
			cacheTarget: cacheTarget,
			proxy: &httputil.ReverseProxy{
				Director:     director,
				ErrorHandler: errorHandler(label),
				Transport:    newRetryTransport(proxyCfg, m, label, pool),
			},
		}
	}
	return sr, variants, nil
}

// SplitRoutes returns the router's split routes, for the gateway to
// commit to the registry once the router is live.
func (r *Router) SplitRoutes() []*split.Route {
	var out []*split.Route
	for i := range r.routes {
		if r.routes[i].split != nil {
			out = append(out, r.routes[i].split)
		}
	}
	return out
}

// splitClient collects what the split needs to know about req's client.
func (r *Router) splitClient(req *http.Request) split.Client {
	ctx := req.Context()
	c := split.Client{APIKey: req.Header.Get(r.apiKeyHeader)}
	if addr, ok := middleware.ClientAddrFrom(ctx); ok {
		c.IP = addr.String()
	} else {
		c.IP = transform.ClientIP(req, r.transformCfg.TrustForwardedHeaders)
	}
	if id, ok := middleware.IdentityFrom(ctx); ok {
		switch id.Method {
		case config.AuthModeJWT:
			c.JWTSubject = id.Client
		case config.AuthModeMTLS:
			c.CertID = id.Client
		}
	}
	if c.CertID == "" {
		if id, ok := middleware.ClientCertificateFrom(ctx); ok {
			c.CertID = id.Client
		}
	}
	if info, ok := middleware.ClientInfoFrom(ctx); ok {
		c.Tier = info.Tier
	}
	return c
}

// selectVariant picks req's variant on a split route and returns the
// route as that variant sees it — its pool, proxy, and cache identity —
// along with the writer to respond through, which records the outcome
// for the guardrails, and the request to forward: without the override
// header, unless the route forwards it.
func (r *Router) selectVariant(rt *route, w http.ResponseWriter, req *http.Request) (*route, http.ResponseWriter, *http.Request, func()) {
	d := rt.split.Select(req, r.splitClient(req))
	middleware.NoteVariant(req.Context(), rt.variants[d.Index].name)
	if h := rt.split.OverrideHeader(); !rt.split.ForwardOverrideHeader() && req.Header.Get(h) != "" {
		// Whether or not it was honoured, the backend never sees it:
		// it's the gateway's to interpret.
		out := req.Clone(req.Context())
		out.Header.Del(h)
		req = out
	}
	v := rt.variants[d.Index]
	if d.SetCookie != nil {
		http.SetCookie(w, d.SetCookie)
	}
	if h := rt.split.ResponseHeader(); h != "" {
		// Set before anything is written, so it reaches cached
		// responses and WebSocket 101s alike.
		w.Header().Set(h, v.name)
	}

	vrt := *rt
	vrt.pool, vrt.proxy, vrt.cacheTarget = v.pool, v.proxy, v.cacheTarget
	vrt.variant = v.name

	start := time.Now()
	rec := &variantRecorder{ResponseWriter: w, status: http.StatusOK}
	done := func() {
		if rec.hijacked {
			return // a WebSocket: its handshake isn't a request to judge
		}
		elapsed := time.Since(start)
		rt.split.Record(d.Index, elapsed, rec.status)
		r.recordVariant(rt.label, v.name, elapsed, rec.status)
	}
	return &vrt, rec, req, done
}

// variantRecorder captures a split request's status for the guardrails,
// passing flushes and hijacks (WebSocket upgrades) through.
type variantRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	hijacked    bool
}

func (rec *variantRecorder) WriteHeader(status int) {
	if !rec.wroteHeader {
		rec.status, rec.wroteHeader = status, true
	}
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *variantRecorder) Write(b []byte) (int, error) {
	rec.wroteHeader = true
	return rec.ResponseWriter.Write(b)
}

func (rec *variantRecorder) Flush() {
	_ = http.NewResponseController(rec.ResponseWriter).Flush()
}

func (rec *variantRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(rec.ResponseWriter).Hijack()
	if err == nil {
		rec.hijacked = true
	}
	return conn, brw, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (rec *variantRecorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// recordVariant counts a finished request in the per-variant metrics.
func (r *Router) recordVariant(route, variant string, elapsed time.Duration, status int) {
	if r.metrics == nil {
		return
	}
	r.metrics.VariantRequests.WithLabelValues(route, variant).Inc()
	if status >= 500 {
		r.metrics.VariantErrors.WithLabelValues(route, variant).Inc()
	}
	r.metrics.VariantDuration.WithLabelValues(route, variant).Observe(elapsed.Seconds())
}
