package proxy

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/config"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/transform"
)

// WithTransformConfig applies the global transform settings: whether
// client-supplied forwarding headers are trusted, the request ID header
// (kept safe from hop-by-hop stripping), and default security headers.
// Without it the router behaves as if transform were left out of the
// config: forwarding headers are set from the connection.
func WithTransformConfig(cfg config.TransformConfig) Option {
	return func(r *Router) { r.transformCfg = cfg }
}

// Transform kinds, the "kind" label of gatekeeper_transforms_applied_total.
const (
	transformPath            = "path"
	transformQuery           = "query"
	transformRequestHeaders  = "request_headers"
	transformResponseHeaders = "response_headers"
)

// transformVars collects the ${...} variable values for req.
func (r *Router) transformVars(rt *route, req *http.Request) transform.Vars {
	v := transform.Vars{
		ClientIP: transform.ClientIP(req, r.transformCfg.TrustForwardedHeaders),
		Route:    rt.label,
	}
	if id, ok := middleware.RequestIDFrom(req.Context()); ok {
		v.RequestID = id
	}
	if c, ok := middleware.ClientInfoFrom(req.Context()); ok {
		v.ClientID, v.ClientTier = c.Label, c.Tier
	}
	if sc := trace.SpanContextFromContext(req.Context()); sc.HasTraceID() {
		v.TraceID = sc.TraceID().String()
	}
	return v
}

// prepare turns the request as the middleware chain saw it into the one
// forwarded for rt: forwarding headers per trust_forwarded_headers, then
// the route's request transform. It also wraps w with the route's
// response transform. Auth and rate limiting already ran on the
// original request; everything after this — the cache key, retries,
// backend selection, WebSocket handshakes — uses the result.
func (r *Router) prepare(rt *route, w http.ResponseWriter, req *http.Request) (http.ResponseWriter, *http.Request, transform.Vars) {
	vars := r.transformVars(rt, req)
	trust := r.transformCfg.TrustForwardedHeaders
	ridHeader := ""
	if r.transformCfg.RequestID.Enabled {
		ridHeader = r.transformCfg.RequestID.Header
	}
	if trust && rt.reqTransform == nil && rt.respTransform == nil && ridHeader == "" {
		return w, req, vars // nothing to change: proxied exactly as before
	}

	out := req.Clone(req.Context())
	if !trust {
		transform.ForwardedHeaders(out)
	}
	if ridHeader != "" {
		transform.UnlistFromConnection(out.Header, ridHeader)
	}

	if rt.reqTransform != nil {
		res := rt.reqTransform.Apply(out, vars)
		if res.PathChanged {
			r.countTransform(rt, transformPath)
			// The path only: query strings can carry tokens.
			trace.SpanFromContext(out.Context()).SetAttributes(tracing.AttrTransformPath.String(out.URL.Path))
		}
		if res.Query {
			r.countTransform(rt, transformQuery)
		}
		if res.Headers {
			r.countTransform(rt, transformRequestHeaders)
		}
	}
	if rt.respTransform != nil {
		w = rt.respTransform.Wrap(w, vars, func() { r.countTransform(rt, transformResponseHeaders) })
	}
	return w, out, vars
}

func (r *Router) countTransform(rt *route, kind string) {
	if r.metrics != nil {
		r.metrics.TransformsApplied.WithLabelValues(rt.label, kind).Inc()
	}
}
