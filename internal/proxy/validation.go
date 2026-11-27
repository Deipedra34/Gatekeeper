package proxy

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/fault"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/validation"
	"gatekeeper/internal/websocket"
)

// Where validation runs: in the router, once the request's route is
// known — after access control, auth, and rate limiting, which see the
// request first, and before anything that costs more or has effects: the
// traffic split's variant choice, fault injection, the cache, retries,
// circuit breakers, and the backend. A rejected request reaches none of
// those. Running after the rate limiter means validation's cost — the
// costliest per-request step before the backend — is bounded per client
// by the rate limit, and an invalid request still counts against it.

// WithMetricsPath names the metrics endpoint's path, which is never
// validated even when a route's prefix covers it.
func WithMetricsPath(path string) Option {
	return func(r *Router) { r.metricsPath = path }
}

// skipValidation reports whether req is never validated, whatever its
// route says: a WebSocket upgrade (its handshake isn't an API call a
// spec describes), or a request for the metrics path or one of the
// usual health check paths, matched exactly. Health check probes aren't
// recognised by User-Agent here, as fault injection does, since any
// client could claim to be one to get past validation. The admin API is
// never validated: it has a listener of its own and never reaches the
// router.
func (r *Router) skipValidation(req *http.Request) bool {
	if websocket.IsUpgrade(req) {
		return true
	}
	path := req.URL.Path
	return (r.metricsPath != "" && path == r.metricsPath) || slices.Contains(fault.BuiltinExemptPaths, path)
}

// buildValidator compiles rt's validation section, if it has one that's
// enabled: its spec is loaded (once per file for the whole router) and
// checked now, so a missing or broken spec fails startup or the reload.
func (r *Router) buildValidator(rt config.Route, label string, specs map[string]*validation.Spec) (*validation.Validator, error) {
	vc := rt.Validation
	if vc == nil || !vc.Enabled {
		return nil, nil
	}
	spec, ok := specs[vc.OpenAPIFile]
	if !ok {
		var err error
		if spec, err = validation.LoadSpec(vc.OpenAPIFile, r.apiKeyHeader); err != nil {
			return nil, fmt.Errorf("proxy: route %s: validation: %w", label, err)
		}
		specs[vc.OpenAPIFile] = spec
	}
	return validation.New(spec, *vc), nil
}

// validate checks req against rt's spec. It returns the request to carry
// on with — its body put back for the backend — and true, or false when
// req was invalid and has been answered. In report_only mode an invalid
// request carries on too, exactly as the client sent it.
func (r *Router) validate(rt *route, w http.ResponseWriter, req *http.Request) (*http.Request, bool) {
	if r.skipValidation(req) {
		return req, true
	}
	// A copy, so the body validation puts back is this request's alone.
	req = req.WithContext(req.Context())
	cfg := rt.validator.Config()
	start := time.Now()
	view := r.validationView(rt, req)
	res := rt.validator.Check(req.Context(), view)
	req.Body = view.Body
	r.recordValidation(rt, res, cfg, time.Since(start))
	if res.Outcome != validation.Invalid || cfg.ReportOnly() {
		return req, true
	}
	// Like any other response on the route, the rejection gets the
	// route's response transform (its security headers, say).
	if rt.respTransform != nil {
		w = rt.respTransform.Wrap(w, r.transformVars(rt, req), func() { r.countTransform(rt, transformResponseHeaders) })
	}
	rid, _ := middleware.RequestIDFrom(req.Context())
	validation.WriteError(w, res.Status(cfg.RejectStatus), res, rid)
	return req, false
}

// validationView is req as rt's backend will receive it, which is what
// the spec describes: its path after strip_prefix and rewrite, and its
// query and headers after the route's request transform. The transform
// runs on a copy; req itself is transformed later, as always, by
// prepare. A route without a request transform validates req itself.
func (r *Router) validationView(rt *route, req *http.Request) *http.Request {
	if rt.reqTransform == nil {
		return req
	}
	view := req.Clone(req.Context())
	rt.reqTransform.Apply(view, r.transformVars(rt, req))
	return view
}

// Validation results, the "result" label of
// gatekeeper_validation_requests_total.
const (
	validationPassed     = "passed"
	validationRejected   = "rejected"
	validationReportOnly = "report_only"
	validationUnmatched  = "unmatched"
)

// validationResult names what became of a request validation found res
// for.
func validationResult(res validation.Result, cfg config.RouteValidation) string {
	switch {
	case res.Outcome == validation.Passed:
		return validationPassed
	case res.Outcome == validation.Unmatched:
		return validationUnmatched
	case cfg.ReportOnly():
		return validationReportOnly
	}
	return validationRejected
}

// recordValidation counts res in /metrics.
func (r *Router) recordValidation(rt *route, res validation.Result, cfg config.RouteValidation, took time.Duration) {
	if r.metrics == nil {
		return
	}
	r.metrics.ValidationDuration.WithLabelValues(rt.label).Observe(took.Seconds())
	result := validationResult(res, cfg)
	r.metrics.ValidationRequests.WithLabelValues(rt.label, result).Inc()
	switch result {
	case validationRejected:
		r.metrics.ValidationRejected.WithLabelValues(rt.label, res.Reason).Inc()
	case validationReportOnly:
		r.metrics.ValidationReportOnly.WithLabelValues(rt.label, res.Reason).Inc()
	}
}
