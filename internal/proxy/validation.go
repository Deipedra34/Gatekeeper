package proxy

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/config"
	"gatekeeper/internal/fault"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/tracing"
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

// WithValidationLog has the router log invalid requests through t,
// which rate limits them, instead of a throttle of its own. The gateway
// passes one long-lived throttle to every router it builds, so a reload
// in the middle of a flood doesn't reset the limit.
func WithValidationLog(t *accesscontrol.LogThrottle) Option {
	return func(r *Router) { r.validationLog = t }
}

// Without WithValidationLog, a router logs at most validationLogBurst
// invalid requests at once, then one per validationLogInterval.
const (
	validationLogInterval = time.Second
	validationLogBurst    = 10
)

// maxLoggedViolations bounds the violations named in a log line.
const maxLoggedViolations = 3

// logValidation logs an invalid request — rejected or, in report_only
// mode, forwarded — at a limited rate. The line names the route, the
// method and path, the operation, the reason, and which fields failed
// and why: never their values, the query string, or the body.
func (r *Router) logValidation(rt *route, req *http.Request, res validation.Result, result string) {
	var b strings.Builder
	fmt.Fprintf(&b, "validation: route %s: %s %s %q", rt.label, result, tracing.Method(req.Method), req.URL.Path)
	if res.Operation != "" {
		fmt.Fprintf(&b, " operation=%q", res.Operation)
	}
	fmt.Fprintf(&b, " reason=%s", res.Reason)
	for i, v := range res.Violations {
		if i == maxLoggedViolations {
			fmt.Fprintf(&b, " (+%d more)", len(res.Violations)-i)
			break
		}
		sep := "; "
		if i == 0 {
			sep = ": "
		}
		b.WriteString(sep + v.In)
		if v.Field != "" {
			b.WriteString(" " + v.Field)
		}
		b.WriteString(" " + v.Message)
	}
	if id, ok := middleware.RequestIDFrom(req.Context()); ok {
		b.WriteString(" request_id=" + id)
	}
	if sc := trace.SpanContextFromContext(req.Context()); sc.HasTraceID() {
		b.WriteString(" trace_id=" + sc.TraceID().String())
	}
	r.validationLog.Printf("%s", b.String())
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
	ctx, span := tracing.Start(req.Context(), tracing.SpanValidation, trace.WithAttributes(tracing.AttrHTTPRoute.String(rt.label)))
	view := r.validationView(rt, req)
	res := rt.validator.Check(ctx, view)
	req.Body = view.Body
	result := validationResult(res, cfg)
	r.recordValidation(rt, res, result, time.Since(start))
	traceValidation(span, req, res, result)
	if res.Outcome != validation.Invalid {
		return req, true
	}
	r.logValidation(rt, req, res, result)
	middleware.NoteValidation(req.Context(), result)
	if cfg.ReportOnly() {
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
func (r *Router) recordValidation(rt *route, res validation.Result, result string, took time.Duration) {
	if r.metrics == nil {
		return
	}
	r.metrics.ValidationDuration.WithLabelValues(rt.label).Observe(took.Seconds())
	r.metrics.ValidationRequests.WithLabelValues(rt.label, result).Inc()
	switch result {
	case validationRejected:
		r.metrics.ValidationRejected.WithLabelValues(rt.label, res.Reason).Inc()
	case validationReportOnly:
		r.metrics.ValidationReportOnly.WithLabelValues(rt.label, res.Reason).Inc()
	}
}

// traceValidation records res on the validation span, and its result on
// the server span too, so traces can be searched by it. A rejection
// marks the validation span failed.
func traceValidation(span trace.Span, req *http.Request, res validation.Result, result string) {
	attrs := []attribute.KeyValue{tracing.AttrValidationResult.String(result)}
	if res.Operation != "" {
		attrs = append(attrs, tracing.AttrValidationOperation.String(res.Operation))
	}
	if res.Reason != "" {
		attrs = append(attrs, tracing.AttrValidationReason.String(res.Reason))
	}
	span.SetAttributes(attrs...)
	if result == validationRejected {
		tracing.Fail(span, "request invalid: "+res.Reason)
	}
	span.End()
	trace.SpanFromContext(req.Context()).SetAttributes(tracing.AttrValidationResult.String(result))
}
