package tracing

import (
	"bufio"
	"net"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// UnmatchedRoute is the http.route of a request that matched no route.
const UnmatchedRoute = "unmatched"

// Handler wraps next in a server span per request: it joins the caller's
// trace if the request carries a traceparent (and picks up its baggage),
// names the span "<METHOD> <route>", and records the response status.
// routeFor resolves a request's route label (the router's RouteLabelFor).
//
// With tracing disabled it returns next unchanged.
func (p *Provider) Handler(next http.Handler, routeFor func(*http.Request) (string, bool)) http.Handler {
	if !p.Enabled() {
		return next
	}
	tracer := p.tp.Tracer(ScopeName)
	prop := p.propagator
	respHeader := p.responseHeader

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		route := UnmatchedRoute
		if routeFor != nil {
			if label, ok := routeFor(r); ok {
				route = label
			}
		}
		method := Method(r.Method)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		ctx, span := tracer.Start(ctx, method+" "+route,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				AttrHTTPMethod.String(method),
				AttrHTTPRoute.String(route),
				AttrURLScheme.String(scheme),
				AttrProtocolVersion.String(protocolVersion(r)),
			),
		)
		defer span.End()

		if respHeader != "" && span.SpanContext().HasTraceID() {
			w.Header().Set(respHeader, span.SpanContext().TraceID().String())
		}

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(withPropagator(ctx, prop)))

		span.SetAttributes(AttrHTTPStatus.Int(sw.status))
		// Per the HTTP semantic conventions, only 5xx makes a server span
		// an error; a 4xx is the client's problem, not the gateway's.
		if sw.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(sw.status))
		}
	})
}

func protocolVersion(r *http.Request) string {
	if r.ProtoMajor == 2 {
		return "2"
	}
	return strconv.Itoa(r.ProtoMajor) + "." + strconv.Itoa(r.ProtoMinor)
}

// statusWriter captures the response status for the server span, and
// passes Hijack through so WebSocket upgrades still work.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.status = http.StatusSwitchingProtocols
	}
	return conn, brw, err
}
