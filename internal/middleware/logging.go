package middleware

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// statusRecorder wraps a ResponseWriter to capture the status code
// written by downstream handlers, since http.ResponseWriter doesn't
// expose it directly.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Hijack lets a WebSocket upgrade take over the connection through the
// recorder, and logs the request as 101 Switching Protocols when it does.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err == nil {
		r.status = http.StatusSwitchingProtocols
	}
	return conn, brw, err
}

// RequestLogger logs one line per request: method, path, status,
// duration, and remote address — plus trace_id=<id> when the request is
// being traced, so a log line leads straight to its trace, and
// variant=<name> when a split route served it from a variant, and
// fault=<faults> when a fault was injected into it (fault=delay,abort),
// and validation=<result> when it failed OpenAPI validation
// (validation=rejected, or validation=report_only when it was forwarded
// anyway). A
// proxied WebSocket connection is logged once it closes, as status 101
// with the connection's whole lifetime as its duration; a request whose
// connection was reset by an injected fault is logged with "reset" for
// its status.
func RequestLogger(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			notes := &logNotes{}
			r = r.WithContext(context.WithValue(r.Context(), logNotesKey{}, notes))

			next.ServeHTTP(rec, r)

			status := strconv.Itoa(rec.status)
			if notes.reset.Load() {
				status = "reset"
			}
			line := fmt.Sprintf("%s %s %s %s %s", r.Method, r.URL.Path, status, time.Since(start), r.RemoteAddr)
			if sc := trace.SpanContextFromContext(r.Context()); sc.HasTraceID() {
				line += " trace_id=" + sc.TraceID().String()
			}
			if v := notes.variant.Load(); v != nil {
				line += " variant=" + *v
			}
			if f := notes.fault.Load(); f != nil {
				line += " fault=" + *f
			}
			if v := notes.validation.Load(); v != nil {
				line += " validation=" + *v
			}
			logger.Print(line)
		})
	}
}

// logNotes is what handlers further down tell RequestLogger to add to a
// request's log line.
type logNotes struct {
	variant    atomic.Pointer[string]
	fault      atomic.Pointer[string]
	validation atomic.Pointer[string]
	reset      atomic.Bool
}

type logNotesKey struct{}

// NoteVariant records the traffic split variant serving the request, for
// its log line. Without RequestLogger in the chain it does nothing.
func NoteVariant(ctx context.Context, variant string) {
	if n, ok := ctx.Value(logNotesKey{}).(*logNotes); ok {
		n.variant.Store(&variant)
	}
}

// NoteFault records the faults injected into the request ("delay",
// "abort,delay", ...), for its log line. Without RequestLogger in the
// chain it does nothing.
func NoteFault(ctx context.Context, faults string) {
	if n, ok := ctx.Value(logNotesKey{}).(*logNotes); ok {
		n.fault.Store(&faults)
	}
}

// NoteValidation records what OpenAPI validation made of an invalid
// request ("rejected", "report_only"), for its log line. Without
// RequestLogger in the chain it does nothing.
func NoteValidation(ctx context.Context, result string) {
	if n, ok := ctx.Value(logNotesKey{}).(*logNotes); ok {
		n.validation.Store(&result)
	}
}

// NoteConnectionReset records that the request's client connection was
// reset rather than answered, for its log line.
func NoteConnectionReset(ctx context.Context) {
	if n, ok := ctx.Value(logNotesKey{}).(*logNotes); ok {
		n.reset.Store(true)
	}
}
