package middleware

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"time"

	"gatekeeper/internal/metrics"
)

// unmatchedRoute labels requests that matched no route.
const unmatchedRoute = "unmatched"

// RequestMetrics records every request's end-to-end latency — auth, rate
// limiting, cache, and the proxied backend call, rejections included —
// in gatekeeper_request_duration_seconds, by route (as resolved by
// routeFor, normally the router's RouteLabelFor) and status code.
//
// Upgraded WebSocket connections are left out: the handler runs for the
// connection's whole lifetime, which would swamp the latency histogram;
// they have gatekeeper_websocket_connection_duration_seconds instead.
func RequestMetrics(m *metrics.Metrics, routeFor func(*http.Request) (string, bool)) Middleware {
	return func(next http.Handler) http.Handler {
		if m == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			route := unmatchedRoute
			if routeFor != nil {
				if label, ok := routeFor(r); ok {
					route = label
				}
			}
			rec := &durationRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			if rec.hijacked {
				return
			}
			m.RequestDuration.WithLabelValues(route, strconv.Itoa(rec.status)).Observe(time.Since(start).Seconds())
		})
	}
}

// durationRecorder captures the status code and whether the connection
// was hijacked (a WebSocket upgrade).
type durationRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	hijacked    bool
}

func (r *durationRecorder) WriteHeader(status int) {
	if !r.wroteHeader {
		r.status = status
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *durationRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

func (r *durationRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err == nil {
		r.hijacked = true
	}
	return conn, brw, err
}
