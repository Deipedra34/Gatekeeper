package middleware

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"time"
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
// duration, and remote address. A proxied WebSocket connection is logged
// once it closes, as status 101 with the connection's whole lifetime as
// its duration.
func RequestLogger(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			logger.Printf("%s %s %d %s %s",
				r.Method, r.URL.Path, rec.status, time.Since(start), r.RemoteAddr)
		})
	}
}
