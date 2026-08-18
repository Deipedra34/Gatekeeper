package middleware

import (
	"log"
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

// RequestLogger logs one line per request: method, path, status,
// duration, and remote address.
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
