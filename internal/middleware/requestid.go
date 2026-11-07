package middleware

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"

	"gatekeeper/internal/config"
)

type requestIDKey struct{}

// RequestIDFrom returns the request ID RequestID assigned, if any.
func RequestIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok
}

// maxRequestIDLen bounds a client-supplied request ID.
const maxRequestIDLen = 128

// validRequestID reports whether a client-supplied ID is safe to keep:
// short, and only characters that can't break a header, a log line, or
// a JSON document.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':', c == '/', c == '+', c == '=', c == '@':
		default:
			return false
		}
	}
	return true
}

// newRequestID returns a random version 4 UUID.
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// RequestID gives each request an ID, when cfg enables it: the one the
// client sent in cfg.Header if it's valid, otherwise a new UUID. The ID
// replaces the header on the request (so the backend receives it), is
// set on the response — overriding any the backend sent, so the client
// always gets back the ID the gateway used — and is available to later
// middleware and transforms via RequestIDFrom. Disabled, it changes
// nothing.
func RequestID(cfg config.RequestIDConfig) Middleware {
	return func(next http.Handler) http.Handler {
		if !cfg.Enabled {
			return next
		}
		header := http.CanonicalHeaderKey(cfg.Header)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(header)
			if !validRequestID(id) || len(r.Header.Values(header)) > 1 {
				id = newRequestID()
			}
			r.Header.Set(header, id)
			w.Header().Set(header, id)
			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			next.ServeHTTP(&requestIDWriter{ResponseWriter: w, header: header, id: id}, r.WithContext(ctx))
		})
	}
}

// requestIDWriter re-asserts the request ID header just before the
// response is written, replacing any copy the backend's response added.
type requestIDWriter struct {
	http.ResponseWriter
	header, id  string
	wroteHeader bool
}

func (w *requestIDWriter) WriteHeader(status int) {
	if !w.wroteHeader && status >= http.StatusOK {
		w.wroteHeader = true
		w.Header().Set(w.header, w.id)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *requestIDWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *requestIDWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *requestIDWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *requestIDWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ClientInfo is how the rate limiter identified a request's client.
type ClientInfo struct {
	// Label is the client as metrics and logs show it: an API key's
	// fingerprint ("key:..."), "jwt:<id>", "mtls:<id>", or the IP or
	// header value. Never a raw API key.
	Label string
	// Tier is the rate-limit tier the client was checked against.
	Tier string
}

type clientInfoKey struct{}

// ClientInfoFrom returns the ClientInfo the rate limiter recorded.
func ClientInfoFrom(ctx context.Context) (ClientInfo, bool) {
	c, ok := ctx.Value(clientInfoKey{}).(ClientInfo)
	return c, ok
}

func withClientInfo(r *http.Request, c ClientInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientInfoKey{}, c))
}
