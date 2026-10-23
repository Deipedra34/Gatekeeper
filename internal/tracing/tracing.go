// Package tracing wires Gatekeeper into OpenTelemetry: it builds the
// tracer provider and OTLP (or stdout) exporter from config, creates the
// server span for each request, and gives the rest of the gateway small
// helpers to start child spans and propagate W3C trace context to
// backends.
//
// Components never hold a tracer of their own. They start spans from
// whatever span is already in the request context (see Start), so with
// tracing disabled there is no span in the context, every helper is a
// no-op, and request handling is exactly what it was before tracing
// existed — including forwarding any incoming traceparent untouched.
//
// Privacy: only the attributes set explicitly in this codebase are ever
// recorded — method, route, status code, tier, a keyed hash of the
// client identity, and similar. Headers, credentials, cookies, bodies,
// query strings, and raw error messages (which can embed URLs) never
// become span data.
package tracing

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName is the instrumentation scope of every Gatekeeper span.
const ScopeName = "gatekeeper"

// Span names for the request pipeline's stages.
const (
	SpanAuth                = "auth"
	SpanRateLimit           = "rate_limit"
	SpanCacheLookup         = "cache.lookup"
	SpanCircuitBreaker      = "circuit_breaker.check"
	SpanBackendAttempt      = "backend.attempt"
	SpanWebSocketHandshake  = "websocket.handshake"
	SpanWebSocketConnection = "websocket.connection"
)

// Attribute keys. Standard OpenTelemetry semantic-convention names are
// used where one exists; Gatekeeper-specific ones are namespaced.
const (
	AttrHTTPMethod      = attribute.Key("http.request.method")
	AttrHTTPRoute       = attribute.Key("http.route")
	AttrHTTPStatus      = attribute.Key("http.response.status_code")
	AttrURLScheme       = attribute.Key("url.scheme")
	AttrServerAddress   = attribute.Key("server.address")
	AttrServerPort      = attribute.Key("server.port")
	AttrProtocolVersion = attribute.Key("network.protocol.version")
	AttrErrorType       = attribute.Key("error.type")

	AttrAuthMode   = attribute.Key("gatekeeper.auth.mode")
	AttrAuthMethod = attribute.Key("gatekeeper.auth.method")
	AttrAuthResult = attribute.Key("gatekeeper.auth.result")

	AttrRateLimitAllowed   = attribute.Key("gatekeeper.ratelimit.allowed")
	AttrRateLimitAlgorithm = attribute.Key("gatekeeper.ratelimit.algorithm")
	AttrRateLimitStore     = attribute.Key("gatekeeper.ratelimit.store")
	AttrRateLimitLimit     = attribute.Key("gatekeeper.ratelimit.limit")
	AttrRateLimitRemaining = attribute.Key("gatekeeper.ratelimit.remaining")
	AttrRateLimitError     = attribute.Key("gatekeeper.ratelimit.store_error")
	AttrClientTier         = attribute.Key("gatekeeper.client.tier")
	AttrClientIDHash       = attribute.Key("gatekeeper.client.id_hash")

	AttrCacheHit = attribute.Key("gatekeeper.cache.hit")

	AttrBreakerState   = attribute.Key("gatekeeper.circuit_breaker.state")
	AttrBreakerAllowed = attribute.Key("gatekeeper.circuit_breaker.allowed")

	AttrBackend = attribute.Key("gatekeeper.backend")
	AttrAttempt = attribute.Key("gatekeeper.backend.attempt")
	AttrRetry   = attribute.Key("gatekeeper.backend.retry")

	AttrWSRejectReason = attribute.Key("gatekeeper.websocket.reject_reason")
	AttrWSCloseReason  = attribute.Key("gatekeeper.websocket.close_reason")
)

// Start starts a span named name as a child of the span in ctx, on the
// same tracer provider. Without a span in ctx — tracing disabled — it
// returns a no-op span and ctx unchanged in effect.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).TracerProvider().Tracer(ScopeName).Start(ctx, name, opts...)
}

// Fail marks span as failed with a short, fixed description. Callers
// pass a constant or a classified reason — never a raw error message.
func Fail(span trace.Span, description string) {
	span.SetStatus(codes.Error, description)
}

type propagatorKey struct{}

func withPropagator(ctx context.Context, p propagation.TextMapPropagator) context.Context {
	return context.WithValue(ctx, propagatorKey{}, p)
}

// Inject writes ctx's trace context (traceparent, tracestate) and
// baggage into header for an outgoing backend request. It's a no-op when
// tracing is disabled, so incoming trace headers are then forwarded as
// they arrived, as before.
func Inject(ctx context.Context, header http.Header) {
	if p, ok := ctx.Value(propagatorKey{}).(propagation.TextMapPropagator); ok {
		p.Inject(ctx, propagation.HeaderCarrier(header))
	}
}

// hashKey keys HashClientID. It's random per process, so a client ID
// hash can correlate one client's requests within a running gateway but
// can't be reversed by guessing candidate IDs (API keys) offline.
var hashKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("tracing: generating client ID hash key: " + err.Error())
	}
	return k
}()

// HashClientID returns a short keyed hash of a client identifier (which
// may be an API key) that's safe to put in a span. "" stays "".
func HashClientID(id string) string {
	if id == "" {
		return ""
	}
	mac := hmac.New(sha256.New, hashKey)
	mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// ErrorType classifies a transport error into a low-cardinality,
// secret-free value for the error.type attribute. Raw error strings
// aren't used because they can contain the request URL, query string
// included. Classification is by error type and errno rather than by
// message, since operating systems localise their messages.
func ErrorType(err error) string {
	var (
		netErr     net.Error
		dnsErr     *net.DNSError
		errno      syscall.Errno
		verifyErr  *tls.CertificateVerificationError
		recordErr  tls.RecordHeaderError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
	)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &verifyErr), errors.As(err, &recordErr), errors.As(err, &unknownCA),
		errors.As(err, &hostErr), errors.As(err, &invalidErr):
		return "tls"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection_closed"
	case errors.As(err, &errno):
		switch errno {
		case syscall.ECONNREFUSED, wsaECONNREFUSED:
			return "connection_refused"
		case syscall.ECONNRESET, wsaECONNRESET:
			return "connection_closed"
		}
	}
	return "other"
}

// Winsock's errno values, which syscall doesn't map onto ECONNREFUSED /
// ECONNRESET. They can't collide with Unix errnos, which are all small.
const (
	wsaECONNREFUSED syscall.Errno = 10061
	wsaECONNRESET   syscall.Errno = 10054
)

// standardMethods are the methods recorded as-is; anything else is
// "_OTHER", as the HTTP semantic conventions require, so a client can't
// stuff arbitrary text into spans through the method.
var standardMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodConnect: true,
	http.MethodOptions: true, http.MethodTrace: true,
}

// Method returns the value for the http.request.method attribute.
func Method(m string) string {
	if standardMethods[m] {
		return m
	}
	return "_OTHER"
}
