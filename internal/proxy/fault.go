package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/fault"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/transform"
)

// WithFaultRegistry has the router ask reg, once per request, whether to
// inject a fault, and apply what it decides to the request's backend
// attempts. Without it nothing is ever injected. The gateway passes one
// long-lived registry to every router it builds.
//
// Where faults run: the decision is made here, in the router — after
// access control, auth, and rate limiting, and after the traffic split
// picked a variant — and applied in the retry transport, to each backend
// attempt, after the load balancer picked the backend and its circuit
// breaker admitted the attempt, in place of the call to the backend. So
// an injected fault goes through the same retries, circuit breaker,
// passive health check, and load balancing a real backend failure
// would, and a request served from the cache never reaches it.
func WithFaultRegistry(reg *fault.Registry) Option {
	return func(r *Router) { r.faults = reg }
}

// decideFault asks the fault registry about req on rt and returns req
// carrying the decision, or req unchanged when nothing is injected.
// WebSocket upgrades are never faulted.
func (r *Router) decideFault(rt *route, req *http.Request) *http.Request {
	d, ok := r.faults.Decide(rt.label, fault.Request{
		HTTP:    req,
		Variant: rt.variant,
		Client:  func() fault.Client { return r.faultClient(req) },
	})
	if !ok {
		return req
	}
	ctx := fault.WithDecision(req.Context(), d)
	trace.SpanFromContext(ctx).SetAttributes(faultAttributes(d)...)
	middleware.NoteFault(ctx, d.Label())
	if d.Reset {
		ctx = context.WithValue(ctx, resetKey{}, &resetState{})
	}
	return req.WithContext(ctx)
}

// errFaultReset is what a backend attempt fails with when a connection
// reset is injected: a connection error, as if the backend had dropped
// it, so it's retried and counted like one.
var errFaultReset = errors.New("fault injected: connection reset")

// resetState records that a request's last attempt failed with an
// injected connection reset, so the router resets the client connection
// instead of answering.
type resetState struct{ requested atomic.Bool }

type resetKey struct{}

// requestReset marks req's client connection for a reset; false if req
// wasn't given a reset fault.
func requestReset(req *http.Request) bool {
	s, ok := req.Context().Value(resetKey{}).(*resetState)
	if ok {
		s.requested.Store(true)
	}
	return ok
}

// resetRequested reports whether req's client connection is to be reset.
func resetRequested(req *http.Request) bool {
	s, ok := req.Context().Value(resetKey{}).(*resetState)
	return ok && s.requested.Load()
}

// resetClient abruptly closes req's client connection, behind w: hijacked
// and closed with SO_LINGER 0, so the client sees a TCP reset rather
// than an orderly close. Where the connection can't be hijacked (HTTP/2)
// the stream is aborted instead. A split route's guardrails count it as
// a failed request.
func resetClient(w http.ResponseWriter, req *http.Request) {
	middleware.NoteConnectionReset(req.Context())
	if vr, ok := w.(*variantRecorder); ok {
		vr.status, vr.reset = http.StatusBadGateway, true
	}
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		panic(http.ErrAbortHandler) // net/http resets the stream, and logs nothing
	}
	raw := conn
	if tc, ok := conn.(*tls.Conn); ok {
		raw = tc.NetConn()
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = raw.Close()
}

// faultClient collects what a fault rule's client allowlist needs to
// know about req's client: the same address access control resolved,
// the API key, and the rate limit tier.
func (r *Router) faultClient(req *http.Request) fault.Client {
	ctx := req.Context()
	c := fault.Client{APIKey: req.Header.Get(r.apiKeyHeader)}
	if addr, ok := middleware.ClientAddrFrom(ctx); ok {
		c.IP = addr
	} else if addr, err := netip.ParseAddr(transform.ClientIP(req, r.transformCfg.TrustForwardedHeaders)); err == nil {
		c.IP = addr
	}
	if info, ok := middleware.ClientInfoFrom(ctx); ok {
		c.Tier = info.Tier
	}
	return c
}

// FaultHeader marks a response whose status was injected by an abort
// fault ("X-Gatekeeper-Fault: abort").
const FaultHeader = "X-Gatekeeper-Fault"

// roundTrip sends one attempt to b — or, when the request carries a fault
// decision that applies to b and counts as a backend failure, injects the
// fault in its place: a delay first, then a connection reset or an
// abort's response instead of the backend's.
func (t *retryTransport) roundTrip(req *http.Request, b *lb.Backend) (*http.Response, error) {
	if d, ok := fault.FromContext(req.Context()); ok && d.CountsAsBackendFailure && d.AppliesTo(b.Label()) {
		t.recordFault(d)
		trace.SpanFromContext(req.Context()).SetAttributes(faultAttributes(d)...)
		if d.Delay > 0 {
			// The attempt's context: a delay longer than proxy.timeout
			// fails the attempt as a slow backend would, and a client
			// that goes away ends it at once.
			if err := sleepContext(req.Context(), d.Delay); err != nil {
				return nil, err
			}
		}
		if d.Reset {
			return nil, errFaultReset
		}
		if d.AbortStatus != 0 {
			// Answered as if the backend had: a 5xx is retried and counted
			// by the circuit breaker and passive health check, a 4xx is
			// passed to the client, exactly like a real one.
			return abortResponse(req, d.AbortStatus), nil
		}
	}
	return b.Settings().Transport.RoundTrip(req)
}

// injectUncounted injects a fault with count_as_backend_failure: false
// into req, about to be sent to b, before the attempt starts — so outside
// its per-attempt timeout, and without its circuit breaker or passive
// health check ever hearing of it. done reports that req is answered: by
// an abort's response, a connection reset, or the client going away
// during the delay. A delay alone leaves the attempt to go ahead.
func (t *retryTransport) injectUncounted(req *http.Request, b *lb.Backend) (resp *http.Response, done bool, err error) {
	d, ok := fault.FromContext(req.Context())
	if !ok || d.CountsAsBackendFailure || !d.AppliesTo(b.Label()) {
		return nil, false, nil
	}
	t.recordFault(d)
	if d.Delay > 0 {
		err = sleepContext(req.Context(), d.Delay)
	}
	switch {
	case err != nil:
	case d.Reset:
		err = errFaultReset
	case d.AbortStatus != 0:
		resp = abortResponse(req, d.AbortStatus)
	default:
		return nil, false, nil
	}
	// The breaker admitted an attempt that's not going to happen.
	if cb := b.Breaker(); cb != nil {
		cb.Release()
	}
	return resp, true, err
}

// faultAttributes describe d on a span.
func faultAttributes(d fault.Decision) []attribute.KeyValue {
	return []attribute.KeyValue{
		tracing.AttrFaultInjected.String(d.Label()),
		tracing.AttrFaultRule.String(d.Rule),
	}
}

// recordFault counts the faults d injects into an attempt.
func (t *retryTransport) recordFault(d fault.Decision) {
	if t.metrics == nil {
		return
	}
	for _, typ := range d.Types() {
		t.metrics.FaultsInjected.WithLabelValues(t.route, typ).Inc()
	}
}

// abortResponse is the response an abort fault answers req with.
func abortResponse(req *http.Request, status int) *http.Response {
	body := "fault injected: " + strconv.Itoa(status) + " " + http.StatusText(status) + "\n"
	return &http.Response{
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":           {"text/plain; charset=utf-8"},
			"X-Content-Type-Options": {"nosniff"},
			FaultHeader:              {fault.TypeAbort},
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// sleepContext waits for d, or until ctx is done if that's sooner. It
// starts no goroutine, so an abandoned request leaves nothing behind.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
