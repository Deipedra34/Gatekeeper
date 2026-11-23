package proxy

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gatekeeper/internal/fault"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/middleware"
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
	return req.WithContext(fault.WithDecision(req.Context(), d))
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
// decision that applies to b, injects the fault in its place: a delay
// first, then an abort's response instead of the backend's.
func (t *retryTransport) roundTrip(req *http.Request, b *lb.Backend) (*http.Response, error) {
	if d, ok := fault.FromContext(req.Context()); ok && d.AppliesTo(b.Label()) {
		if d.Delay > 0 {
			// The attempt's context: a delay longer than proxy.timeout
			// fails the attempt as a slow backend would, and a client
			// that goes away ends it at once.
			if err := sleepContext(req.Context(), d.Delay); err != nil {
				return nil, err
			}
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
