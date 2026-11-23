package proxy

import (
	"net/http"
	"net/netip"

	"gatekeeper/internal/fault"
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
