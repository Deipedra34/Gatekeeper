package middleware

import (
	"context"
	"net/http"
	"net/netip"

	"gatekeeper/internal/accesscontrol"
)

// AccessControl rejects requests from client addresses the route's
// policy doesn't admit, before anything else in the chain has spent work
// on them: a blocked request never reaches auth, the rate limiter (so it
// consumes no tokens), the cache, the circuit breaker, or a backend.
//
// The client address is the one c resolves — the connection's peer, or
// the address reported by a trusted proxy (see accesscontrol.Resolver) —
// and is recorded on the request for later middleware (see
// ClientAddrFrom). routeFor maps a request to its route label (normally
// the router's RouteLabelFor); a request matching no route gets the
// global policy.
func AccessControl(c *accesscontrol.Controller, routeFor func(*http.Request) (string, bool)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, known := c.ClientAddr(r)
			route := ""
			if routeFor != nil {
				route, _ = routeFor(r)
			}
			policy := c.PolicyFor(route)
			if reason := policy.Check(addr, known); reason != accesscontrol.ReasonNone {
				http.Error(w, "access denied", policy.DenyStatus())
				return
			}
			if known {
				r = r.WithContext(context.WithValue(r.Context(), clientAddrKey{}, addr))
			}
			next.ServeHTTP(w, r)
		})
	}
}

type clientAddrKey struct{}

// ClientAddrFrom returns the client address the access control
// middleware resolved for this request. There's none when access
// control isn't configured.
func ClientAddrFrom(ctx context.Context) (netip.Addr, bool) {
	a, ok := ctx.Value(clientAddrKey{}).(netip.Addr)
	return a, ok
}
