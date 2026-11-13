package middleware

import (
	"context"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"time"

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
//
// An address that passes the lists is then checked against the ban
// list in the shared store; a banned one is rejected the same way, with
// a Retry-After header saying when the ban ends. If the store can't be
// read the request is let through, as the rate limiter does.
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
				block(w, policy.DenyStatus(), 0)
				return
			}
			if known {
				if ban, banned, err := c.Banned(r.Context(), addr); err == nil && banned {
					block(w, policy.DenyStatus(), time.Until(ban.ExpiresAt))
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), clientAddrKey{}, addr))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// block writes the rejection. retryAfter, when positive, is how long
// until a ban ends.
func block(w http.ResponseWriter, status int, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(max(math.Ceil(retryAfter.Seconds()), 1))))
	}
	http.Error(w, "access denied", status)
}

type clientAddrKey struct{}

// ClientAddrFrom returns the client address the access control
// middleware resolved for this request. There's none when access
// control isn't configured.
func ClientAddrFrom(ctx context.Context) (netip.Addr, bool) {
	a, ok := ctx.Value(clientAddrKey{}).(netip.Addr)
	return a, ok
}
