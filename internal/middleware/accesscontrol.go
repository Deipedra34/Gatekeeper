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
//
// With auto-ban on, a request the lists reject counts as a "denied"
// offense, and the auth and rate limit middleware further down report
// their rejections too (see reportOffense), so an address that keeps
// offending gets banned.
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
				if known {
					recordOffense(r.Context(), c, addr, accesscontrol.OffenseDenied)
				}
				block(w, policy.DenyStatus(), 0)
				return
			}
			if known {
				if ban, banned, err := c.Banned(r.Context(), addr); err == nil && banned {
					block(w, policy.DenyStatus(), time.Until(ban.ExpiresAt))
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), accessKey{}, requestAccess{addr: addr, c: c}))
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

// requestAccess is what the access control middleware attaches to a
// request it lets through: the resolved client address, and the
// controller to report offenses to.
type requestAccess struct {
	addr netip.Addr
	c    *accesscontrol.Controller
}

type accessKey struct{}

// ClientAddrFrom returns the client address the access control
// middleware resolved for this request. There's none when access
// control isn't configured.
func ClientAddrFrom(ctx context.Context) (netip.Addr, bool) {
	ra, ok := ctx.Value(accessKey{}).(requestAccess)
	return ra.addr, ok
}

// reportOffense counts an offense (a rate limit or auth rejection) by
// r's client toward an automatic ban. Without access control on the
// request it does nothing.
func reportOffense(r *http.Request, o accesscontrol.Offense) {
	if ra, ok := r.Context().Value(accessKey{}).(requestAccess); ok {
		recordOffense(r.Context(), ra.c, ra.addr, o)
	}
}

// recordOffense records o for addr. The request is being rejected
// anyway; if the store fails, the offense just isn't counted.
func recordOffense(ctx context.Context, c *accesscontrol.Controller, addr netip.Addr, o accesscontrol.Offense) {
	_, _, _ = c.RecordOffense(ctx, addr, o)
}
