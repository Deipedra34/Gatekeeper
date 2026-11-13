package middleware

import (
	"context"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/metrics"
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
func AccessControl(c *accesscontrol.Controller, routeFor func(*http.Request) (string, bool), opts ...AccessControlOption) Middleware {
	a := &accessControl{c: c, routeFor: routeFor}
	for _, opt := range opts {
		opt(a)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, known := c.ClientAddr(r)
			route := ""
			if a.routeFor != nil {
				route, _ = a.routeFor(r)
			}
			policy := c.PolicyFor(route)
			if reason := policy.Check(addr, known); reason != accesscontrol.ReasonNone {
				if known {
					a.recordOffense(r.Context(), addr, accesscontrol.OffenseDenied)
				}
				a.block(w, reason, policy.DenyStatus(), 0)
				return
			}
			if known {
				if ban, banned, err := c.Banned(r.Context(), addr); err == nil && banned {
					reason := accesscontrol.ReasonAutoBan
					if ban.Source == accesscontrol.SourceManual {
						reason = accesscontrol.ReasonManualBan
					}
					a.block(w, reason, policy.DenyStatus(), time.Until(ban.ExpiresAt))
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), accessKey{}, requestAccess{addr: addr, a: a}))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AccessControlOption customises AccessControl.
type AccessControlOption func(*accessControl)

// WithAccessMetrics counts blocked requests and issued bans in m.
func WithAccessMetrics(m *metrics.Metrics) AccessControlOption {
	return func(a *accessControl) { a.metrics = m }
}

// accessControl is one AccessControl middleware's settings.
type accessControl struct {
	c        *accesscontrol.Controller
	routeFor func(*http.Request) (string, bool)
	metrics  *metrics.Metrics
}

// block writes the rejection. retryAfter, when positive, is how long
// until a ban ends.
func (a *accessControl) block(w http.ResponseWriter, reason accesscontrol.Reason, status int, retryAfter time.Duration) {
	if a.metrics != nil {
		a.metrics.AccessBlocked.WithLabelValues(string(reason)).Inc()
	}
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(max(math.Ceil(retryAfter.Seconds()), 1))))
	}
	http.Error(w, "access denied", status)
}

// recordOffense records o for addr. The request is being rejected
// anyway; if the store fails, the offense just isn't counted.
func (a *accessControl) recordOffense(ctx context.Context, addr netip.Addr, o accesscontrol.Offense) {
	_, banned, err := a.c.RecordOffense(ctx, addr, o)
	if err == nil && banned && a.metrics != nil {
		a.metrics.BansIssued.WithLabelValues(accesscontrol.SourceAuto).Inc()
	}
}

// requestAccess is what the access control middleware attaches to a
// request it lets through: the resolved client address, and the
// controller to report offenses to.
type requestAccess struct {
	addr netip.Addr
	a    *accessControl
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
		ra.a.recordOffense(r.Context(), ra.addr, o)
	}
}
