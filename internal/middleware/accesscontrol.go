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
				a.block(w, r, addr, reason, policy.DenyStatus(), 0)
				return
			}
			if known {
				ban, banned, err := c.Banned(r.Context(), addr)
				if err != nil {
					a.log.Printf("access_control: WARNING: ban check for %s failed, letting the request through: %v", addr, err)
				}
				if banned {
					reason := accesscontrol.ReasonAutoBan
					if ban.Source == accesscontrol.SourceManual {
						reason = accesscontrol.ReasonManualBan
					}
					a.block(w, r, addr, reason, policy.DenyStatus(), time.Until(ban.ExpiresAt))
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

// WithAccessLog logs blocked requests, new bans, and store errors
// through t, which rate limits them. Without it nothing is logged.
func WithAccessLog(t *accesscontrol.LogThrottle) AccessControlOption {
	return func(a *accessControl) { a.log = t }
}

// accessControl is one AccessControl middleware's settings.
type accessControl struct {
	c        *accesscontrol.Controller
	routeFor func(*http.Request) (string, bool)
	metrics  *metrics.Metrics
	log      *accesscontrol.LogThrottle // nil: no logging
}

// maxLoggedPath caps how much of a blocked request's path is logged.
const maxLoggedPath = 100

// block writes the rejection. retryAfter, when positive, is how long
// until a ban ends.
//
// The log line has the method, the path (truncated, never the query),
// the client address, and the reason — never headers, which can carry
// credentials.
func (a *accessControl) block(w http.ResponseWriter, r *http.Request, addr netip.Addr, reason accesscontrol.Reason, status int, retryAfter time.Duration) {
	if a.metrics != nil {
		a.metrics.AccessBlocked.WithLabelValues(string(reason)).Inc()
	}
	client := "unknown"
	if addr.IsValid() {
		client = addr.String()
	}
	path := r.URL.Path
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath] + "..."
	}
	a.log.Printf("access_control: blocked %s %q from %s: %s (status %d)", r.Method, path, client, reason, status)
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(max(math.Ceil(retryAfter.Seconds()), 1))))
	}
	http.Error(w, "access denied", status)
}

// recordOffense records o for addr. The request is being rejected
// anyway; if the store fails, the offense just isn't counted.
func (a *accessControl) recordOffense(ctx context.Context, addr netip.Addr, o accesscontrol.Offense) {
	ban, banned, err := a.c.RecordOffense(ctx, addr, o)
	if err != nil {
		a.log.Printf("access_control: WARNING: recording a %s offense for %s failed: %v", o, addr, err)
		return
	}
	if !banned {
		return
	}
	if a.metrics != nil {
		a.metrics.BansIssued.WithLabelValues(accesscontrol.SourceAuto).Inc()
	}
	a.log.Printf("access_control: auto-banned %s until %s (level %d: %s)",
		ban.IP, ban.ExpiresAt.Format(time.RFC3339), ban.Level, ban.Reason)
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
