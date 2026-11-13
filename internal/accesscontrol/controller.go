package accesscontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// PolicySettings is the uncompiled form of a Policy.
type PolicySettings struct {
	Mode       Mode
	Allow      []string
	Deny       []string
	DenyStatus int
}

// Settings configures a Controller.
type Settings struct {
	// Global applies to every route without an override.
	Global PolicySettings
	// Routes holds the effective policy of each route that overrides the
	// global one, keyed by route label (config.Route.Label). Routes not
	// listed use Global.
	Routes map[string]PolicySettings
	// TrustedProxies are the proxies whose forwarding headers are
	// believed (see Resolver).
	TrustedProxies []string
	// Store holds bans. It's the store the rate limiter uses, so with
	// Redis bans are shared by every instance. Nil disables bans.
	Store store.Store
	// AutoBan, if set (and Store is too), bans addresses that offend
	// repeatedly.
	AutoBan *AutoBanSettings
	// NeverBan lists addresses and ranges that are never banned. Trusted
	// proxies are never banned either: banning one would block every
	// client behind it.
	NeverBan []string
}

// Controller is the compiled access control of one config: built when
// the config is loaded or reloaded, read-only afterwards, so requests
// use it without locking.
type Controller struct {
	resolver *Resolver
	global   *Policy
	routes   map[string]*Policy
	bans     *BanList
	autoBan  *AutoBan
	neverBan *PrefixSet
}

// NewController compiles s. Every list is parsed once, here.
func NewController(s Settings) (*Controller, error) {
	trusted, err := NewPrefixSet(s.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("accesscontrol: trusted proxies: %w", err)
	}
	global, err := newPolicy(s.Global)
	if err != nil {
		return nil, err
	}
	neverBan, err := NewPrefixSet(s.NeverBan)
	if err != nil {
		return nil, fmt.Errorf("accesscontrol: never_ban: %w", err)
	}
	c := &Controller{
		resolver: NewResolver(trusted), global: global, neverBan: neverBan,
		routes: make(map[string]*Policy, len(s.Routes)),
	}
	if s.Store != nil {
		c.bans = NewBanList(s.Store)
		if s.AutoBan != nil {
			c.autoBan = NewAutoBan(s.Store, c.bans, *s.AutoBan)
		}
	}
	for label, ps := range s.Routes {
		p, err := newPolicy(ps)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", label, err)
		}
		c.routes[label] = p
	}
	return c, nil
}

func newPolicy(ps PolicySettings) (*Policy, error) {
	if ps.Mode == "" {
		ps.Mode = ModeOff
	}
	if ps.DenyStatus == 0 {
		ps.DenyStatus = http.StatusForbidden
	}
	return NewPolicy(ps.Mode, ps.Allow, ps.Deny, ps.DenyStatus)
}

// PolicyFor returns the policy for the route labelled route: its own
// override if it has one, the global policy otherwise (including for a
// request that matches no route).
func (c *Controller) PolicyFor(route string) *Policy {
	if p, ok := c.routes[route]; ok {
		return p
	}
	return c.global
}

// ClientAddr returns req's client address (see Resolver.ClientAddr).
func (c *Controller) ClientAddr(req *http.Request) (netip.Addr, bool) {
	return c.resolver.ClientAddr(req)
}

// Bans returns the ban list, or nil when bans are disabled.
func (c *Controller) Bans() *BanList { return c.bans }

// Protected reports whether addr may never be banned: it's on the
// never_ban list or is a trusted proxy.
func (c *Controller) Protected(addr netip.Addr) bool {
	return c.neverBan.Contains(addr) || c.resolver.Trusted(addr)
}

// Banned returns addr's current ban, if it has one. A protected address
// is never banned, even if a ban was stored before it became protected
// (by a reload adding it to never_ban).
func (c *Controller) Banned(ctx context.Context, addr netip.Addr) (Ban, bool, error) {
	if c.bans == nil || c.Protected(addr) {
		return Ban{}, false, nil
	}
	return c.bans.Get(ctx, addr)
}

// RecordOffense counts an offense by addr toward an automatic ban; see
// AutoBan.Record. It's a no-op when auto-ban is off and for a protected
// address.
func (c *Controller) RecordOffense(ctx context.Context, addr netip.Addr, o Offense) (Ban, bool, error) {
	if c.autoBan == nil || c.Protected(addr) {
		return Ban{}, false, nil
	}
	return c.autoBan.Record(ctx, addr, o)
}

// Resolver returns the client address resolver.
func (c *Controller) Resolver() *Resolver { return c.resolver }

// Errors from Ban and Unban.
var (
	// ErrProtected means the address is on never_ban or is a trusted
	// proxy.
	ErrProtected = errors.New("accesscontrol: address is on the never_ban list or is a trusted proxy")
	// ErrBansDisabled means the controller has no store to keep bans in.
	ErrBansDisabled = errors.New("accesscontrol: bans are not available")
)

// DefaultManualBanDuration is how long a manual ban lasts when no
// duration is given and auto-ban isn't configured.
const DefaultManualBanDuration = time.Hour

// DefaultBanDuration is the duration of a manual ban that doesn't name
// one: auto-ban's first-ban duration, or DefaultManualBanDuration.
func (c *Controller) DefaultBanDuration() time.Duration {
	if c.autoBan != nil {
		return c.autoBan.s.BanDuration
	}
	return DefaultManualBanDuration
}

// Ban bans addr for d, replacing any current ban, as an operator action
// (source "manual"). A protected address can't be banned.
func (c *Controller) Ban(ctx context.Context, addr netip.Addr, d time.Duration, reason string) (Ban, error) {
	if c.bans == nil {
		return Ban{}, ErrBansDisabled
	}
	addr = normalize(addr)
	if c.Protected(addr) {
		return Ban{}, ErrProtected
	}
	if d <= 0 {
		return Ban{}, errors.New("accesscontrol: ban duration must be > 0")
	}
	now := time.Now().UTC()
	ban := Ban{IP: addr.String(), Source: SourceManual, Reason: reason, BannedAt: now, ExpiresAt: now.Add(d)}
	if err := c.bans.Add(ctx, ban); err != nil {
		return Ban{}, err
	}
	return ban, nil
}

// Unban lifts addr's ban, whichever way it was issued. found reports
// whether there was one.
func (c *Controller) Unban(ctx context.Context, addr netip.Addr) (found bool, err error) {
	if c.bans == nil {
		return false, ErrBansDisabled
	}
	return c.bans.Remove(ctx, addr)
}
