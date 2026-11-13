package accesscontrol

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

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
}

// Controller is the compiled access control of one config: built when
// the config is loaded or reloaded, read-only afterwards, so requests
// use it without locking.
type Controller struct {
	resolver *Resolver
	global   *Policy
	routes   map[string]*Policy
	bans     *BanList
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
	c := &Controller{resolver: NewResolver(trusted), global: global, routes: make(map[string]*Policy, len(s.Routes))}
	if s.Store != nil {
		c.bans = NewBanList(s.Store)
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

// Banned returns addr's current ban, if it has one.
func (c *Controller) Banned(ctx context.Context, addr netip.Addr) (Ban, bool, error) {
	if c.bans == nil {
		return Ban{}, false, nil
	}
	return c.bans.Get(ctx, addr)
}

// Resolver returns the client address resolver.
func (c *Controller) Resolver() *Resolver { return c.resolver }
