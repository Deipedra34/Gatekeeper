package accesscontrol

import (
	"fmt"
	"net/http"
	"net/netip"
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
}

// Controller is the compiled access control of one config: built when
// the config is loaded or reloaded, read-only afterwards, so requests
// use it without locking.
type Controller struct {
	resolver *Resolver
	global   *Policy
	routes   map[string]*Policy
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

// Resolver returns the client address resolver.
func (c *Controller) Resolver() *Resolver { return c.resolver }
