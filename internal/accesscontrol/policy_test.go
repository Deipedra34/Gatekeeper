package accesscontrol

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustPolicy(t *testing.T, mode Mode, allow, deny []string) *Policy {
	t.Helper()
	p, err := NewPolicy(mode, allow, deny, http.StatusForbidden)
	require.NoError(t, err)
	return p
}

func TestPolicy_Off(t *testing.T) {
	p := mustPolicy(t, ModeOff, []string{"10.0.0.0/8"}, []string{"0.0.0.0/0", "::/0"})
	assert.Equal(t, ReasonNone, p.Check(addr("198.51.100.1"), true))
	assert.Equal(t, ReasonNone, p.Check(addr("2001:db8::1"), true))
	assert.Equal(t, ReasonNone, p.Check(addr("10.0.0.1"), false))

	var nilPolicy *Policy
	assert.Equal(t, ReasonNone, nilPolicy.Check(addr("198.51.100.1"), true))
}

func TestPolicy_Denylist(t *testing.T) {
	p := mustPolicy(t, ModeDenylist, nil, []string{"198.51.100.0/24", "2001:db8:bad::/48", "203.0.113.7"})
	assert.Equal(t, ReasonDenyList, p.Check(addr("198.51.100.20"), true))
	assert.Equal(t, ReasonDenyList, p.Check(addr("2001:db8:bad::1"), true))
	assert.Equal(t, ReasonDenyList, p.Check(addr("203.0.113.7"), true))
	assert.Equal(t, ReasonNone, p.Check(addr("203.0.113.8"), true))
	assert.Equal(t, ReasonNone, p.Check(addr("2001:db8:900d::1"), true))
	// Unknown client address: only denied addresses are rejected, and
	// this one can't be shown to be one.
	assert.Equal(t, ReasonNone, p.Check(addr("198.51.100.20"), false))
}

func TestPolicy_AllowlistOnly(t *testing.T) {
	p := mustPolicy(t, ModeAllowlistOnly, []string{"10.0.0.0/8", "2001:db8::/32"}, nil)
	assert.Equal(t, ReasonNone, p.Check(addr("10.1.2.3"), true))
	assert.Equal(t, ReasonNone, p.Check(addr("2001:db8::1"), true))
	assert.Equal(t, ReasonNotInAllowlist, p.Check(addr("11.0.0.1"), true))
	assert.Equal(t, ReasonNotInAllowlist, p.Check(addr("2001:db9::1"), true))
	// Unknown client address: fail closed.
	assert.Equal(t, ReasonNotInAllowlist, p.Check(addr("10.1.2.3"), false))
}

func TestPolicy_DenyWinsOverAllow(t *testing.T) {
	allow := []string{"10.0.0.0/8", "2001:db8::/32"}
	deny := []string{"10.6.6.0/24", "2001:db8:6::/48"}
	for _, mode := range []Mode{ModeAllowlistOnly, ModeDenylist} {
		p := mustPolicy(t, mode, allow, deny)
		assert.Equal(t, ReasonDenyList, p.Check(addr("10.6.6.6"), true), mode)
		assert.Equal(t, ReasonDenyList, p.Check(addr("2001:db8:6::1"), true), mode)
		assert.Equal(t, ReasonNone, p.Check(addr("10.7.7.7"), true), mode)
	}
	// The same address on both lists.
	p := mustPolicy(t, ModeAllowlistOnly, []string{"203.0.113.7"}, []string{"203.0.113.7"})
	assert.Equal(t, ReasonDenyList, p.Check(addr("203.0.113.7"), true))
}

func TestNewPolicy_Errors(t *testing.T) {
	_, err := NewPolicy("strict", nil, nil, 403)
	assert.Error(t, err)
	_, err = NewPolicy(ModeDenylist, nil, []string{"10.0.0.0/40"}, 403)
	assert.ErrorContains(t, err, "deny list")
	_, err = NewPolicy(ModeAllowlistOnly, []string{"nope"}, nil, 403)
	assert.ErrorContains(t, err, "allow list")
}

func TestController_RouteOverridesGlobal(t *testing.T) {
	c, err := NewController(Settings{
		Global: PolicySettings{Mode: ModeDenylist, Deny: []string{"198.51.100.0/24"}},
		Routes: map[string]PolicySettings{
			"/admin":  {Mode: ModeAllowlistOnly, Allow: []string{"10.0.0.0/8"}, DenyStatus: http.StatusNotFound},
			"/public": {Mode: ModeOff},
		},
	})
	require.NoError(t, err)

	global := c.PolicyFor("/api")
	assert.Equal(t, ModeDenylist, global.Mode())
	assert.Equal(t, http.StatusForbidden, global.DenyStatus())
	assert.Equal(t, ReasonDenyList, global.Check(addr("198.51.100.1"), true))
	assert.Equal(t, ReasonNone, global.Check(addr("203.0.113.1"), true))
	assert.Same(t, global, c.PolicyFor(""), "a request matching no route gets the global policy")

	admin := c.PolicyFor("/admin")
	assert.Equal(t, http.StatusNotFound, admin.DenyStatus())
	assert.Equal(t, ReasonNotInAllowlist, admin.Check(addr("203.0.113.1"), true))
	assert.Equal(t, ReasonNone, admin.Check(addr("10.0.0.1"), true))

	assert.Equal(t, ReasonNone, c.PolicyFor("/public").Check(addr("198.51.100.1"), true))
}

func TestNewController_Errors(t *testing.T) {
	_, err := NewController(Settings{TrustedProxies: []string{"proxy.internal"}})
	assert.ErrorContains(t, err, "trusted proxies")
	_, err = NewController(Settings{NeverBan: []string{"10.0.0.0/99"}})
	assert.ErrorContains(t, err, "never_ban")
	_, err = NewController(Settings{Routes: map[string]PolicySettings{"/x": {Mode: ModeDenylist, Deny: []string{"x"}}}})
	assert.ErrorContains(t, err, "/x")
}
