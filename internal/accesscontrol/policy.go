package accesscontrol

import (
	"fmt"
	"net/netip"
)

// Mode is how a Policy uses its lists.
type Mode string

// Modes, matching the config values.
const (
	ModeOff           Mode = "off"            // no list restriction
	ModeDenylist      Mode = "denylist"       // reject addresses on the deny list
	ModeAllowlistOnly Mode = "allowlist_only" // reject addresses not on the allow list
)

// Reason says why a request was blocked. It's the "reason" label of
// gatekeeper_access_control_blocked_total and the block reason recorded
// on traces.
type Reason string

// Block reasons. ReasonNone means the request may continue.
const (
	ReasonNone           Reason = ""
	ReasonDenyList       Reason = "deny_list"
	ReasonNotInAllowlist Reason = "not_in_allowlist"
	ReasonAutoBan        Reason = "auto_ban"
	ReasonManualBan      Reason = "manual_ban"
)

// Policy is one compiled set of allow/deny rules: the global one, or a
// route's after its override is merged in.
type Policy struct {
	mode       Mode
	allow      *PrefixSet
	deny       *PrefixSet
	denyStatus int
}

// NewPolicy compiles a policy. denyStatus is the status a blocked
// request gets.
func NewPolicy(mode Mode, allow, deny []string, denyStatus int) (*Policy, error) {
	switch mode {
	case ModeOff, ModeDenylist, ModeAllowlistOnly:
	default:
		return nil, fmt.Errorf("accesscontrol: unknown mode %q", mode)
	}
	a, err := NewPrefixSet(allow)
	if err != nil {
		return nil, fmt.Errorf("accesscontrol: allow list: %w", err)
	}
	d, err := NewPrefixSet(deny)
	if err != nil {
		return nil, fmt.Errorf("accesscontrol: deny list: %w", err)
	}
	return &Policy{mode: mode, allow: a, deny: d, denyStatus: denyStatus}, nil
}

// Mode returns the policy's mode.
func (p *Policy) Mode() Mode { return p.mode }

// DenyStatus is the HTTP status a request blocked under this policy
// gets.
func (p *Policy) DenyStatus() int { return p.denyStatus }

// Check decides whether addr may continue. The deny list always wins:
// an address on both lists is blocked. known is false when the client
// address couldn't be determined at all; allowlist_only then blocks
// (fail closed), the other modes let the request through.
func (p *Policy) Check(addr netip.Addr, known bool) Reason {
	if p == nil || p.mode == ModeOff {
		return ReasonNone
	}
	if !known {
		if p.mode == ModeAllowlistOnly {
			return ReasonNotInAllowlist
		}
		return ReasonNone
	}
	if p.deny.Contains(addr) {
		return ReasonDenyList
	}
	if p.mode == ModeAllowlistOnly && !p.allow.Contains(addr) {
		return ReasonNotInAllowlist
	}
	return ReasonNone
}
