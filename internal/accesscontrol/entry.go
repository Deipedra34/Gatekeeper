// Package accesscontrol decides which client IP addresses may use the
// gateway: compiled allow and deny lists of single addresses and CIDR
// ranges (IPv4 and IPv6), the client address itself as seen through any
// trusted proxies, and temporary bans kept in the shared store.
//
// It doesn't know about config files or HTTP middleware; the gateway
// builds a Controller from the config and the middleware package asks it
// what to do with each request.
package accesscontrol

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ParseEntry parses one access list entry: a single IPv4 or IPv6
// address ("203.0.113.7", "2001:db8::1") or a CIDR range
// ("10.0.0.0/8", "2001:db8::/32"). A single address becomes a /32 or
// /128 prefix. Host bits set in a range ("10.1.2.3/8") are masked off,
// as most tools do.
//
// IPv4-mapped IPv6 addresses ("::ffff:192.0.2.1") are stored as plain
// IPv4, so an entry matches a client however its address is written.
// Zones ("fe80::1%eth0") are rejected: they only mean something on the
// host that wrote them.
func ParseEntry(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("empty entry")
	}
	if strings.Contains(s, "%") {
		return netip.Prefix{}, fmt.Errorf("%q: IPv6 zones are not allowed", s)
	}

	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR range", s)
		}
		if a := p.Addr(); a.Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("%q: an IPv4-mapped range needs a prefix length of at least 96", s)
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}

	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid IP address or CIDR range", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
