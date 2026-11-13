package accesscontrol

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// PeerAddr is the address of the connection's immediate peer, from
// r.RemoteAddr — the one address a client can't choose freely. IPv4-
// mapped IPv6 addresses are unmapped and zones dropped, so it compares
// equal to the entries in a PrefixSet. ok is false if RemoteAddr isn't
// an IP address (a Unix socket, or a hand-built test request).
func PeerAddr(r *http.Request) (addr netip.Addr, ok bool) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return normalize(ap.Addr()), true
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return normalize(a), true
}

func normalize(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// Resolver works out the real client address of a request. Forwarding
// headers are only believed when the connection's peer is a trusted
// proxy; from anyone else they're ignored, so a client can't pick its
// own address by sending X-Forwarded-For.
type Resolver struct {
	trusted *PrefixSet
}

// NewResolver returns a Resolver trusting the proxies in trusted (nil or
// empty: none, so the peer address is always the client).
func NewResolver(trusted *PrefixSet) *Resolver {
	return &Resolver{trusted: trusted}
}

// Trusted reports whether a is one of the trusted proxies.
func (r *Resolver) Trusted(a netip.Addr) bool {
	return r != nil && r.trusted.Contains(a)
}

// ClientAddr returns the client address of req:
//
//   - the peer address, if the peer isn't a trusted proxy;
//   - otherwise the right-most X-Forwarded-For address that isn't a
//     trusted proxy. Every proxy appends the address it received the
//     request from, so walking right to left past the proxies we trust
//     lands on the first hop nobody we trust vouches for — anything
//     further left was written by the client and may be forged. If a
//     hop doesn't parse as an address, the walk stops at the last
//     trusted hop before it. If every hop is trusted, the left-most one
//     is the client;
//   - without X-Forwarded-For, X-Real-IP if it holds a valid address;
//   - otherwise the peer address.
//
// ok is false only when the peer address itself can't be determined.
func (r *Resolver) ClientAddr(req *http.Request) (addr netip.Addr, ok bool) {
	peer, ok := PeerAddr(req)
	if !ok || !r.Trusted(peer) {
		return peer, ok
	}

	if values := req.Header.Values("X-Forwarded-For"); len(values) > 0 {
		client := peer
		for i := len(values) - 1; i >= 0; i-- {
			v := values[i]
			for end := len(v); end >= 0; {
				start := strings.LastIndexByte(v[:end], ',') + 1
				hop := strings.TrimSpace(v[start:end])
				end = start - 1
				if hop == "" {
					continue
				}
				a, ok := parseHop(hop)
				if !ok {
					return client, true
				}
				client = a
				if !r.Trusted(a) {
					return a, true
				}
			}
		}
		return client, true
	}

	if a, ok := parseHop(strings.TrimSpace(req.Header.Get("X-Real-IP"))); ok {
		return a, true
	}
	return peer, true
}

// parseHop parses one forwarding header address, which some proxies
// write with a port ("203.0.113.7:4711", "[2001:db8::1]:443").
func parseHop(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return normalize(a), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return normalize(ap.Addr()), true
	}
	return netip.Addr{}, false
}
