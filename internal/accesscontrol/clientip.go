package accesscontrol

import (
	"net"
	"net/http"
	"net/netip"
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
