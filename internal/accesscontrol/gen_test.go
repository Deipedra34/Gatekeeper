package accesscontrol

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
)

// generateEntries returns n deterministic access list entries: a mix of
// single IPv4 and IPv6 addresses and ranges of assorted lengths.
func generateEntries(n int) []string {
	rng := rand.New(rand.NewPCG(1, 2))
	out := make([]string, 0, n)
	for i := range n {
		switch i % 4 {
		case 0:
			out = append(out, fmt.Sprintf("%d.%d.%d.%d", rng.IntN(256), rng.IntN(256), rng.IntN(256), rng.IntN(256)))
		case 1:
			out = append(out, fmt.Sprintf("%d.%d.%d.0/%d", rng.IntN(256), rng.IntN(256), rng.IntN(256), 16+rng.IntN(9)))
		case 2:
			out = append(out, fmt.Sprintf("2001:db8:%x:%x::%x", rng.IntN(1<<16), rng.IntN(1<<16), rng.IntN(1<<16)))
		default:
			out = append(out, fmt.Sprintf("2001:db8:%x::/%d", rng.IntN(1<<16), 40+rng.IntN(25)))
		}
	}
	return out
}

// probeAddr returns a deterministic address to look up: IPv4 for even i,
// IPv6 under 2001:db8::/32 (where the generated IPv6 entries are) for
// odd i.
func probeAddr(i int) netip.Addr {
	rng := rand.New(rand.NewPCG(uint64(i), 7))
	if i%2 == 0 {
		return netip.AddrFrom4([4]byte{byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
	}
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	for j := 4; j < 16; j++ {
		b[j] = byte(rng.IntN(256))
	}
	return netip.AddrFrom16(b)
}
