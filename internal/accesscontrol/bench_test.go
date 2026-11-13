package accesscontrol

import (
	"fmt"
	"net/netip"
	"testing"
)

// BenchmarkPrefixSet_Contains looks addresses up in lists of growing
// size. A lookup is a binary search, so the cost grows with log(n) and
// never allocates.
func BenchmarkPrefixSet_Contains(b *testing.B) {
	for _, n := range []int{10, 1_000, 10_000, 100_000} {
		s := MustPrefixSet(generateEntries(n))
		probes := make([]netip.Addr, 1024)
		for i := range probes {
			probes[i] = probeAddr(i)
		}
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				_ = s.Contains(probes[i&1023])
				i++
			}
		})
	}
}

// BenchmarkPrefixSet_LinearScan is the naive alternative, for
// comparison: checking every prefix in turn.
func BenchmarkPrefixSet_LinearScan(b *testing.B) {
	entries := generateEntries(10_000)
	prefixes := make([]netip.Prefix, len(entries))
	for i, e := range entries {
		prefixes[i], _ = ParseEntry(e)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		a := probeAddr(i & 1023)
		for _, p := range prefixes {
			if p.Contains(a) {
				break
			}
		}
		i++
	}
}

// BenchmarkNewPrefixSet compiles a large list, as config load and every
// reload do.
func BenchmarkNewPrefixSet(b *testing.B) {
	entries := generateEntries(100_000)
	b.ReportAllocs()
	for b.Loop() {
		_ = MustPrefixSet(entries)
	}
}

func BenchmarkResolver_ClientAddr(b *testing.B) {
	r := NewResolver(MustPrefixSet([]string{"10.0.0.0/8", "192.0.2.0/24"}))
	b.Run("untrusted_peer", func(b *testing.B) {
		req := request("203.0.113.7:4711", "X-Forwarded-For", "1.2.3.4")
		b.ReportAllocs()
		for b.Loop() {
			_, _ = r.ClientAddr(req)
		}
	})
	b.Run("two_trusted_hops", func(b *testing.B) {
		req := request("10.0.0.1:4711", "X-Forwarded-For", "198.51.100.7, 192.0.2.4, 10.1.1.1")
		b.ReportAllocs()
		for b.Loop() {
			_, _ = r.ClientAddr(req)
		}
	})
}
