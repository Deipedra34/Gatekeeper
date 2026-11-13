package accesscontrol

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEntry(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"203.0.113.7", "203.0.113.7/32"},
		{" 203.0.113.7 ", "203.0.113.7/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3/8", "10.0.0.0/8"}, // host bits masked
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2001:DB8::1/48", "2001:db8::/48"},
		{"::/0", "::/0"},
		{"::ffff:192.0.2.1", "192.0.2.1/32"},     // IPv4-mapped -> IPv4
		{"::ffff:192.0.2.0/120", "192.0.2.0/24"}, // mapped range -> IPv4 range
		{"::ffff:0.0.0.0/96", "0.0.0.0/0"},       // the whole mapped space
		{"fe80::1", "fe80::1/128"},               // link-local is fine without a zone
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1/128"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			p, err := ParseEntry(c.in)
			require.NoError(t, err)
			assert.Equal(t, c.want, p.String())
		})
	}
}

func TestParseEntry_Invalid(t *testing.T) {
	for _, in := range []string{
		"", "   ", "localhost", "10.0.0.256", "10.0.0", "10.0.0.0/33", "10.0.0.0/-1",
		"10.0.0.0/", "/8", "2001:db8::/129", "2001:db8:::1", "fe80::1%eth0",
		"fe80::/64%eth0", "::ffff:192.0.2.0/64", "1.2.3.4:80", "10.0.0.0/8/8",
	} {
		t.Run(in, func(t *testing.T) {
			_, err := ParseEntry(in)
			assert.Error(t, err)
		})
	}
}

func TestNewPrefixSet_ReportsTheBadEntry(t *testing.T) {
	_, err := NewPrefixSet([]string{"10.0.0.0/8", "192.168.1.1", "not-an-ip", "::1"})
	require.Error(t, err)
	var ee *EntryError
	require.True(t, errors.As(err, &ee))
	assert.Equal(t, 2, ee.Index)
	assert.Contains(t, err.Error(), `"not-an-ip"`)
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestPrefixSet_IPv4(t *testing.T) {
	s := MustPrefixSet([]string{"203.0.113.7", "10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12"})
	assert.Equal(t, 4, s.Len())

	for _, in := range []string{
		"203.0.113.7",                // single address
		"10.0.0.0", "10.255.255.255", // range boundaries
		"10.42.0.1",
		"192.168.0.0", "192.168.0.255",
		"172.16.0.1", "172.31.255.255",
		"::ffff:10.1.2.3", // IPv4-mapped IPv6 matches the IPv4 entry
	} {
		assert.True(t, s.Contains(addr(in)), in)
	}
	for _, in := range []string{
		"203.0.113.6", "203.0.113.8", // neighbours of a single address
		"9.255.255.255", "11.0.0.0", // just outside a range
		"192.168.1.0", "172.32.0.0", "172.15.255.255",
		"0.0.0.0", "255.255.255.255",
		"::a00:1", // the IPv6 address with the same low bits as 10.0.0.1 is not IPv4
	} {
		assert.False(t, s.Contains(addr(in)), in)
	}
}

func TestPrefixSet_IPv6(t *testing.T) {
	s := MustPrefixSet([]string{"2001:db8::1", "2001:db8:abcd::/48", "fd00::/8", "::1"})

	for _, in := range []string{
		"2001:db8::1",
		"2001:db8:abcd::", "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff", "2001:db8:abcd:12::7",
		"fd00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::1",
	} {
		assert.True(t, s.Contains(addr(in)), in)
	}
	for _, in := range []string{
		"2001:db8::2", "2001:db8::",
		"2001:db8:abce::", "2001:db8:abcc:ffff:ffff:ffff:ffff:ffff",
		"fc00::1", "fe00::",
		"::2", "::",
		"127.0.0.1", // IPv4 loopback is not ::1
	} {
		assert.False(t, s.Contains(addr(in)), in)
	}
}

func TestPrefixSet_ZoneIsIgnored(t *testing.T) {
	s := MustPrefixSet([]string{"fe80::/10"})
	assert.True(t, s.Contains(addr("fe80::1%eth0")))
}

func TestPrefixSet_MatchEverything(t *testing.T) {
	v4 := MustPrefixSet([]string{"0.0.0.0/0"})
	assert.True(t, v4.Contains(addr("0.0.0.0")))
	assert.True(t, v4.Contains(addr("255.255.255.255")))
	assert.False(t, v4.Contains(addr("::1")))

	v6 := MustPrefixSet([]string{"::/0"})
	assert.True(t, v6.Contains(addr("::")))
	assert.True(t, v6.Contains(addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))
	assert.False(t, v6.Contains(addr("10.0.0.1")))
}

func TestPrefixSet_OverlappingAndAdjacentEntriesMerge(t *testing.T) {
	s := MustPrefixSet([]string{
		"10.0.0.0/8", "10.1.0.0/16", "10.1.2.3", // nested
		"192.168.0.0/25", "192.168.0.128/25", // adjacent: one /24
		"2001:db8::/33", "2001:db8:8000::/33", // adjacent: one /32
		"2001:db8::/48",                      // nested
		"255.255.255.255", "255.255.255.254", // at the top of the space
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	})
	assert.Len(t, s.v4, 3)
	assert.Len(t, s.v6, 2)
	assert.True(t, s.Contains(addr("192.168.0.127")))
	assert.True(t, s.Contains(addr("192.168.0.128")))
	assert.False(t, s.Contains(addr("192.168.1.0")))
	assert.True(t, s.Contains(addr("2001:db8:7fff::1")))
	assert.True(t, s.Contains(addr("2001:db8:8000::1")))
	assert.False(t, s.Contains(addr("2001:db9::")))
	assert.True(t, s.Contains(addr("255.255.255.255")))
	assert.True(t, s.Contains(addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))
}

func TestPrefixSet_Empty(t *testing.T) {
	var nilSet *PrefixSet
	assert.False(t, nilSet.Contains(addr("10.0.0.1")))
	assert.True(t, nilSet.Empty())
	assert.Equal(t, 0, nilSet.Len())

	s := MustPrefixSet(nil)
	assert.False(t, s.Contains(addr("10.0.0.1")))
	assert.False(t, s.Contains(netip.Addr{}))
	assert.True(t, s.Empty())
}

// TestPrefixSet_AgainstLinearScan checks the compiled table against the
// obvious implementation over many generated entries and probes.
func TestPrefixSet_AgainstLinearScan(t *testing.T) {
	entries := generateEntries(2000)
	s := MustPrefixSet(entries)
	prefixes := make([]netip.Prefix, len(entries))
	for i, e := range entries {
		prefixes[i], _ = ParseEntry(e)
	}
	for i := range 5000 {
		a := probeAddr(i)
		want := false
		for _, p := range prefixes {
			if p.Contains(a) {
				want = true
				break
			}
		}
		require.Equal(t, want, s.Contains(a), a.String())
	}
	// And every entry's own first and last address is a hit.
	for _, p := range prefixes {
		require.True(t, s.Contains(p.Addr()), p.String())
		last := p.Addr().As16()
		if p.Addr().Is4() {
			v4 := p.Addr().As4()
			for i := p.Bits(); i < 32; i++ {
				v4[i/8] |= 0x80 >> (i % 8)
			}
			require.True(t, s.Contains(netip.AddrFrom4(v4)), p.String())
			continue
		}
		for i := p.Bits(); i < 128; i++ {
			last[i/8] |= 0x80 >> (i % 8)
		}
		require.True(t, s.Contains(netip.AddrFrom16(last)), p.String())
	}
}
