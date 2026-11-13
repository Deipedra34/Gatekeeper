package accesscontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func request(remote string, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func TestPeerAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:4711":      "203.0.113.7",
		"[2001:db8::1]:443":     "2001:db8::1",
		"[::ffff:192.0.2.1]:80": "192.0.2.1",
		"[fe80::1%eth0]:80":     "fe80::1",
		"198.51.100.2":          "198.51.100.2", // no port
		"2001:db8::2":           "2001:db8::2",
	}
	for remote, want := range cases {
		a, ok := PeerAddr(request(remote))
		assert.True(t, ok, remote)
		assert.Equal(t, want, a.String(), remote)
	}
	for _, remote := range []string{"", "@", "/var/run/gatekeeper.sock", "example.com:80"} {
		_, ok := PeerAddr(request(remote))
		assert.False(t, ok, remote)
	}
}

func TestResolver_UntrustedPeerCantSpoofItsAddress(t *testing.T) {
	r := NewResolver(MustPrefixSet([]string{"10.0.0.0/8"}))
	for _, hdr := range [][]string{
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Forwarded-For", "10.0.0.1, 192.168.1.1"},
		{"X-Real-IP", "127.0.0.1"},
		{"X-Forwarded-For", "1.1.1.1", "X-Real-IP", "2.2.2.2"},
	} {
		a, ok := r.ClientAddr(request("203.0.113.7:1234", hdr...))
		assert.True(t, ok)
		assert.Equal(t, "203.0.113.7", a.String(), hdr)
	}
}

func TestResolver_NoTrustedProxiesMeansPeerOnly(t *testing.T) {
	for _, r := range []*Resolver{NewResolver(nil), NewResolver(MustPrefixSet(nil))} {
		a, _ := r.ClientAddr(request("10.0.0.1:1", "X-Forwarded-For", "198.51.100.9"))
		assert.Equal(t, "10.0.0.1", a.String())
	}
}

func TestResolver_TrustedProxy(t *testing.T) {
	r := NewResolver(MustPrefixSet([]string{"10.0.0.0/8", "2001:db8:ffff::/48"}))
	cases := []struct {
		name    string
		remote  string
		headers []string
		want    string
	}{
		{"single hop", "10.0.0.1:1", []string{"X-Forwarded-For", "198.51.100.9"}, "198.51.100.9"},
		{"right-most untrusted wins over a spoofed left entry", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "127.0.0.1, 198.51.100.9"}, "198.51.100.9"},
		{"trusted hops are skipped", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "6.6.6.6, 198.51.100.9, 10.2.3.4, 10.9.9.9"}, "198.51.100.9"},
		{"several header lines read as one list", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "6.6.6.6, 198.51.100.9", "X-Forwarded-For", "10.2.3.4"}, "198.51.100.9"},
		{"every hop trusted: the left-most", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "10.3.3.3, 10.2.2.2"}, "10.3.3.3"},
		{"garbage stops the walk at the last trusted hop", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "6.6.6.6, unknown, 10.2.2.2"}, "10.2.2.2"},
		{"garbage right next to the proxy: the proxy itself", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "6.6.6.6, not-an-ip"}, "10.0.0.1"},
		{"empty entries are skipped", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "198.51.100.9, , "}, "198.51.100.9"},
		{"hops with ports", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "[2001:db8::7]:5000, 10.2.2.2:80"}, "2001:db8::7"},
		{"IPv6 client", "10.0.0.1:1", []string{"X-Forwarded-For", "2001:db8:1::5"}, "2001:db8:1::5"},
		{"IPv6 proxy", "[2001:db8:ffff::1]:443", []string{"X-Forwarded-For", "198.51.100.9"}, "198.51.100.9"},
		{"mapped addresses are unmapped", "10.0.0.1:1", []string{"X-Forwarded-For", "::ffff:198.51.100.9"}, "198.51.100.9"},
		{"X-Real-IP without X-Forwarded-For", "10.0.0.1:1", []string{"X-Real-IP", "198.51.100.9"}, "198.51.100.9"},
		{"X-Forwarded-For wins over X-Real-IP", "10.0.0.1:1",
			[]string{"X-Forwarded-For", "198.51.100.9", "X-Real-IP", "6.6.6.6"}, "198.51.100.9"},
		{"invalid X-Real-IP: the peer", "10.0.0.1:1", []string{"X-Real-IP", "nope"}, "10.0.0.1"},
		{"no headers: the peer", "10.0.0.1:1", nil, "10.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := r.ClientAddr(request(c.remote, c.headers...))
			assert.True(t, ok)
			assert.Equal(t, c.want, a.String())
		})
	}
}

func TestResolver_UnknownPeer(t *testing.T) {
	r := NewResolver(MustPrefixSet([]string{"0.0.0.0/0"}))
	_, ok := r.ClientAddr(request("not-an-address", "X-Forwarded-For", "198.51.100.9"))
	assert.False(t, ok)
}
