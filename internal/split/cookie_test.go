package split

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieSigner_RoundTrip(t *testing.T) {
	s := NewCookieSigner([]byte("0123456789abcdef"))
	for _, b := range []int{0, 1, 4999, 9999} {
		v := s.Sign("/api", b)
		got, ok := s.Verify("/api", v)
		require.True(t, ok, v)
		assert.Equal(t, b, got)
	}
}

func TestCookieSigner_RejectsForgeries(t *testing.T) {
	s := NewCookieSigner([]byte("0123456789abcdef"))
	good := s.Sign("/api", 42)
	tampered := []byte(good)
	tampered[len(tampered)-1] ^= 1 // always a different character

	for _, v := range []string{
		"",
		"42",
		"42.",
		"9999." + good[3:],  // another bucket, the same signature
		"042." + good[3:],   // a non-canonical number
		"-1." + good[3:],    // out of range
		"10000." + good[3:], // out of range
		string(tampered),    // a tampered signature
		NewCookieSigner([]byte("another-secret-1")).Sign("/api", 42), // another secret
		s.Sign("/other", 42), // another route
	} {
		_, ok := s.Verify("/api", v)
		assert.False(t, ok, "%q", v)
	}
}

func TestCookieSigner_RandomSecretIsPerSigner(t *testing.T) {
	a, b := NewCookieSigner(nil), NewCookieSigner(nil)
	_, ok := b.Verify("/api", a.Sign("/api", 7))
	assert.False(t, ok)
	_, ok = a.Verify("/api", a.Sign("/api", 7))
	assert.True(t, ok)
}

func TestRandomBucket_Spreads(t *testing.T) {
	seen := map[int]bool{}
	for range 1000 {
		b := RandomBucket()
		require.True(t, b >= 0 && b < Buckets, strconv.Itoa(b))
		seen[b/1000] = true
	}
	assert.Len(t, seen, 10)
}
