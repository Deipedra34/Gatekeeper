package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashOf(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// TestMatchToken_ComparesEveryTokenInConstantTime pins down the token
// check's timing-relevant shape: it uses crypto/subtle, always compares
// fixed-length hashes (never the raw token, whose length could leak),
// and compares against every configured token whether or not — and
// wherever — one matches.
func TestMatchToken_ComparesEveryTokenInConstantTime(t *testing.T) {
	assert.Equal(t, reflect.ValueOf(subtle.ConstantTimeCompare).Pointer(), reflect.ValueOf(tokenCompare).Pointer(),
		"token hashes must be compared with subtle.ConstantTimeCompare")

	tokens := []tokenHash{
		{id: "first", hash: hashOf("token-one-aaaaaaaaaaaa")},
		{id: "middle", hash: hashOf("token-two-bbbbbbbbbbbb")},
		{id: "last", hash: hashOf("token-three-cccccccccc")},
	}

	calls := 0
	orig := tokenCompare
	tokenCompare = func(a, b []byte) int {
		calls++
		require.Len(t, a, sha256.Size, "the presented token is hashed before comparing")
		require.Len(t, b, sha256.Size)
		return orig(a, b)
	}
	t.Cleanup(func() { tokenCompare = orig })

	for _, tc := range []struct {
		presented string
		wantID    string
		wantOK    bool
	}{
		{"token-one-aaaaaaaaaaaa", "first", true},
		{"token-two-bbbbbbbbbbbb", "middle", true},
		{"token-three-cccccccccc", "last", true},
		{"token-three-ccccccccc", "", false},  // one character short
		{"token-three-cccccccccd", "", false}, // last character wrong
		{"", "", false},
		{"x", "", false},
	} {
		calls = 0
		id, ok := matchToken(tokens, tc.presented)
		assert.Equal(t, tc.wantOK, ok, tc.presented)
		assert.Equal(t, tc.wantID, id, tc.presented)
		assert.Equal(t, len(tokens), calls, "every token is compared, match or not (%q)", tc.presented)
	}
}

func TestFailureLimiter_LocksOutAfterMaxFailuresUntilWindowEnds(t *testing.T) {
	l := newFailureLimiter(3, time.Minute)
	ip := netip.MustParseAddr("192.0.2.7")
	other := netip.MustParseAddr("192.0.2.8")
	now := time.Now()

	for i := 0; i < 2; i++ {
		l.fail(ip, now)
		assert.Zero(t, l.blocked(ip, now), "under the limit after %d failures", i+1)
	}
	l.fail(ip, now)
	assert.InDelta(t, time.Minute, l.blocked(ip, now.Add(time.Second)), float64(2*time.Second))
	assert.Zero(t, l.blocked(other, now), "other addresses are unaffected")
	assert.Zero(t, l.blocked(ip, now.Add(time.Minute)), "the lockout ends with the window")
}

func TestAuditPath_NeverLogsARawClientKey(t *testing.T) {
	assert.Equal(t, "/admin/v1/ratelimits/key:0123456789ab", auditPath("/admin/v1/ratelimits/key:0123456789ab", true))
	assert.Equal(t, "/admin/v1/ratelimits/10.1.2.3/reset", auditPath("/admin/v1/ratelimits/10.1.2.3/reset", true))
	assert.Equal(t, "/admin/v1/ratelimits/jwt:alice", auditPath("/admin/v1/ratelimits/jwt:alice", true))
	assert.Equal(t, "/admin/v1/ratelimits/[redacted]/reset", auditPath("/admin/v1/ratelimits/sk-live-raw-key/reset", true))
	assert.Equal(t, "/admin/v1/status", auditPath("/admin/v1/status", true))
}
