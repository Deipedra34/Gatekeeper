package accesscontrol

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func autoBanController(t *testing.T, s AutoBanSettings, neverBan ...string) *Controller {
	t.Helper()
	if s.Triggers == nil {
		s.Triggers = []Offense{OffenseRateLimit, OffenseAuthFailure, OffenseDenied}
	}
	c, err := NewController(Settings{Store: memStore(t), AutoBan: &s, NeverBan: neverBan, TrustedProxies: []string{"10.0.0.1"}})
	require.NoError(t, err)
	return c
}

func TestAutoBan_BansAtTheThreshold(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 3, Window: time.Minute, BanDuration: 10 * time.Minute})
	client := addr("203.0.113.7")

	for i := range 2 {
		_, banned, err := c.RecordOffense(ctx, client, OffenseRateLimit)
		require.NoError(t, err)
		assert.False(t, banned, "offense %d", i+1)
	}
	_, banned, _ := c.Banned(ctx, client)
	assert.False(t, banned)

	start := time.Now()
	ban, banned, err := c.RecordOffense(ctx, client, OffenseAuthFailure) // offenses of any trigger add up
	require.NoError(t, err)
	require.True(t, banned)
	assert.Equal(t, "203.0.113.7", ban.IP)
	assert.Equal(t, SourceAuto, ban.Source)
	assert.Equal(t, 1, ban.Level)
	assert.Contains(t, ban.Reason, "auth_failure")
	assert.WithinDuration(t, start.Add(10*time.Minute), ban.ExpiresAt, 2*time.Second)

	got, banned, err := c.Banned(ctx, client)
	require.NoError(t, err)
	assert.True(t, banned)
	assert.Equal(t, ban.ExpiresAt.Unix(), got.ExpiresAt.Unix())

	// Another address is unaffected.
	_, banned, _ = c.Banned(ctx, addr("203.0.113.8"))
	assert.False(t, banned)
}

func TestAutoBan_OnlyConfiguredTriggersCount(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 1, Window: time.Minute, BanDuration: time.Minute, Triggers: []Offense{OffenseAuthFailure}})
	client := addr("203.0.113.7")
	for range 5 {
		_, banned, err := c.RecordOffense(ctx, client, OffenseRateLimit)
		require.NoError(t, err)
		assert.False(t, banned)
		_, banned, _ = c.RecordOffense(ctx, client, OffenseDenied)
		assert.False(t, banned)
	}
	_, banned, _ := c.RecordOffense(ctx, client, OffenseAuthFailure)
	assert.True(t, banned)
}

func TestAutoBan_OffensesOutsideTheWindowDontCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// The window is long enough that the two offenses after the sleep
	// land in the same one even on a slow runner (-race).
	c := autoBanController(t, AutoBanSettings{Threshold: 2, Window: time.Second, BanDuration: time.Minute})
	client := addr("203.0.113.7")
	_, banned, _ := c.RecordOffense(ctx, client, OffenseRateLimit)
	require.False(t, banned)
	time.Sleep(1500 * time.Millisecond) // the window ends
	_, banned, _ = c.RecordOffense(ctx, client, OffenseRateLimit)
	assert.False(t, banned, "the first offense expired with its window")
	_, banned, _ = c.RecordOffense(ctx, client, OffenseRateLimit)
	assert.True(t, banned)
}

func TestAutoBan_BanExpires(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 1, Window: time.Minute, BanDuration: 100 * time.Millisecond})
	client := addr("2001:db8::7")
	_, banned, _ := c.RecordOffense(ctx, client, OffenseDenied)
	require.True(t, banned)
	_, banned, _ = c.Banned(ctx, client)
	require.True(t, banned)
	time.Sleep(250 * time.Millisecond)
	_, banned, err := c.Banned(ctx, client)
	require.NoError(t, err)
	assert.False(t, banned)
	n, _ := c.Bans().Count(ctx)
	assert.Equal(t, 0, n)
}

func TestAutoBan_Escalation(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{
		Threshold: 1, Window: time.Minute, BanDuration: time.Minute,
		Escalation: EscalationSettings{Enabled: true, Multiplier: 3, MaxDuration: 20 * time.Minute, ResetAfter: time.Hour},
	})
	client := addr("203.0.113.7")

	want := []struct {
		level int
		d     time.Duration
	}{{1, time.Minute}, {2, 3 * time.Minute}, {3, 9 * time.Minute}, {4, 20 * time.Minute}, {5, 20 * time.Minute}}
	for _, w := range want {
		before := time.Now()
		ban, banned, err := c.RecordOffense(ctx, client, OffenseRateLimit)
		require.NoError(t, err)
		require.True(t, banned)
		assert.Equal(t, w.level, ban.Level)
		assert.WithinDuration(t, before.Add(w.d), ban.ExpiresAt, 2*time.Second, "level %d", w.level)
		// Lift it (as an operator would) so the next offense counts.
		_, err = c.Unban(ctx, client)
		require.NoError(t, err)
	}

	// Escalation is per address.
	ban, _, _ := c.RecordOffense(ctx, addr("203.0.113.8"), OffenseRateLimit)
	assert.Equal(t, 1, ban.Level)
}

func TestAutoBan_EscalationResetsAfterAQuietPeriod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// reset_after is long enough that the first two bans escalate even
	// on a slow runner (-race).
	c := autoBanController(t, AutoBanSettings{
		Threshold: 1, Window: time.Minute, BanDuration: time.Minute,
		Escalation: EscalationSettings{Enabled: true, Multiplier: 2, MaxDuration: time.Hour, ResetAfter: time.Second},
	})
	client := addr("203.0.113.7")
	ban, _, _ := c.RecordOffense(ctx, client, OffenseRateLimit)
	require.Equal(t, 1, ban.Level)
	_, _ = c.Unban(ctx, client)
	ban, _, _ = c.RecordOffense(ctx, client, OffenseRateLimit)
	require.Equal(t, 2, ban.Level)
	_, _ = c.Unban(ctx, client)

	time.Sleep(1500 * time.Millisecond) // longer than reset_after since the last ban
	ban, _, err := c.RecordOffense(ctx, client, OffenseRateLimit)
	require.NoError(t, err)
	assert.Equal(t, 1, ban.Level)
	assert.WithinDuration(t, time.Now().Add(time.Minute), ban.ExpiresAt, 2*time.Second)
}

func TestAutoBan_WithoutEscalationEveryBanIsTheSame(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 1, Window: time.Minute, BanDuration: time.Minute})
	client := addr("203.0.113.7")
	for range 3 {
		ban, banned, _ := c.RecordOffense(ctx, client, OffenseRateLimit)
		require.True(t, banned)
		assert.Equal(t, 1, ban.Level)
		_, _ = c.Unban(ctx, client)
	}
}

func TestAutoBan_Duration(t *testing.T) {
	ab := NewAutoBan(nil, nil, AutoBanSettings{
		BanDuration: 10 * time.Minute,
		Escalation:  EscalationSettings{Enabled: true, Multiplier: 2, MaxDuration: 24 * time.Hour},
	})
	assert.Equal(t, 10*time.Minute, ab.Duration(0))
	assert.Equal(t, 10*time.Minute, ab.Duration(1))
	assert.Equal(t, 20*time.Minute, ab.Duration(2))
	assert.Equal(t, 80*time.Minute, ab.Duration(4))
	assert.Equal(t, 24*time.Hour, ab.Duration(10))
	assert.Equal(t, 24*time.Hour, ab.Duration(1_000_000), "no overflow")
}

func TestAutoBan_NeverBanIsRespected(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 1, Window: time.Minute, BanDuration: time.Minute},
		"127.0.0.1", "192.0.2.0/24", "2001:db8:a::/48")
	for _, ip := range []string{"127.0.0.1", "192.0.2.200", "2001:db8:a::5", "::ffff:127.0.0.1", "10.0.0.1" /* trusted proxy */} {
		for range 3 {
			_, banned, err := c.RecordOffense(ctx, addr(ip), OffenseAuthFailure)
			require.NoError(t, err)
			assert.False(t, banned, ip)
		}
		_, banned, _ := c.Banned(ctx, addr(ip))
		assert.False(t, banned, ip)
	}
	_, banned, _ := c.RecordOffense(ctx, addr("192.0.3.1"), OffenseAuthFailure)
	assert.True(t, banned, "just outside never_ban")
}

func TestAutoBan_ConcurrentOffensesBanOnce(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 10, Window: time.Minute, BanDuration: time.Minute,
		Escalation: EscalationSettings{Enabled: true, Multiplier: 2, MaxDuration: time.Hour, ResetAfter: time.Hour}})
	client := addr("203.0.113.7")
	var bans atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, banned, err := c.RecordOffense(ctx, client, OffenseRateLimit)
			assert.NoError(t, err)
			if banned {
				bans.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, bans.Load(), "exactly one request issues the ban")
	ban, banned, _ := c.Banned(ctx, client)
	require.True(t, banned)
	assert.Equal(t, 1, ban.Level, "and escalation counted it once")
}

func TestAutoBan_DisabledRecordsNothing(t *testing.T) {
	ctx := context.Background()
	c, err := NewController(Settings{Store: memStore(t)})
	require.NoError(t, err)
	for range 100 {
		_, banned, err := c.RecordOffense(ctx, addr("203.0.113.7"), OffenseRateLimit)
		require.NoError(t, err)
		require.False(t, banned)
	}
}

func TestAutoBan_StillBannedAddressIsNotBannedAgain(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{
		Threshold: 1, Window: 100 * time.Millisecond, BanDuration: time.Hour,
		Escalation: EscalationSettings{Enabled: true, Multiplier: 2, MaxDuration: 24 * time.Hour, ResetAfter: time.Hour},
	})
	client := addr("203.0.113.7")
	first, banned, _ := c.RecordOffense(ctx, client, OffenseDenied)
	require.True(t, banned)

	// A new window, and the threshold is reached again while the ban is
	// still in force (an allowlist keeps rejecting the address).
	time.Sleep(250 * time.Millisecond)
	_, banned, err := c.RecordOffense(ctx, client, OffenseDenied)
	require.NoError(t, err)
	assert.False(t, banned)
	current, _, _ := c.Banned(ctx, client)
	assert.Equal(t, first.Level, current.Level, "not escalated")
	assert.Equal(t, first.ExpiresAt.Unix(), current.ExpiresAt.Unix(), "not extended")
}

func TestAutoBan_UnbanStartsTheCountOver(t *testing.T) {
	ctx := context.Background()
	c := autoBanController(t, AutoBanSettings{Threshold: 2, Window: time.Minute, BanDuration: time.Minute})
	client := addr("203.0.113.7")
	_, _, _ = c.RecordOffense(ctx, client, OffenseRateLimit)
	_, _ = c.Unban(ctx, client) // nothing to lift, but the count is cleared
	_, banned, _ := c.RecordOffense(ctx, client, OffenseRateLimit)
	assert.False(t, banned)
	_, banned, _ = c.RecordOffense(ctx, client, OffenseRateLimit)
	assert.True(t, banned)
}
