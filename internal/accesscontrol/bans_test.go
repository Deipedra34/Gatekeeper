package accesscontrol

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/ratelimiter/store"
)

func memStore(t *testing.T) store.Store {
	t.Helper()
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	return st
}

func manualBan(ip string, d time.Duration) Ban {
	now := time.Now().UTC()
	return Ban{IP: ip, Source: SourceManual, BannedAt: now, ExpiresAt: now.Add(d)}
}

func TestBanList_AddGetRemove(t *testing.T) {
	ctx := context.Background()
	b := NewBanList(memStore(t))

	_, found, err := b.Get(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, b.Add(ctx, manualBan("203.0.113.7", time.Hour)))
	require.NoError(t, b.Add(ctx, manualBan("::ffff:198.51.100.1", time.Hour))) // stored unmapped
	require.NoError(t, b.Add(ctx, manualBan("2001:db8::1", time.Hour)))

	ban, found, err := b.Get(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "203.0.113.7", ban.IP)
	assert.Equal(t, SourceManual, ban.Source)
	_, found, _ = b.Get(ctx, addr("198.51.100.1"))
	assert.True(t, found)
	_, found, _ = b.Get(ctx, addr("::ffff:198.51.100.1"))
	assert.True(t, found, "a mapped address finds the ban of its IPv4 form")

	bans, err := b.List(ctx)
	require.NoError(t, err)
	require.Len(t, bans, 3)
	assert.Equal(t, []string{"198.51.100.1", "2001:db8::1", "203.0.113.7"}, []string{bans[0].IP, bans[1].IP, bans[2].IP})
	n, err := b.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, n)

	removed, err := b.Remove(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = b.Remove(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.False(t, removed, "nothing left to remove")
	_, found, _ = b.Get(ctx, addr("203.0.113.7"))
	assert.False(t, found)
	n, _ = b.Count(ctx)
	assert.Equal(t, 2, n)
}

func TestBanList_ReplacesAnExistingBan(t *testing.T) {
	ctx := context.Background()
	b := NewBanList(memStore(t))
	require.NoError(t, b.Add(ctx, manualBan("203.0.113.7", time.Minute)))
	longer := manualBan("203.0.113.7", time.Hour)
	longer.Reason = "second"
	require.NoError(t, b.Add(ctx, longer))
	ban, _, _ := b.Get(ctx, addr("203.0.113.7"))
	assert.Equal(t, "second", ban.Reason)
	bans, _ := b.List(ctx)
	assert.Len(t, bans, 1)
}

func TestBanList_RejectsBadBans(t *testing.T) {
	ctx := context.Background()
	b := NewBanList(memStore(t))
	assert.Error(t, b.Add(ctx, manualBan("10.0.0.0/8", time.Hour)))
	assert.Error(t, b.Add(ctx, manualBan("nope", time.Hour)))
	assert.Error(t, b.Add(ctx, manualBan("10.0.0.1", -time.Second)))
}

func TestBanList_Expiry(t *testing.T) {
	ctx := context.Background()
	st := memStore(t)
	b := NewBanList(st)
	require.NoError(t, b.Add(ctx, manualBan("203.0.113.7", time.Hour)))
	require.NoError(t, b.Add(ctx, manualBan("203.0.113.8", 2*time.Hour)))

	// Ninety minutes later the first ban is over: Get, List, and Count
	// all stop reporting it, and the index is pruned.
	later := time.Now().Add(90 * time.Minute)
	b.now = func() time.Time { return later }
	_, found, err := b.Get(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.False(t, found)
	_, found, _ = b.Get(ctx, addr("203.0.113.8"))
	assert.True(t, found)
	n, _ := b.Count(ctx)
	assert.Equal(t, 1, n)
	bans, err := b.List(ctx)
	require.NoError(t, err)
	require.Len(t, bans, 1)
	assert.Equal(t, "203.0.113.8", bans[0].IP)
	idx, _, err := b.loadIndex(ctx)
	require.NoError(t, err)
	assert.NotContains(t, idx, "203.0.113.7")
}

func TestBanList_KeyExpiresInTheStore(t *testing.T) {
	ctx := context.Background()
	b := NewBanList(memStore(t))
	require.NoError(t, b.Add(ctx, manualBan("203.0.113.7", 50*time.Millisecond)))
	_, found, _ := b.Get(ctx, addr("203.0.113.7"))
	require.True(t, found)
	time.Sleep(150 * time.Millisecond)
	_, found, err := b.Get(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.False(t, found, "the store dropped the ban on its own")
	n, _ := b.Count(ctx)
	assert.Equal(t, 0, n)
}

func TestBanList_ConcurrentAddsAllLandInTheIndex(t *testing.T) {
	ctx := context.Background()
	b := NewBanList(memStore(t))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := addr("203.0.113.0").As4()
			ip[3] = byte(i + 1)
			assert.NoError(t, b.Add(ctx, manualBan(netip.AddrFrom4(ip).String(), time.Hour)))
		}()
	}
	wg.Wait()
	n, err := b.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 8, n)
}

// TestBans_SharedThroughRedis runs two controllers — two gateway
// instances — against one Redis: a ban issued by either is enforced by
// both, and lifting it on one lifts it everywhere.
func TestBans_SharedThroughRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	newInstance := func() *Controller {
		st := store.NewRedisStore(mr.Addr(), "", 0, time.Second)
		t.Cleanup(func() { st.Close() })
		c, err := NewController(Settings{
			Global:  PolicySettings{Mode: ModeOff},
			Store:   st,
			AutoBan: &AutoBanSettings{Threshold: 3, Window: time.Minute, BanDuration: time.Hour, Triggers: []Offense{OffenseAuthFailure}},
		})
		require.NoError(t, err)
		return c
	}
	a, b := newInstance(), newInstance()
	ctx := context.Background()

	_, err := a.Ban(ctx, addr("203.0.113.7"), time.Hour, "manual")
	require.NoError(t, err)
	_, banned, err := b.Banned(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.True(t, banned, "instance b sees instance a's ban")

	// Offenses seen by different instances add up.
	client := addr("198.51.100.9")
	_, banned, _ = a.RecordOffense(ctx, client, OffenseAuthFailure)
	assert.False(t, banned)
	_, banned, _ = b.RecordOffense(ctx, client, OffenseAuthFailure)
	assert.False(t, banned)
	ban, banned, err := a.RecordOffense(ctx, client, OffenseAuthFailure)
	require.NoError(t, err)
	require.True(t, banned)
	assert.Equal(t, SourceAuto, ban.Source)
	_, banned, _ = b.Banned(ctx, client)
	assert.True(t, banned)

	bans, err := b.Bans().List(ctx)
	require.NoError(t, err)
	assert.Len(t, bans, 2)

	found, err := b.Unban(ctx, addr("203.0.113.7"))
	require.NoError(t, err)
	assert.True(t, found)
	_, banned, _ = a.Banned(ctx, addr("203.0.113.7"))
	assert.False(t, banned, "lifted everywhere")

	// Redis expires the ban key itself.
	mr.FastForward(2 * time.Hour)
	_, banned, _ = a.Banned(ctx, client)
	assert.False(t, banned)
}

func TestController_BanRules(t *testing.T) {
	ctx := context.Background()
	c, err := NewController(Settings{
		Store:          memStore(t),
		TrustedProxies: []string{"10.0.0.1"},
		NeverBan:       []string{"127.0.0.0/8", "::1", "192.0.2.0/24"},
	})
	require.NoError(t, err)

	for _, ip := range []string{"127.0.0.1", "::1", "192.0.2.55", "10.0.0.1"} {
		_, err := c.Ban(ctx, addr(ip), time.Hour, "")
		assert.ErrorIs(t, err, ErrProtected, ip)
	}
	_, err = c.Ban(ctx, addr("203.0.113.7"), 0, "")
	assert.Error(t, err)

	ban, err := c.Ban(ctx, addr("::ffff:203.0.113.7"), time.Hour, "abuse report")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", ban.IP)
	assert.Equal(t, SourceManual, ban.Source)
	assert.Equal(t, DefaultManualBanDuration, c.DefaultBanDuration())

	// A ban stored before an address became protected (say, never_ban
	// grew in a reload) isn't enforced.
	require.NoError(t, c.Bans().Add(ctx, manualBan("192.0.2.55", time.Hour)))
	_, banned, err := c.Banned(ctx, addr("192.0.2.55"))
	require.NoError(t, err)
	assert.False(t, banned)

	noStore, err := NewController(Settings{})
	require.NoError(t, err)
	_, err = noStore.Ban(ctx, addr("203.0.113.7"), time.Hour, "")
	assert.ErrorIs(t, err, ErrBansDisabled)
	_, err = noStore.Unban(ctx, addr("203.0.113.7"))
	assert.ErrorIs(t, err, ErrBansDisabled)
	_, banned, err = noStore.Banned(ctx, addr("203.0.113.7"))
	assert.NoError(t, err)
	assert.False(t, banned)
}
