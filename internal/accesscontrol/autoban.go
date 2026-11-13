package accesscontrol

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// Offense is an event that counts toward an automatic ban. The values
// match the auto_ban.triggers config values.
type Offense string

// Offenses.
const (
	OffenseRateLimit   Offense = "rate_limit"   // rejected by the rate limiter
	OffenseAuthFailure Offense = "auth_failure" // failed authentication
	OffenseDenied      Offense = "denied"       // rejected by the allow/deny lists
)

// AutoBanSettings configures automatic bans.
type AutoBanSettings struct {
	// Threshold offenses from one address within Window ban it for
	// BanDuration.
	Threshold   int
	Window      time.Duration
	BanDuration time.Duration
	// Triggers are the offenses that count; others are ignored.
	Triggers []Offense
}

// AutoBan counts offenses per client address and bans an address that
// reaches the threshold. Counters live in the shared store (a fixed
// window per address, created by the first offense), so offenses seen
// by different gateway instances add up.
type AutoBan struct {
	st       store.Store
	bans     *BanList
	s        AutoBanSettings
	triggers map[Offense]bool
	now      func() time.Time
}

// NewAutoBan returns an AutoBan recording into st and banning through
// bans.
func NewAutoBan(st store.Store, bans *BanList, s AutoBanSettings) *AutoBan {
	ab := &AutoBan{st: st, bans: bans, s: s, triggers: map[Offense]bool{}, now: time.Now}
	for _, t := range s.Triggers {
		ab.triggers[t] = true
	}
	return ab
}

func strikesKey(a netip.Addr) string { return keyPrefix + "strikes:" + a.String() }

// Record counts offense o by addr. When that's the offense that reaches
// the threshold, addr is banned and the new ban returned (banned true).
//
// Only the request whose increment lands exactly on the threshold
// issues the ban, so concurrent offenses — on this instance or another —
// can't ban an address twice. The counter is cleared once the ban is
// in place.
func (ab *AutoBan) Record(ctx context.Context, addr netip.Addr, o Offense) (ban Ban, banned bool, err error) {
	if ab == nil || !ab.triggers[o] {
		return Ban{}, false, nil
	}
	addr = normalize(addr)
	n, err := ab.st.Increment(ctx, strikesKey(addr), ab.s.Window)
	if err != nil {
		return Ban{}, false, err
	}
	if n != int64(ab.s.Threshold) {
		return Ban{}, false, nil
	}

	now := ab.now().UTC()
	ban = Ban{
		IP:        addr.String(),
		Source:    SourceAuto,
		Reason:    fmt.Sprintf("%d offenses within %s (last: %s)", n, ab.s.Window, o),
		Level:     1,
		BannedAt:  now,
		ExpiresAt: now.Add(ab.s.BanDuration),
	}
	if err := ab.bans.Add(ctx, ban); err != nil {
		return Ban{}, false, err
	}
	_ = ab.st.Delete(ctx, strikesKey(addr))
	return ban, true, nil
}
