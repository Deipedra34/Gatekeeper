package accesscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// Ban sources.
const (
	SourceAuto   = "auto"   // issued by auto-ban
	SourceManual = "manual" // issued through the admin API
)

// Ban is one temporary ban of a client address, as stored.
type Ban struct {
	IP        string    `json:"ip"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason,omitempty"`
	Level     int       `json:"level,omitempty"` // 1 for a first auto-ban, 2 for the next, ...
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store keys. Everything access control keeps lives under keyPrefix,
// so it never collides with rate limiter or cache keys.
const (
	keyPrefix = "gatekeeper:access:"
	indexKey  = keyPrefix + "bans"
)

func banKey(a netip.Addr) string { return keyPrefix + "ban:" + a.String() }

// maxCASRetries bounds the optimistic-concurrency loops below. Losing
// that many races in a row only happens under heavy contention on one
// key, and the caller gets an error rather than a spin.
const maxCASRetries = 16

var errContention = errors.New("accesscontrol: too much contention updating the store")

// BanList keeps bans in the store the rate limiter uses, so with Redis
// every gateway instance sees the same bans. Each ban is its own key
// with a TTL, so it disappears on its own when it expires — the ban key
// is the only thing a request checks. A small index key (address ->
// expiry) is maintained alongside it for listing bans and counting them
// for /metrics; it's pruned of expired entries whenever it's written.
type BanList struct {
	st  store.Store
	now func() time.Time
}

// NewBanList returns a BanList over st.
func NewBanList(st store.Store) *BanList {
	return &BanList{st: st, now: time.Now}
}

// Add stores ban, replacing any current ban of the same address. It
// expires at ban.ExpiresAt.
func (b *BanList) Add(ctx context.Context, ban Ban) error {
	addr, err := netip.ParseAddr(ban.IP)
	if err != nil {
		return fmt.Errorf("accesscontrol: ban: %q is not an IP address", ban.IP)
	}
	addr = normalize(addr)
	ban.IP = addr.String()
	ttl := ban.ExpiresAt.Sub(b.now())
	if ttl <= 0 {
		return errors.New("accesscontrol: ban: expiry must be in the future")
	}
	val, err := json.Marshal(ban)
	if err != nil {
		return err
	}
	if err := b.put(ctx, banKey(addr), val, ttl); err != nil {
		return err
	}
	exp := ban.ExpiresAt.UnixMilli()
	return b.updateIndex(ctx, func(idx map[string]int64) { idx[ban.IP] = exp })
}

// put writes val at key whatever is there now.
func (b *BanList) put(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	for range maxCASRetries {
		old, err := b.st.Load(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			old = nil
		} else if err != nil {
			return err
		}
		ok, err := b.st.CompareAndSwap(ctx, key, old, val, ttl)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return errContention
}

// Get returns the current ban of addr, if there is one.
func (b *BanList) Get(ctx context.Context, addr netip.Addr) (Ban, bool, error) {
	raw, err := b.st.Load(ctx, banKey(normalize(addr)))
	if errors.Is(err, store.ErrNotFound) {
		return Ban{}, false, nil
	}
	if err != nil {
		return Ban{}, false, err
	}
	var ban Ban
	if err := json.Unmarshal(raw, &ban); err != nil {
		return Ban{}, false, fmt.Errorf("accesscontrol: corrupt ban record for %s: %w", addr, err)
	}
	if !b.now().Before(ban.ExpiresAt) {
		return Ban{}, false, nil
	}
	return ban, true, nil
}

// Remove lifts the ban of addr. found reports whether there was one.
func (b *BanList) Remove(ctx context.Context, addr netip.Addr) (found bool, err error) {
	addr = normalize(addr)
	_, found, err = b.Get(ctx, addr)
	if err != nil {
		return false, err
	}
	if err := b.st.Delete(ctx, banKey(addr)); err != nil {
		return false, err
	}
	ip := addr.String()
	return found, b.updateIndex(ctx, func(idx map[string]int64) { delete(idx, ip) })
}

// List returns every active ban, ordered by address.
func (b *BanList) List(ctx context.Context) ([]Ban, error) {
	idx, _, err := b.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	now := b.now().UnixMilli()
	bans := make([]Ban, 0, len(idx))
	var stale []string
	for ip, exp := range idx {
		addr, err := netip.ParseAddr(ip)
		if err != nil || exp <= now {
			stale = append(stale, ip)
			continue
		}
		ban, ok, err := b.Get(ctx, addr)
		if err != nil {
			return nil, err
		}
		if !ok { // lifted elsewhere, or expired
			stale = append(stale, ip)
			continue
		}
		bans = append(bans, ban)
	}
	if len(stale) > 0 {
		// Best effort: a failed prune is retried on the next write.
		_ = b.updateIndex(ctx, func(idx map[string]int64) {
			for _, ip := range stale {
				delete(idx, ip)
			}
		})
	}
	sort.Slice(bans, func(i, j int) bool { return bans[i].IP < bans[j].IP })
	return bans, nil
}

// Count returns the number of active bans, from the index alone.
func (b *BanList) Count(ctx context.Context) (int, error) {
	idx, _, err := b.loadIndex(ctx)
	if err != nil {
		return 0, err
	}
	now := b.now().UnixMilli()
	n := 0
	for _, exp := range idx {
		if exp > now {
			n++
		}
	}
	return n, nil
}

func (b *BanList) loadIndex(ctx context.Context) (map[string]int64, []byte, error) {
	raw, err := b.st.Load(ctx, indexKey)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]int64{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	idx := map[string]int64{}
	if err := json.Unmarshal(raw, &idx); err != nil {
		// A corrupt index only affects listing; start it over.
		idx = map[string]int64{}
	}
	return idx, raw, nil
}

// updateIndex applies fn to the index, dropping expired entries, with
// compare-and-swap so concurrent writers on other instances don't lose
// each other's updates.
func (b *BanList) updateIndex(ctx context.Context, fn func(map[string]int64)) error {
	for range maxCASRetries {
		idx, raw, err := b.loadIndex(ctx)
		if err != nil {
			return err
		}
		now := b.now().UnixMilli()
		for ip, exp := range idx {
			if exp <= now {
				delete(idx, ip)
			}
		}
		fn(idx)
		val, err := json.Marshal(idx)
		if err != nil {
			return err
		}
		ok, err := b.st.CompareAndSwap(ctx, indexKey, raw, val, 0)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return errContention
}
