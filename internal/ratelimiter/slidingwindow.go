package ratelimiter

import (
	"context"
	"encoding/json"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// slidingWindowLog implements the Sliding Window Log algorithm. Every
// allowed request's timestamp gets appended to a per-client log, and a
// request is allowed only if fewer than `limit` timestamps are still
// inside the trailing `window`. That gives an exact, smooth rate limit
// with no boundary artefacts — the cost is storing one timestamp per
// request in the window (O(limit) space and CPU per check) instead of
// the O(1) state Token Bucket and Fixed Window Counter get away with.
type slidingWindowLog struct {
	store  store.Store
	limit  int64
	window time.Duration
	// ttl bounds how long a client's log sticks around after they stop
	// sending requests. One window is plenty, since the log only ever
	// gets consulted for entries inside the trailing window anyway.
	ttl time.Duration
}

func newSlidingWindowLog(st store.Store, rule Rule, window time.Duration) *slidingWindowLog {
	return &slidingWindowLog{store: st, limit: rule.Burst, window: window, ttl: window * 2}
}

func (w *slidingWindowLog) Allow(ctx context.Context, key string) (Result, error) {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		raw, err := w.store.Load(ctx, key)
		now := time.Now()

		var log []int64
		var oldVal []byte
		switch err {
		case nil:
			oldVal = raw
			if decErr := json.Unmarshal(raw, &log); decErr != nil {
				return Result{}, decErr
			}
		case store.ErrNotFound:
			// oldVal stays nil, log stays empty.
		default:
			return Result{}, err
		}

		cutoff := now.Add(-w.window).UnixNano()
		kept := log[:0]
		for _, ts := range log {
			if ts > cutoff {
				kept = append(kept, ts)
			}
		}

		allowed := int64(len(kept)) < w.limit
		newLog := kept
		if allowed {
			newLog = append(newLog, now.UnixNano())
		}

		newVal, err := json.Marshal(newLog)
		if err != nil {
			return Result{}, err
		}

		ok, err := w.store.CompareAndSwap(ctx, key, oldVal, newVal, w.ttl)
		if err != nil {
			return Result{}, err
		}
		if !ok {
			continue
		}

		remaining := w.limit - int64(len(newLog))
		if remaining < 0 {
			remaining = 0
		}
		result := Result{
			Allowed:   allowed,
			Limit:     w.limit,
			Remaining: remaining,
		}
		if !allowed && len(kept) > 0 {
			// The window frees up one slot as soon as its oldest entry
			// ages out.
			oldest := time.Unix(0, kept[0])
			result.RetryAfter = w.window - now.Sub(oldest)
		}
		return result, nil
	}

	return Result{}, ErrTooMuchContention
}
