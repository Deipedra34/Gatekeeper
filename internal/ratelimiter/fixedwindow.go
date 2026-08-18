package ratelimiter

import (
	"context"
	"strconv"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// fixedWindow implements the Fixed Window Counter algorithm. Time gets
// divided into fixed-size buckets aligned to the epoch (every wall-clock
// second, here), and each client gets one counter per bucket that resets
// when the bucket rolls over. It's the cheapest of the three — one
// atomic increment per request, O(1) storage — but it'll let up to 2x
// the configured limit through in a short burst that spans a window
// boundary: `limit` requests in the last instant of one window, then
// `limit` more in the first instant of the next. See the README for the
// full trade-off writeup.
type fixedWindow struct {
	store  store.Store
	limit  int64
	window time.Duration
}

func newFixedWindow(st store.Store, rule Rule, window time.Duration) *fixedWindow {
	return &fixedWindow{store: st, limit: rule.Burst, window: window}
}

func (f *fixedWindow) Allow(ctx context.Context, key string) (Result, error) {
	now := time.Now()
	windowIndex := now.UnixNano() / int64(f.window)
	windowKey := windowBucketKey(key, windowIndex)

	count, err := f.store.Increment(ctx, windowKey, f.window)
	if err != nil {
		return Result{}, err
	}

	remaining := f.limit - count
	if remaining < 0 {
		remaining = 0
	}

	result := Result{
		Allowed:   count <= f.limit,
		Limit:     f.limit,
		Remaining: remaining,
	}
	if !result.Allowed {
		windowEnd := time.Unix(0, (windowIndex+1)*int64(f.window))
		result.RetryAfter = windowEnd.Sub(now)
	}
	return result, nil
}

func windowBucketKey(key string, windowIndex int64) string {
	return key + ":" + strconv.FormatInt(windowIndex, 10)
}
