package ratelimiter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// Inspector is implemented by every Limiter New returns. It backs the
// admin API: reading a client's quota without spending any of it, and
// putting a client back to a full allowance.
type Inspector interface {
	// Peek reports what Allow would decide for key right now, without
	// consuming anything: Allowed is whether the next request would get
	// through, Remaining how many could.
	Peek(ctx context.Context, key string) (Result, error)

	// Reset forgets key's state, so its next request starts from a full
	// allowance.
	Reset(ctx context.Context, key string) error
}

// Inspect returns l's Inspector, or an error for a Limiter that doesn't
// support inspection (none of the built-in ones).
func Inspect(l Limiter) (Inspector, error) {
	in, ok := l.(Inspector)
	if !ok {
		return nil, fmt.Errorf("ratelimiter: %T does not support inspection", l)
	}
	return in, nil
}

// Peek implements Inspector.
func (b *tokenBucket) Peek(ctx context.Context, key string) (Result, error) {
	tokens := float64(b.burst)
	raw, err := b.store.Load(ctx, key)
	switch err {
	case nil:
		var state bucketState
		if err := json.Unmarshal(raw, &state); err != nil {
			return Result{}, err
		}
		elapsed := time.Since(time.Unix(0, state.LastRefill))
		tokens = min(state.Tokens+elapsed.Seconds()*b.rate, float64(b.burst))
	case store.ErrNotFound:
	default:
		return Result{}, err
	}
	result := Result{Allowed: tokens >= 1, Limit: b.burst, Remaining: int64(tokens)}
	if !result.Allowed {
		result.RetryAfter = time.Duration((1 - tokens) / b.rate * float64(time.Second))
	}
	return result, nil
}

// Reset implements Inspector.
func (b *tokenBucket) Reset(ctx context.Context, key string) error {
	return b.store.Delete(ctx, key)
}

// Peek implements Inspector.
func (w *slidingWindowLog) Peek(ctx context.Context, key string) (Result, error) {
	var log []int64
	raw, err := w.store.Load(ctx, key)
	switch err {
	case nil:
		if err := json.Unmarshal(raw, &log); err != nil {
			return Result{}, err
		}
	case store.ErrNotFound:
	default:
		return Result{}, err
	}
	now := time.Now()
	cutoff := now.Add(-w.window).UnixNano()
	var kept []int64
	for _, ts := range log {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	result := Result{Allowed: int64(len(kept)) < w.limit, Limit: w.limit, Remaining: max(w.limit-int64(len(kept)), 0)}
	if !result.Allowed && len(kept) > 0 {
		result.RetryAfter = w.window - now.Sub(time.Unix(0, kept[0]))
	}
	return result, nil
}

// Reset implements Inspector.
func (w *slidingWindowLog) Reset(ctx context.Context, key string) error {
	return w.store.Delete(ctx, key)
}

// Peek implements Inspector.
func (f *fixedWindow) Peek(ctx context.Context, key string) (Result, error) {
	now := time.Now()
	windowIndex := now.UnixNano() / int64(f.window)
	var count int64
	raw, err := f.store.Load(ctx, windowBucketKey(key, windowIndex))
	switch err {
	case nil:
		count = store.DecodeCounter(raw)
	case store.ErrNotFound:
	default:
		return Result{}, err
	}
	result := Result{Allowed: count < f.limit, Limit: f.limit, Remaining: max(f.limit-count, 0)}
	if !result.Allowed {
		result.RetryAfter = time.Unix(0, (windowIndex+1)*int64(f.window)).Sub(now)
	}
	return result, nil
}

// Reset implements Inspector. Only the current window holds state that
// matters; earlier windows' counters are already irrelevant and expire
// on their own.
func (f *fixedWindow) Reset(ctx context.Context, key string) error {
	windowIndex := time.Now().UnixNano() / int64(f.window)
	return f.store.Delete(ctx, windowBucketKey(key, windowIndex))
}
