package ratelimiter

import (
	"context"
	"encoding/json"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// tokenBucket implements the Token Bucket algorithm. Each client owns a
// bucket holding up to rule.Burst tokens that refills continuously at
// rule.Rate tokens/second; every request costs one token, and requests
// that show up to an empty bucket get rejected. Because the refill is
// continuous instead of reset-at-a-boundary, it sidesteps the "2x burst
// at window edges" problem Fixed Window Counter has — the price is
// storing a float token count and a timestamp per client instead of a
// single integer.
type tokenBucket struct {
	store store.Store
	rate  float64 // tokens per second
	burst int64   // bucket capacity
	// ttl is how long an idle client's bucket state sticks around. It's
	// sized to the time it'd take to fully refill from empty, plus some
	// slack, so it never expires early — by the time it does expire, the
	// client has been idle long enough to deserve a full bucket anyway.
	ttl time.Duration
}

func newTokenBucket(st store.Store, rule Rule) *tokenBucket {
	refillTime := time.Duration(float64(rule.Burst)/rule.Rate*float64(time.Second)) * 2
	if refillTime < time.Minute {
		refillTime = time.Minute
	}
	return &tokenBucket{store: st, rate: rule.Rate, burst: rule.Burst, ttl: refillTime}
}

// bucketState is the JSON-encoded value persisted per client.
type bucketState struct {
	Tokens     float64 `json:"tokens"`
	LastRefill int64   `json:"last_refill_unix_nano"`
}

const maxCASRetries = 20

// Allow implements Limiter with an optimistic compare-and-swap loop: load
// the current state, work out how much refill is owed since it was last
// written, decide allow or deny, then try writing the new state back —
// but only if nothing else changed it in the meantime. If something did,
// it just reloads and tries again.
func (b *tokenBucket) Allow(ctx context.Context, key string) (Result, error) {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		raw, err := b.store.Load(ctx, key)
		now := time.Now()

		var state bucketState
		var oldVal []byte
		switch err {
		case nil:
			oldVal = raw
			if decErr := json.Unmarshal(raw, &state); decErr != nil {
				return Result{}, decErr
			}
		case store.ErrNotFound:
			state = bucketState{Tokens: float64(b.burst), LastRefill: now.UnixNano()}
		default:
			return Result{}, err
		}

		elapsed := now.Sub(time.Unix(0, state.LastRefill))
		refilled := state.Tokens + elapsed.Seconds()*b.rate
		if refilled > float64(b.burst) {
			refilled = float64(b.burst)
		}

		allowed := refilled >= 1
		newTokens := refilled
		if allowed {
			newTokens--
		}

		newState := bucketState{Tokens: newTokens, LastRefill: now.UnixNano()}
		newVal, err := json.Marshal(newState)
		if err != nil {
			return Result{}, err
		}

		ok, err := b.store.CompareAndSwap(ctx, key, oldVal, newVal, b.ttl)
		if err != nil {
			return Result{}, err
		}
		if !ok {
			continue // another goroutine/instance updated the bucket first; retry
		}

		result := Result{
			Allowed:   allowed,
			Limit:     b.burst,
			Remaining: int64(newTokens),
		}
		if !allowed {
			// Time until at least one token is available again.
			deficit := 1 - refilled
			result.RetryAfter = time.Duration(deficit / b.rate * float64(time.Second))
		}
		return result, nil
	}

	return Result{}, ErrTooMuchContention
}
