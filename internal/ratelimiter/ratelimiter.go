// Package ratelimiter implements pluggable rate-limiting algorithms that
// share a single storage abstraction (see internal/ratelimiter/store),
// so the same Token Bucket, Sliding Window Log, or Fixed Window Counter
// code runs unmodified against either an in-memory map or Redis.
package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// ErrTooMuchContention comes back when a CAS-based algorithm (Token
// Bucket, Sliding Window Log) can't land an update after maxCASRetries
// tries. This shouldn't happen under normal load — it's a safety valve
// against pathological contention, not something meant to trigger in
// practice.
var ErrTooMuchContention = errors.New("ratelimiter: too much contention on client state, try again")

// Result describes the outcome of a single Allow check.
type Result struct {
	// Allowed is true if the request may proceed.
	Allowed bool
	// Limit is the maximum number of requests permitted in the current
	// window/bucket (the tier's configured burst).
	Limit int64
	// Remaining is the number of additional requests the client could
	// make right now without being rejected.
	Remaining int64
	// RetryAfter is how long the caller should wait before its next
	// request is likely to be allowed. Only meaningful when !Allowed.
	RetryAfter time.Duration
}

// Limiter is what every rate-limiting algorithm implements. Callers
// identify the client with an opaque key — an API key, IP address, or
// header value, depending on internal/middleware's scoping logic — and
// the limiter handles all the bookkeeping needed to decide whether that
// client still has room to make another request.
type Limiter interface {
	Allow(ctx context.Context, key string) (Result, error)
}

// Rule is the rate/burst allowance a Limiter enforces. Its two fields
// map onto the algorithms differently:
//
//   - Token Bucket treats Rate as the refill rate (tokens/second) and
//     Burst as the bucket capacity, so short spikes up to Burst are
//     absorbed immediately and the sustained long-run rate converges to
//     Rate.
//   - Sliding Window Log and Fixed Window Counter both use a fixed
//     one-second window and treat Burst as the maximum number of
//     requests allowed inside that window. Rate is not used by these
//     two algorithms; the trade-off is documented in the README.
type Rule struct {
	Rate  float64
	Burst int64
}

// window is the fixed window size used by the two windowed algorithms.
// It is not exposed in configuration (see Rule's doc comment) to keep
// the config schema identical across all three algorithms.
const window = time.Second

// New constructs a Limiter for the named algorithm backed by st. Every
// distinct (algorithm, store) pair used by the gateway should share one
// Limiter instance per tier so all clients in that tier contend for the
// same counters.
func New(algorithm string, st store.Store, rule Rule) (Limiter, error) {
	switch algorithm {
	case "token_bucket":
		return newTokenBucket(st, rule), nil
	case "sliding_window_log":
		return newSlidingWindowLog(st, rule, window), nil
	case "fixed_window":
		return newFixedWindow(st, rule, window), nil
	default:
		return nil, fmt.Errorf("ratelimiter: unknown algorithm %q", algorithm)
	}
}
