// Package store defines the storage abstraction that rate-limiting
// algorithms use to persist counters and state. Two implementations are
// provided: an in-memory store for single-instance deployments, and a
// Redis-backed store for coordinating limits across multiple instances.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Load when no value exists for a key.
var ErrNotFound = errors.New("store: key not found")

// Store is the minimal set of atomic primitives a rate-limiting algorithm
// needs to keep per-client state safe under concurrent access. It only
// exposes two kinds of operation, on purpose, so very different backends —
// an in-process map, Redis, whatever comes next — can each implement it
// without leaking their own quirks into the algorithms built on top:
//
//   - Increment: a monotonically increasing counter with a sliding
//     time-to-live. Fixed Window Counter uses this one directly.
//   - Load / CompareAndSwap: optimistic-concurrency key/value access, for
//     algorithms (Token Bucket, Sliding Window Log) that need to read some
//     arbitrary state, mutate it, and write it back without clobbering
//     someone else's concurrent update.
type Store interface {
	// Increment bumps the counter at key by one and returns the value
	// after the increment. If the key doesn't exist yet, it's created with
	// the given ttl. That ttl only applies on creation, so repeated calls
	// within the same window share one expiry — which is exactly what
	// gives Fixed Window Counter its "reset at the window boundary" behavior.
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)

	// Load returns the raw bytes stored at key, or ErrNotFound if there's
	// nothing there.
	Load(ctx context.Context, key string) ([]byte, error)

	// CompareAndSwap replaces the value at key with newVal, atomically, but
	// only if the current value matches oldVal. A nil oldVal means "this
	// key must not exist yet." ttl sets the expiry on the new value. It
	// returns true if the swap went through; false means someone else got
	// there first and the caller should reload and retry.
	CompareAndSwap(ctx context.Context, key string, oldVal, newVal []byte, ttl time.Duration) (bool, error)

	// Close releases whatever resources the store is holding — connections,
	// background goroutines, that sort of thing.
	Close() error

	// Ping checks that the store is actually reachable. Used at startup,
	// and by the Redis-backed store's health check to decide whether it's
	// safe to stop falling back to in-memory limiting.
	Ping(ctx context.Context) error
}
