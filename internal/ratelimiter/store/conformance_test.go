package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testStoreConformance runs the same behavioral test suite against any
// Store implementation, so MemoryStore and RedisStore (backed by
// miniredis in redis_test.go) are held to identical guarantees.
//
// newStore returns a fresh Store plus an "advance" function that moves
// that store's clock forward by d for the purpose of TTL expiry. For
// MemoryStore this is a real time.Sleep; miniredis simulates TTLs
// virtually (they only tick down via FastForward, not wall-clock time),
// so the Redis-backed test supplies mr.FastForward instead — this keeps
// the TTL tests both correct and instant for both backends.
func testStoreConformance(t *testing.T, newStore func() (Store, func(time.Duration))) {
	t.Run("Increment starts at 1 and increases", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()
		ctx := context.Background()

		v, err := s.Increment(ctx, "counter", time.Minute)
		require.NoError(t, err)
		assert.Equal(t, int64(1), v)

		v, err = s.Increment(ctx, "counter", time.Minute)
		require.NoError(t, err)
		assert.Equal(t, int64(2), v)

		v, err = s.Increment(ctx, "counter", time.Minute)
		require.NoError(t, err)
		assert.Equal(t, int64(3), v)
	})

	t.Run("Increment respects ttl and resets after expiry", func(t *testing.T) {
		s, advance := newStore()
		defer s.Close()
		ctx := context.Background()

		v, err := s.Increment(ctx, "expiring", 50*time.Millisecond)
		require.NoError(t, err)
		assert.Equal(t, int64(1), v)

		advance(150 * time.Millisecond)

		v, err = s.Increment(ctx, "expiring", 50*time.Millisecond)
		require.NoError(t, err)
		assert.Equal(t, int64(1), v, "counter should have reset after ttl expired")
	})

	t.Run("Increment is safe under concurrent access", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()
		ctx := context.Background()

		const goroutines = 50
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := s.Increment(ctx, "concurrent", time.Minute)
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		v, err := s.Increment(ctx, "concurrent", time.Minute)
		require.NoError(t, err)
		assert.Equal(t, int64(goroutines+1), v)
	})

	t.Run("Load returns ErrNotFound for missing key", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()

		_, err := s.Load(context.Background(), "missing")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("CompareAndSwap creates a key only when it must not exist", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()
		ctx := context.Background()

		ok, err := s.CompareAndSwap(ctx, "cas-key", nil, []byte("v1"), time.Minute)
		require.NoError(t, err)
		assert.True(t, ok)

		ok, err = s.CompareAndSwap(ctx, "cas-key", nil, []byte("v2"), time.Minute)
		require.NoError(t, err)
		assert.False(t, ok, "second create-only swap must fail because the key now exists")

		got, err := s.Load(ctx, "cas-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("v1"), got)
	})

	t.Run("CompareAndSwap updates only on matching oldVal", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()
		ctx := context.Background()

		_, err := s.CompareAndSwap(ctx, "cas-update", nil, []byte("v1"), time.Minute)
		require.NoError(t, err)

		ok, err := s.CompareAndSwap(ctx, "cas-update", []byte("wrong"), []byte("v2"), time.Minute)
		require.NoError(t, err)
		assert.False(t, ok)

		ok, err = s.CompareAndSwap(ctx, "cas-update", []byte("v1"), []byte("v2"), time.Minute)
		require.NoError(t, err)
		assert.True(t, ok)

		got, err := s.Load(ctx, "cas-update")
		require.NoError(t, err)
		assert.Equal(t, []byte("v2"), got)
	})

	t.Run("CompareAndSwap under concurrency only lets one writer per generation win", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()
		ctx := context.Background()

		_, err := s.CompareAndSwap(ctx, "cas-race", nil, []byte("0"), time.Minute)
		require.NoError(t, err)

		const goroutines = 20
		var wg sync.WaitGroup
		var successes int64
		var mu sync.Mutex
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				ok, err := s.CompareAndSwap(ctx, "cas-race", []byte("0"), []byte("1"), time.Minute)
				assert.NoError(t, err)
				if ok {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		assert.Equal(t, int64(1), successes, "exactly one concurrent CAS from the same base value should succeed")
	})

	t.Run("Ping succeeds", func(t *testing.T) {
		s, _ := newStore()
		defer s.Close()
		assert.NoError(t, s.Ping(context.Background()))
	})
}
