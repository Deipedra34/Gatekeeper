package ratelimiter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/ratelimiter/store"
)

func TestTokenBucket_AllowsBurstThenRejects(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	b := newTokenBucket(st, Rule{Rate: 1, Burst: 5})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		res, err := b.Allow(ctx, "client-a")
		require.NoError(t, err)
		assert.Truef(t, res.Allowed, "request %d should be allowed within burst capacity", i+1)
	}

	res, err := b.Allow(ctx, "client-a")
	require.NoError(t, err)
	assert.False(t, res.Allowed, "request beyond burst capacity should be rejected")
	assert.Positive(t, res.RetryAfter)
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	// 10 tokens/sec refill => 1 token every 100ms.
	b := newTokenBucket(st, Rule{Rate: 10, Burst: 1})
	ctx := context.Background()

	res, err := b.Allow(ctx, "client-b")
	require.NoError(t, err)
	require.True(t, res.Allowed)

	res, err = b.Allow(ctx, "client-b")
	require.NoError(t, err)
	require.False(t, res.Allowed, "bucket of size 1 should be empty immediately after being consumed")

	time.Sleep(150 * time.Millisecond)

	res, err = b.Allow(ctx, "client-b")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "bucket should have refilled after waiting longer than the refill period")
}

func TestTokenBucket_DifferentClientsHaveIndependentBuckets(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	b := newTokenBucket(st, Rule{Rate: 1, Burst: 1})
	ctx := context.Background()

	res, err := b.Allow(ctx, "client-x")
	require.NoError(t, err)
	assert.True(t, res.Allowed)

	res, err = b.Allow(ctx, "client-y")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "a different client's bucket must not be affected by client-x's consumption")
}

// TestTokenBucket_ConcurrentRequestsNeverExceedBurst fires many
// concurrent requests at a single client and asserts that the number of
// allowed requests never exceeds the configured burst, verifying the
// CAS loop actually serializes updates instead of racing.
func TestTokenBucket_ConcurrentRequestsNeverExceedBurst(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	const burst = 10
	b := newTokenBucket(st, Rule{Rate: 1, Burst: burst})
	ctx := context.Background()

	const goroutines = 100
	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			res, err := b.Allow(ctx, "hammered-client")
			assert.NoError(t, err)
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(burst), allowed, "exactly `burst` requests should be allowed out of a concurrent burst")
}
