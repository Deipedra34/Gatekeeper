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

func TestSlidingWindowLog_AllowsUpToLimitThenRejects(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	w := newSlidingWindowLog(st, Rule{Burst: 3}, time.Second)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		res, err := w.Allow(ctx, "client-a")
		require.NoError(t, err)
		assert.Truef(t, res.Allowed, "request %d should be within the window limit", i+1)
	}

	res, err := w.Allow(ctx, "client-a")
	require.NoError(t, err)
	assert.False(t, res.Allowed)
	assert.Positive(t, res.RetryAfter)
}

func TestSlidingWindowLog_SlidesForwardAsEntriesAge(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	window := 150 * time.Millisecond
	w := newSlidingWindowLog(st, Rule{Burst: 1}, window)
	ctx := context.Background()

	res, err := w.Allow(ctx, "client-b")
	require.NoError(t, err)
	require.True(t, res.Allowed)

	res, err = w.Allow(ctx, "client-b")
	require.NoError(t, err)
	require.False(t, res.Allowed, "second request within the same window should be rejected")

	time.Sleep(window + 50*time.Millisecond)

	res, err = w.Allow(ctx, "client-b")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "request after the window has fully elapsed should be allowed again")
}

func TestSlidingWindowLog_UnlikeFixedWindowDoesNotDoubleAtBoundary(t *testing.T) {
	// This is the property that distinguishes Sliding Window Log from
	// Fixed Window Counter: no matter when a request lands, the count
	// of allowed requests in any trailing `window` never exceeds the
	// limit — including across what would be a fixed-window boundary.
	st := store.NewMemoryStore()
	defer st.Close()
	window := 200 * time.Millisecond
	w := newSlidingWindowLog(st, Rule{Burst: 2}, window)
	ctx := context.Background()

	res, err := w.Allow(ctx, "client-c")
	require.NoError(t, err)
	require.True(t, res.Allowed)
	res, err = w.Allow(ctx, "client-c")
	require.NoError(t, err)
	require.True(t, res.Allowed)

	// Sleep to just past the midpoint of the window, then immediately
	// try again: a fixed window aligned to this boundary would have
	// reset and allow 2 more right now, but the sliding log must not.
	time.Sleep(window/2 + 20*time.Millisecond)
	res, err = w.Allow(ctx, "client-c")
	require.NoError(t, err)
	assert.False(t, res.Allowed, "sliding window must still count the still-recent earlier requests")
}

func TestSlidingWindowLog_ConcurrentRequestsNeverExceedLimit(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	const limit = 10
	w := newSlidingWindowLog(st, Rule{Burst: limit}, time.Second)
	ctx := context.Background()

	const goroutines = 100
	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			res, err := w.Allow(ctx, "hammered-client")
			assert.NoError(t, err)
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(limit), allowed)
}
