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

func TestFixedWindow_AllowsUpToLimitThenRejects(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	f := newFixedWindow(st, Rule{Burst: 3}, time.Hour) // long window: no boundary flakiness
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		res, err := f.Allow(ctx, "client-a")
		require.NoError(t, err)
		assert.Truef(t, res.Allowed, "request %d should be within the window limit", i+1)
	}

	res, err := f.Allow(ctx, "client-a")
	require.NoError(t, err)
	assert.False(t, res.Allowed)
	assert.Positive(t, res.RetryAfter)
}

func TestFixedWindow_ResetsOnWindowBoundary(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	window := 100 * time.Millisecond
	f := newFixedWindow(st, Rule{Burst: 1}, window)
	ctx := context.Background()

	res, err := f.Allow(ctx, "client-b")
	require.NoError(t, err)
	require.True(t, res.Allowed)

	res, err = f.Allow(ctx, "client-b")
	require.NoError(t, err)
	require.False(t, res.Allowed)

	time.Sleep(window * 2)

	res, err = f.Allow(ctx, "client-b")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "counter should have reset in the new window")
}

// TestFixedWindow_BoundaryCanDoubleAllowedRequests documents the
// algorithm's known trade-off: a client that waits until the very end
// of one window and immediately sends more requests at the start of
// the next can get up to 2x the configured limit through in a short
// span. This is expected behavior, not a bug — see the README's
// algorithm comparison.
func TestFixedWindow_BoundaryCanDoubleAllowedRequests(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	window := 100 * time.Millisecond
	f := newFixedWindow(st, Rule{Burst: 2}, window)
	ctx := context.Background()

	// Consume both slots as late as possible in the current window.
	for {
		now := time.Now()
		windowIdx := now.UnixNano() / int64(window)
		remaining := time.Unix(0, (windowIdx+1)*int64(window)).Sub(now)
		if remaining < 20*time.Millisecond {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	res, err := f.Allow(ctx, "client-c")
	require.NoError(t, err)
	require.True(t, res.Allowed)
	res, err = f.Allow(ctx, "client-c")
	require.NoError(t, err)
	require.True(t, res.Allowed)

	time.Sleep(25 * time.Millisecond) // cross into the next window

	res, err = f.Allow(ctx, "client-c")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "new window grants a fresh allowance immediately")
	res, err = f.Allow(ctx, "client-c")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "4 requests landed within roughly one window's duration, double the configured limit of 2")
}

func TestFixedWindow_ConcurrentRequestsNeverExceedLimit(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	const limit = 10
	f := newFixedWindow(st, Rule{Burst: limit}, time.Hour)
	ctx := context.Background()

	const goroutines = 100
	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			res, err := f.Allow(ctx, "hammered-client")
			assert.NoError(t, err)
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(limit), allowed)
}
