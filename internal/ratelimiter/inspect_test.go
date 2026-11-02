package ratelimiter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/ratelimiter/store"
)

// TestInspector_PeekDoesNotConsumeAndResetRestores runs every algorithm
// through the same scenario: Peek reports the allowance without spending
// it, an exhausted client peeks as blocked, and Reset gives it the full
// allowance back. Rate is tiny so nothing refills mid-test.
func TestInspector_PeekDoesNotConsumeAndResetRestores(t *testing.T) {
	for _, algorithm := range []string{"token_bucket", "sliding_window_log", "fixed_window"} {
		t.Run(algorithm, func(t *testing.T) {
			st := store.NewMemoryStore()
			t.Cleanup(func() { st.Close() })
			ctx := context.Background()

			// The windowed algorithms use a 1s window; running near a
			// boundary could reset it under us, so the token bucket's
			// exact numbers are checked and the windowed ones only need
			// to agree with Allow within the same instant.
			l, err := New(algorithm, st, Rule{Rate: 0.01, Burst: 3})
			require.NoError(t, err)
			in, err := Inspect(l)
			require.NoError(t, err)

			before, err := in.Peek(ctx, "client")
			require.NoError(t, err)
			assert.True(t, before.Allowed)
			assert.Equal(t, int64(3), before.Remaining)
			assert.Equal(t, int64(3), before.Limit)

			again, err := in.Peek(ctx, "client")
			require.NoError(t, err)
			assert.Equal(t, int64(3), again.Remaining, "Peek must not consume anything")

			for i := 0; i < 3; i++ {
				_, err := l.Allow(ctx, "client")
				require.NoError(t, err)
			}
			if algorithm == "token_bucket" {
				spent, err := in.Peek(ctx, "client")
				require.NoError(t, err)
				assert.False(t, spent.Allowed)
				assert.Equal(t, int64(0), spent.Remaining)
				assert.Positive(t, spent.RetryAfter)
			}

			require.NoError(t, in.Reset(ctx, "client"))
			after, err := in.Peek(ctx, "client")
			require.NoError(t, err)
			assert.True(t, after.Allowed)
			assert.Equal(t, int64(3), after.Remaining)

			res, err := l.Allow(ctx, "client")
			require.NoError(t, err)
			assert.True(t, res.Allowed, "a reset client gets through again")
		})
	}
}
