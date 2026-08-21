package ratelimiter

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"gatekeeper/internal/ratelimiter/store"
)

func newBenchMemoryStore(b *testing.B) store.Store {
	b.Helper()
	return store.NewMemoryStore()
}

func newBenchRedisStore(b *testing.B) store.Store {
	b.Helper()
	mr := miniredis.RunT(b)
	return store.NewRedisStore(mr.Addr(), "", 0, time.Second)
}

// benchRule picks a Rule sized so each algorithm is measured on its
// steady-state path rather than a pathological one:
//   - Token Bucket gets a huge rate/burst so the bucket never runs dry;
//     its per-client state is a fixed-size float+timestamp regardless,
//     so this doesn't change what's being measured.
//   - Sliding Window Log and Fixed Window Counter get a burst sized like
//     a real tier (1000/s). Sliding Window Log's state is O(burst)
//     entries, so an unbounded burst would let the log grow for as long
//     as the benchmark runs; bounding it keeps the benchmark measuring
//     the algorithm's steady-state cost instead of unbounded growth.
func benchRule(algorithm string) Rule {
	if algorithm == "token_bucket" {
		return Rule{Rate: 1e9, Burst: 1e9}
	}
	return Rule{Rate: 1e9, Burst: 1000}
}

// runAllowBenchmark drives Limiter.Allow for a single client key in a
// tight sequential loop, reporting the standard ns/op and allocs/op the
// README's benchmark table is built from.
func runAllowBenchmark(b *testing.B, algorithm string, st store.Store) {
	b.Helper()
	defer st.Close()

	limiter, err := New(algorithm, st, benchRule(algorithm))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := limiter.Allow(ctx, "bench-client"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenBucket_Memory(b *testing.B) {
	runAllowBenchmark(b, "token_bucket", newBenchMemoryStore(b))
}

func BenchmarkTokenBucket_Redis(b *testing.B) {
	runAllowBenchmark(b, "token_bucket", newBenchRedisStore(b))
}

func BenchmarkSlidingWindowLog_Memory(b *testing.B) {
	runAllowBenchmark(b, "sliding_window_log", newBenchMemoryStore(b))
}

func BenchmarkSlidingWindowLog_Redis(b *testing.B) {
	runAllowBenchmark(b, "sliding_window_log", newBenchRedisStore(b))
}

func BenchmarkFixedWindow_Memory(b *testing.B) {
	runAllowBenchmark(b, "fixed_window", newBenchMemoryStore(b))
}

func BenchmarkFixedWindow_Redis(b *testing.B) {
	runAllowBenchmark(b, "fixed_window", newBenchRedisStore(b))
}
