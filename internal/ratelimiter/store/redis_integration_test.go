package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestRedisStore_Conformance_RealRedis runs the shared Store conformance
// suite against a real Redis server rather than the in-process miniredis
// fake used by TestRedisStore_Conformance. It only runs when
// GATEKEEPER_TEST_REDIS_ADDR points at a reachable Redis (CI sets this to
// the workflow's redis service container); otherwise it skips, so a plain
// `go test ./...` on a machine without Redis stays green.
//
// Because a real server's TTLs tick down with wall-clock time, the
// "advance" function here is a real time.Sleep instead of miniredis's
// virtual FastForward. Each newStore call flushes the database so the
// sub-tests — and repeat runs — start from a clean slate.
func TestRedisStore_Conformance_RealRedis(t *testing.T) {
	addr := os.Getenv("GATEKEEPER_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("GATEKEEPER_TEST_REDIS_ADDR not set; skipping real-Redis conformance test")
	}

	ctx := context.Background()
	probe := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 2 * time.Second})
	if err := probe.Ping(ctx).Err(); err != nil {
		probe.Close()
		t.Fatalf("GATEKEEPER_TEST_REDIS_ADDR=%q is set but Redis is unreachable: %v", addr, err)
	}
	probe.Close()

	testStoreConformance(t, func() (Store, func(time.Duration)) {
		flush := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 2 * time.Second})
		if err := flush.FlushDB(ctx).Err(); err != nil {
			t.Fatalf("flushing test Redis: %v", err)
		}
		flush.Close()

		return NewRedisStore(addr, "", 0, 2*time.Second), func(d time.Duration) {
			time.Sleep(d)
		}
	})
}
