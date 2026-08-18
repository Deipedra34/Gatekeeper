package store

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// newTestRedisStore spins up an in-process fake Redis server so the
// RedisStore test suite doesn't require a real Redis instance. It
// returns mr.FastForward as the store's time-advance function, since
// miniredis TTLs are virtual and only tick down when FastForward is
// called explicitly (see testStoreConformance's doc comment).
func newTestRedisStore(t *testing.T) (Store, func(time.Duration)) {
	t.Helper()
	mr := miniredis.RunT(t)
	return NewRedisStore(mr.Addr(), "", 0, time.Second), mr.FastForward
}

func TestRedisStore_Conformance(t *testing.T) {
	testStoreConformance(t, func() (Store, func(time.Duration)) {
		return newTestRedisStore(t)
	})
}
