package store

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// entry is a single value held by MemoryStore, tagged with its own expiry
// so a lazy sweep can reclaim stale keys without needing a goroutine per key.
type entry struct {
	value     []byte
	expiresAt time.Time // zero value means "never expires"
}

func (e entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// MemoryStore is a mutex-protected in-process implementation of Store. It's
// the default backend for single-instance deployments, and it doubles as
// the fallback when Redis is configured but unreachable (see "Graceful
// degradation" in the README).
type MemoryStore struct {
	mu   sync.Mutex
	data map[string]entry

	stopSweep chan struct{}
}

// NewMemoryStore creates a MemoryStore and starts a background goroutine
// that periodically evicts expired keys — otherwise a long-running process
// would slowly accumulate memory for clients that stopped sending requests
// a while ago.
func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		data:      make(map[string]entry),
		stopSweep: make(chan struct{}),
	}
	go s.sweepLoop()
	return s
}

func (s *MemoryStore) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweep()
		case <-s.stopSweep:
			return
		}
	}
}

func (s *MemoryStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.data {
		if e.expired(now) {
			delete(s.data, k)
		}
	}
}

// Increment implements Store.
func (s *MemoryStore) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e, ok := s.data[key]
	if !ok || e.expired(now) {
		e = entry{value: encodeInt64(1), expiresAt: now.Add(ttl)}
		s.data[key] = e
		return 1, nil
	}

	next := decodeInt64(e.value) + 1
	e.value = encodeInt64(next)
	s.data[key] = e
	return next, nil
}

// Load implements Store.
func (s *MemoryStore) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok || e.expired(time.Now()) {
		return nil, ErrNotFound
	}
	// Return a copy so callers can't mutate our internal state.
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out, nil
}

// CompareAndSwap implements Store.
func (s *MemoryStore) CompareAndSwap(_ context.Context, key string, oldVal, newVal []byte, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e, ok := s.data[key]
	if !ok || e.expired(now) {
		if oldVal != nil {
			return false, nil
		}
	} else if !bytes.Equal(e.value, oldVal) {
		return false, nil
	}

	val := make([]byte, len(newVal))
	copy(val, newVal)

	next := entry{value: val}
	if ttl > 0 {
		next.expiresAt = now.Add(ttl)
	}
	s.data[key] = next
	return true, nil
}

// Ping implements Store. The in-memory store is always reachable.
func (s *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// Close implements Store.
func (s *MemoryStore) Close() error {
	close(s.stopSweep)
	return nil
}

// encodeInt64/decodeInt64 let Increment store its counter as the same
// []byte type Store uses everywhere else, so MemoryStore doesn't need a
// second internal representation just for counters.
func encodeInt64(n int64) []byte {
	return []byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	}
}

func decodeInt64(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	return int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
}
