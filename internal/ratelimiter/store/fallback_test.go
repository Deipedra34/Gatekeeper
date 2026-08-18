package store

import (
	"context"
	"errors"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// brokenStore always errors, simulating an unreachable Redis.
type brokenStore struct{}

func (brokenStore) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("connection refused")
}
func (brokenStore) Load(context.Context, string) ([]byte, error) {
	return nil, errors.New("connection refused")
}
func (brokenStore) CompareAndSwap(context.Context, string, []byte, []byte, time.Duration) (bool, error) {
	return false, errors.New("connection refused")
}
func (brokenStore) Ping(context.Context) error { return errors.New("connection refused") }
func (brokenStore) Close() error               { return nil }

func TestFallbackStore_FallsBackWhenPrimaryErrors(t *testing.T) {
	fs := NewFallbackStore(brokenStore{}, NewMemoryStore(), time.Hour, log.Default())
	defer fs.Close()

	v, err := fs.Increment(context.Background(), "key", time.Minute)
	require.NoError(t, err, "a broken primary must not surface an error to the caller")
	assert.Equal(t, int64(1), v)
}

func TestFallbackStore_RecoversAfterHealthCheck(t *testing.T) {
	primary := &toggleStore{}
	fs := NewFallbackStore(primary, NewMemoryStore(), 20*time.Millisecond, log.Default())
	defer fs.Close()

	_, err := fs.Increment(context.Background(), "key", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 0, primary.calls(), "unhealthy primary should be skipped entirely")

	primary.setHealthy(true)
	time.Sleep(60 * time.Millisecond) // let the background health check observe recovery

	_, err = fs.Increment(context.Background(), "key", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, primary.calls(), "once healthy again, the primary should be used")
}

// toggleStore lets a test flip whether the store errors, to exercise
// FallbackStore's recovery path. It's accessed concurrently by the test
// goroutine and FallbackStore's background health-check loop, so its
// state is mutex-protected.
type toggleStore struct {
	mu             sync.Mutex
	healthy        bool
	incrementCalls int
}

func (s *toggleStore) setHealthy(h bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = h
}

func (s *toggleStore) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incrementCalls
}

func (s *toggleStore) Increment(context.Context, string, time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy {
		return 0, errors.New("down")
	}
	s.incrementCalls++
	return 1, nil
}
func (s *toggleStore) Load(context.Context, string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy {
		return nil, errors.New("down")
	}
	return nil, ErrNotFound
}
func (s *toggleStore) CompareAndSwap(context.Context, string, []byte, []byte, time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy {
		return false, errors.New("down")
	}
	return true, nil
}
func (s *toggleStore) Ping(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy {
		return errors.New("down")
	}
	return nil
}
func (s *toggleStore) Close() error { return nil }
