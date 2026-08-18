package store

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// FallbackStore wraps a primary store (in practice, Redis) with a
// secondary store (always in-memory) so a primary outage costs you
// rate-limiting accuracy, not the whole gateway. Every operation tries the
// primary first; if that fails, it logs a warning, falls back to the
// secondary for that one call, and marks the primary unhealthy so later
// calls skip straight to the secondary — until a background health check
// confirms the primary is back.
type FallbackStore struct {
	primary   Store
	secondary Store
	logger    *log.Logger

	healthy atomic.Bool

	checkInterval time.Duration
	stopCh        chan struct{}
}

// NewFallbackStore creates a FallbackStore and starts its background
// health checker, which pings primary every checkInterval to detect
// recovery after a failover.
func NewFallbackStore(primary, secondary Store, checkInterval time.Duration, logger *log.Logger) *FallbackStore {
	fs := &FallbackStore{
		primary:       primary,
		secondary:     secondary,
		logger:        logger,
		checkInterval: checkInterval,
		stopCh:        make(chan struct{}),
	}
	fs.healthy.Store(true)
	go fs.healthLoop()
	return fs
}

func (fs *FallbackStore) healthLoop() {
	ticker := time.NewTicker(fs.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fs.checkHealth()
		case <-fs.stopCh:
			return
		}
	}
}

func (fs *FallbackStore) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), fs.checkInterval)
	defer cancel()

	err := fs.primary.Ping(ctx)
	if err == nil {
		if fs.healthy.CompareAndSwap(false, true) {
			fs.logger.Printf("store: primary backend recovered, resuming use of it")
		}
		return
	}
	fs.markUnhealthy(err)
}

// markUnhealthy flips the store to secondary-only mode. It only prints on
// the true->false transition, so you get one log line per outage instead
// of one per failed request.
func (fs *FallbackStore) markUnhealthy(err error) {
	if fs.healthy.CompareAndSwap(true, false) {
		fs.logger.Printf("store: WARNING: primary backend unreachable (%v); falling back to in-memory rate limiting", err)
	}
}

// Increment implements Store.
func (fs *FallbackStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if fs.healthy.Load() {
		v, err := fs.primary.Increment(ctx, key, ttl)
		if err == nil {
			return v, nil
		}
		fs.markUnhealthy(err)
	}
	return fs.secondary.Increment(ctx, key, ttl)
}

// Load implements Store.
func (fs *FallbackStore) Load(ctx context.Context, key string) ([]byte, error) {
	if fs.healthy.Load() {
		v, err := fs.primary.Load(ctx, key)
		if err == nil || err == ErrNotFound {
			return v, err
		}
		fs.markUnhealthy(err)
	}
	return fs.secondary.Load(ctx, key)
}

// CompareAndSwap implements Store.
func (fs *FallbackStore) CompareAndSwap(ctx context.Context, key string, oldVal, newVal []byte, ttl time.Duration) (bool, error) {
	if fs.healthy.Load() {
		ok, err := fs.primary.CompareAndSwap(ctx, key, oldVal, newVal, ttl)
		if err == nil {
			return ok, nil
		}
		fs.markUnhealthy(err)
	}
	return fs.secondary.CompareAndSwap(ctx, key, oldVal, newVal, ttl)
}

// Ping implements Store, reporting on whichever backend is currently
// active.
func (fs *FallbackStore) Ping(ctx context.Context) error {
	if fs.healthy.Load() {
		return fs.primary.Ping(ctx)
	}
	return fs.secondary.Ping(ctx)
}

// Close implements Store, releasing both the primary and secondary
// backends and stopping the health-check loop.
func (fs *FallbackStore) Close() error {
	close(fs.stopCh)
	primaryErr := fs.primary.Close()
	secondaryErr := fs.secondary.Close()
	if primaryErr != nil {
		return primaryErr
	}
	return secondaryErr
}
