package split

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWindow_CountsRequestsAndErrors(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	w := newWindow(time.Minute)
	for i := range 100 {
		w.record(now, 10*time.Millisecond, i%10 == 0)
	}
	s := w.sample(now)
	assert.Equal(t, uint64(100), s.Requests)
	assert.Equal(t, uint64(10), s.Errors)
	assert.InDelta(t, 0.10, s.ErrorRate(), 1e-9)
	assert.Zero(t, Sample{}.ErrorRate())
}

func TestWindow_OldRequestsLeaveTheWindow(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	w := newWindow(time.Minute)
	w.record(now, time.Millisecond, true)
	w.record(now.Add(30*time.Second), time.Millisecond, false)

	assert.Equal(t, uint64(2), w.sample(now.Add(50*time.Second)).Requests)
	s := w.sample(now.Add(65 * time.Second))
	assert.Equal(t, uint64(1), s.Requests, "the first request has aged out")
	assert.Equal(t, uint64(0), s.Errors)
	assert.Equal(t, uint64(0), w.sample(now.Add(2*time.Minute)).Requests)

	// The first request's slot is reused for a new slice, which starts
	// from zero instead of adding to the old count.
	w.record(now.Add(60*time.Second), time.Millisecond, false)
	s = w.sample(now.Add(65 * time.Second))
	assert.Equal(t, uint64(2), s.Requests, "the 30s and 60s requests")
	assert.Equal(t, uint64(0), s.Errors)
}

func TestWindow_Reset(t *testing.T) {
	now := time.Now()
	w := newWindow(time.Minute)
	w.record(now, time.Millisecond, true)
	w.reset()
	assert.Equal(t, Sample{}, w.sample(now))
}

func TestWindow_P95(t *testing.T) {
	now := time.Now()
	w := newWindow(time.Minute)
	// 95 fast requests and 5 slow ones: p95 sits at the top of the fast
	// ones; with 10 slow ones it's among the slow.
	for range 95 {
		w.record(now, 20*time.Millisecond, false)
	}
	for range 5 {
		w.record(now, 2*time.Second, false)
	}
	p95 := w.sample(now).P95
	assert.InDelta(t, float64(20*time.Millisecond), float64(p95), float64(6*time.Millisecond))

	for range 10 {
		w.record(now, 2*time.Second, false)
	}
	p95 = w.sample(now).P95
	assert.InDelta(t, float64(2*time.Second), float64(p95), float64(500*time.Millisecond))
	assert.Zero(t, newWindow(time.Minute).sample(now).P95)
}

func TestLatencyBuckets(t *testing.T) {
	assert.Equal(t, 0, latencyBucket(0))
	assert.Equal(t, 0, latencyBucket(time.Millisecond))
	assert.Equal(t, latencyBuckets-1, latencyBucket(time.Hour))
	for _, d := range []time.Duration{2 * time.Millisecond, 50 * time.Millisecond, time.Second, 30 * time.Second} {
		k := latencyBucket(d)
		assert.True(t, float64(d) > latencyBound(k-1) && float64(d) <= latencyBound(k)*1.0000001, "%s in bucket %d", d, k)
	}
}
