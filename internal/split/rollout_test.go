package split

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// fakeClock is a settable clock for routes under test.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// eventLog records a route's events.
type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) record(e Event) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) kinds() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.events {
		out = append(out, e.Kind)
	}
	return out
}

func (l *eventLog) last() Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.events[len(l.events)-1]
}

func rolloutRoute(t *testing.T, clock *fakeClock, events *eventLog) *Route {
	t.Helper()
	cfg := twoWay()
	cfg.Rollout = &config.RolloutConfig{Variant: "canary", Steps: []int{5, 25, 50, 100}, Interval: config.Duration{Duration: 10 * time.Minute}}
	return newRoute(t, cfg, WithClock(clock.Now), WithEvents(events.record))
}

func TestRollout_StepsUpOverTime(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := rolloutRoute(t, clock, events)

	assert.Equal(t, Weights{95, 5}, r.Weights(), "the first step replaces the configured weight")
	st := r.Rollout()
	require.NotNil(t, st)
	assert.Equal(t, RolloutRunning, st.State)
	assert.Equal(t, 0, st.Step)
	assert.Equal(t, clock.Now().Add(10*time.Minute), *st.NextStepAt)

	clock.Advance(9*time.Minute + 59*time.Second)
	assert.Equal(t, Weights{95, 5}, r.Weights())
	clock.Advance(time.Second)
	assert.Equal(t, Weights{75, 25}, r.Weights())
	assert.Equal(t, []string{EventRolloutStep}, events.kinds())
	e := events.last()
	assert.Equal(t, "/api", e.Route)
	assert.Equal(t, "canary", e.Variant)
	assert.Equal(t, map[string]int{"stable": 75, "canary": 25}, e.Weights)
	assert.True(t, e.Auto)

	clock.Advance(10 * time.Minute)
	assert.Equal(t, Weights{50, 50}, r.Weights())
	clock.Advance(10 * time.Minute)
	assert.Equal(t, Weights{0, 100}, r.Weights())
	st = r.Rollout()
	assert.Equal(t, RolloutCompleted, st.State)
	assert.Nil(t, st.NextStepAt)

	clock.Advance(time.Hour)
	assert.Equal(t, Weights{0, 100}, r.Weights(), "it stays at the last step")
	assert.Len(t, events.kinds(), 3)
}

func TestRollout_CatchesUpAfterAQuietPeriod(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := rolloutRoute(t, clock, events)
	clock.Advance(25 * time.Minute) // no requests in between
	assert.Equal(t, Weights{50, 50}, r.Weights())
	assert.Equal(t, 2, r.Rollout().Step)
	assert.Equal(t, []string{EventRolloutStep}, events.kinds(), "one event for the catch-up")
	assert.Equal(t, clock.Now().Add(5*time.Minute), *r.Rollout().NextStepAt, "steps stay on the original schedule")
}

func TestRollout_PauseAndResume(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := rolloutRoute(t, clock, events)
	clock.Advance(14 * time.Minute) // 4 minutes into step 1
	assert.Equal(t, Weights{75, 25}, r.Weights())

	require.NoError(t, r.Pause())
	assert.Equal(t, RolloutPaused, r.Rollout().State)
	assert.Nil(t, r.Rollout().NextStepAt)
	assert.ErrorIs(t, r.Pause(), ErrNoRollout, "already paused")

	clock.Advance(3 * time.Hour)
	assert.Equal(t, Weights{75, 25}, r.Weights(), "frozen while paused")

	require.NoError(t, r.Resume(false))
	assert.Equal(t, RolloutRunning, r.Rollout().State)
	assert.ErrorIs(t, r.Resume(false), ErrNothingToResume, "not paused")
	assert.Equal(t, clock.Now().Add(6*time.Minute), *r.Rollout().NextStepAt, "the 4 minutes already spent still count")
	clock.Advance(6 * time.Minute)
	assert.Equal(t, Weights{50, 50}, r.Weights())

	assert.Equal(t, []string{EventRolloutStep, EventPause, EventResume, EventRolloutStep}, events.kinds())
}

func TestRollout_ThreeVariantsKeepTheirProportions(t *testing.T) {
	cfg := twoWay()
	cfg.Variants = []config.VariantConfig{
		{Name: "stable", Weight: 60}, {Name: "legacy", Weight: 30}, {Name: "canary", Weight: 10},
	}
	clock := newFakeClock()
	cfg.Rollout = &config.RolloutConfig{Variant: "canary", Steps: []int{10, 40}, Interval: config.Duration{Duration: time.Minute}}
	r := newRoute(t, cfg, WithClock(clock.Now))
	assert.Equal(t, Weights{60, 30, 10}, r.Weights())
	clock.Advance(time.Minute)
	assert.Equal(t, Weights{40, 20, 40}, r.Weights())
}

func TestRollout_WithoutOne(t *testing.T) {
	r := newRoute(t, twoWay())
	assert.Nil(t, r.Rollout())
	assert.ErrorIs(t, r.Pause(), ErrNoRollout)
	assert.ErrorIs(t, r.Resume(false), ErrNothingToResume)
}

func TestRollout_ConcurrentReadersSeeOneStepEvent(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := rolloutRoute(t, clock, events)
	clock.Advance(10 * time.Minute)
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { assert.Equal(t, Weights{75, 25}, r.Weights()) })
	}
	wg.Wait()
	assert.Equal(t, []string{EventRolloutStep}, events.kinds())
}
