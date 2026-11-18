package split

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// guardedRoute is a 90/10 split whose canary has guardrails.
func guardedRoute(t *testing.T, clock *fakeClock, events *eventLog, ar config.AutoRollbackConfig) *Route {
	t.Helper()
	cfg := twoWay()
	if ar.Window.Duration == 0 {
		ar.Window.Duration = time.Minute
	}
	if ar.Cooldown.Duration == 0 {
		ar.Cooldown.Duration = 10 * time.Minute
	}
	cfg.Variants[1].AutoRollback = &ar
	return newRoute(t, cfg, WithClock(clock.Now), WithEvents(events.record))
}

// serve records n requests on variant i.
func serve(r *Route, i, n int, latency time.Duration, status int) {
	for range n {
		r.Record(i, latency, status)
	}
}

// settle lets the evaluation throttle pass and records one more
// baseline request, which triggers an evaluation.
func settle(r *Route, clock *fakeClock) {
	clock.Advance(evalInterval)
	r.Record(0, 10*time.Millisecond, http.StatusOK)
}

func TestGuard_RollsBackOnErrorRate(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 100, MaxErrorRateIncrease: 0.05})
	serve(r, 0, 500, 10*time.Millisecond, http.StatusOK)
	serve(r, 0, 5, 10*time.Millisecond, http.StatusBadGateway) // the baseline has 1% errors
	serve(r, 1, 90, 10*time.Millisecond, http.StatusOK)
	serve(r, 1, 10, 10*time.Millisecond, http.StatusInternalServerError) // 10%
	settle(r, clock)

	assert.Equal(t, Weights{100, 0}, r.Weights())
	e := events.last()
	assert.Equal(t, EventRollback, e.Kind)
	assert.Equal(t, "canary", e.Variant)
	assert.Equal(t, TriggerErrorRate, e.Trigger)
	assert.True(t, e.Auto)
	assert.Contains(t, e.Reason, "5xx rate 10.0% over 100 requests vs baseline 1.0%")
	lr := r.Status().LastRollback
	require.NotNil(t, lr)
	assert.True(t, lr.Auto)
	assert.Equal(t, TriggerErrorRate, lr.Trigger)

	// The windows start over, so nothing that led to the rollback lingers.
	assert.Equal(t, uint64(0), r.guardFor(1).own.sample(clock.Now()).Requests)
}

func TestGuard_RollsBackOnLatency(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 50, MaxP95LatencyRatio: 1.5})
	serve(r, 0, 200, 40*time.Millisecond, http.StatusOK)
	serve(r, 1, 60, 200*time.Millisecond, http.StatusOK)
	settle(r, clock)
	assert.Equal(t, Weights{100, 0}, r.Weights())
	assert.Equal(t, TriggerLatency, events.last().Trigger)
	assert.Contains(t, events.last().Reason, "p95 latency")
}

func TestGuard_SmallSamplesNeverTrigger(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 100, MaxErrorRateIncrease: 0.05, MaxP95LatencyRatio: 1.5})
	serve(r, 0, 500, 10*time.Millisecond, http.StatusOK)
	serve(r, 1, 99, 5*time.Second, http.StatusServiceUnavailable) // every one failed, and slowly
	settle(r, clock)
	assert.Equal(t, Weights{90, 10}, r.Weights(), "99 requests are below min_requests")
	assert.Empty(t, events.kinds())

	serve(r, 1, 1, 5*time.Second, http.StatusServiceUnavailable)
	settle(r, clock)
	assert.Equal(t, Weights{100, 0}, r.Weights(), "the 100th request makes the sample count")
}

func TestGuard_LatencyNeedsABaselineSample(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 50, MaxP95LatencyRatio: 1.5})
	serve(r, 0, 10, 10*time.Millisecond, http.StatusOK) // too few to know the baseline's p95
	serve(r, 1, 100, time.Second, http.StatusOK)
	settle(r, clock)
	assert.Equal(t, Weights{90, 10}, r.Weights())
}

func TestGuard_WithinLimitsNothingHappens(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 100, MaxErrorRateIncrease: 0.05, MaxP95LatencyRatio: 1.5})
	serve(r, 0, 1000, 50*time.Millisecond, http.StatusOK)
	serve(r, 0, 30, 50*time.Millisecond, http.StatusInternalServerError) // 3%
	serve(r, 1, 200, 60*time.Millisecond, http.StatusOK)                 // 20% slower
	serve(r, 1, 14, 60*time.Millisecond, http.StatusInternalServerError) // 6.5%: +3.5 points
	settle(r, clock)
	assert.Equal(t, Weights{90, 10}, r.Weights())
	assert.Empty(t, events.kinds())
}

func TestGuard_OldErrorsAgeOut(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 100, MaxErrorRateIncrease: 0.05})
	serve(r, 1, 100, time.Millisecond, http.StatusInternalServerError)
	clock.Advance(2 * time.Minute) // past the 1m window before anyone looks
	serve(r, 1, 100, time.Millisecond, http.StatusOK)
	settle(r, clock)
	assert.Equal(t, Weights{90, 10}, r.Weights())
}

func TestGuard_EvaluatesAtMostOncePerInterval(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 10, MaxErrorRateIncrease: 0.05})
	r.Record(0, time.Millisecond, http.StatusOK) // the first evaluation: nothing to judge yet
	serve(r, 1, 50, time.Millisecond, http.StatusInternalServerError)
	assert.Equal(t, Weights{90, 10}, r.Weights(), "not re-evaluated within the interval")
	settle(r, clock)
	assert.Equal(t, Weights{100, 0}, r.Weights())
}

func TestGuard_IdleVariantIsNotJudged(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := guardedRoute(t, clock, events, config.AutoRollbackConfig{MinRequests: 10, MaxErrorRateIncrease: 0.05})
	require.NoError(t, r.SetWeights(Weights{100, 0}))
	// Testers forcing the canary while it has no weight can't roll back
	// what isn't there.
	serve(r, 1, 50, time.Millisecond, http.StatusInternalServerError)
	settle(r, clock)
	assert.Equal(t, []string{EventSet}, events.kinds())
}

func TestGuard_UnguardedRouteIgnoresRecords(t *testing.T) {
	r := newRoute(t, twoWay())
	serve(r, 1, 1000, time.Second, http.StatusInternalServerError)
	assert.Equal(t, Weights{90, 10}, r.Weights())
}
