package split

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControl_SetWeights(t *testing.T) {
	events := &eventLog{}
	r := newRoute(t, twoWay(), WithEvents(events.record))
	require.NoError(t, r.SetWeights(Weights{70, 30}, false))
	assert.Equal(t, Weights{70, 30}, r.Weights())
	st := r.Status()
	assert.True(t, st.Manual)
	assert.Equal(t, []VariantStatus{{Name: "stable", Weight: 70, ConfiguredWeight: 90}, {Name: "canary", Weight: 30, ConfiguredWeight: 10}}, st.Variants)
	assert.Equal(t, EventSet, events.last().Kind)
	assert.Equal(t, map[string]int{"stable": 70, "canary": 30}, events.last().Weights)

	for _, bad := range []Weights{{70, 20}, {101, -1}, {100}, {50, 25, 25}} {
		assert.ErrorIs(t, r.SetWeights(bad, false), ErrInvalidWeights, "%v", bad)
	}
	assert.Equal(t, Weights{70, 30}, r.Weights(), "unchanged by a bad request")
}

func TestControl_SetWeightsStopsTheRollout(t *testing.T) {
	clock := newFakeClock()
	r := rolloutRoute(t, clock, &eventLog{})
	require.NoError(t, r.SetWeights(Weights{80, 20}, false))
	assert.Equal(t, RolloutStopped, r.Rollout().State)
	clock.Advance(time.Hour)
	assert.Equal(t, Weights{80, 20}, r.Weights(), "the schedule no longer applies")
	assert.ErrorIs(t, r.Pause(), ErrNoRollout)
}

func TestControl_Promote(t *testing.T) {
	clock := newFakeClock()
	r := rolloutRoute(t, clock, &eventLog{})
	require.NoError(t, r.Promote(1, false))
	assert.Equal(t, Weights{0, 100}, r.Weights())
	assert.Equal(t, RolloutStopped, r.Rollout().State)
	require.NoError(t, r.Promote(0, false))
	assert.Equal(t, Weights{100, 0}, r.Weights(), "promoting stable is a full rollback by hand")
	assert.Error(t, r.Promote(2, false))
}

func TestControl_ManualRollback(t *testing.T) {
	clock, events := newFakeClock(), &eventLog{}
	r := rolloutRoute(t, clock, events)
	clock.Advance(20 * time.Minute)
	assert.Equal(t, Weights{50, 50}, r.Weights())

	done, err := r.Rollback(1, "manual")
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, Weights{100, 0}, r.Weights())
	st := r.Status()
	require.NotNil(t, st.LastRollback)
	assert.Equal(t, Rollback{Variant: "canary", Trigger: TriggerManual, Reason: "manual", Auto: false, At: clock.Now()}, *st.LastRollback)
	assert.Equal(t, RolloutStopped, st.Rollout.State)

	done, err = r.Rollback(1, "again")
	require.NoError(t, err)
	assert.False(t, done, "nothing left to take")
	assert.Equal(t, "manual", r.Status().LastRollback.Reason)

	_, err = r.Rollback(0, "x")
	assert.ErrorIs(t, err, ErrBaseline)
	e := events.last()
	assert.Equal(t, EventRollback, e.Kind)
	assert.Equal(t, "canary", e.Variant)
}

func TestControl_ResumeRestartsAStoppedRollout(t *testing.T) {
	clock := newFakeClock()
	r := rolloutRoute(t, clock, &eventLog{})
	clock.Advance(20 * time.Minute)
	_, err := r.Rollback(1, "manual")
	require.NoError(t, err)

	clock.Advance(time.Hour)
	require.NoError(t, r.Resume(false))
	assert.Equal(t, Weights{95, 5}, r.Weights(), "from the first step again")
	st := r.Status()
	assert.False(t, st.Manual)
	assert.Equal(t, RolloutRunning, st.Rollout.State)
	assert.Equal(t, clock.Now().Add(10*time.Minute), *st.Rollout.NextStepAt)
	assert.ErrorIs(t, r.Resume(false), ErrNothingToResume)
}

func TestControl_ResumeRestoresConfiguredWeights(t *testing.T) {
	r := newRoute(t, twoWay())
	assert.ErrorIs(t, r.Resume(false), ErrNothingToResume)
	require.NoError(t, r.SetWeights(Weights{50, 50}, false))
	require.NoError(t, r.Resume(false))
	assert.Equal(t, Weights{90, 10}, r.Weights())
	assert.False(t, r.Status().Manual)
}
