package circuitbreaker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() Config {
	return Config{
		FailureThreshold:    3,
		OpenDuration:        30 * time.Millisecond,
		HalfOpenMaxRequests: 1,
		SuccessesToClose:    1,
		FailuresToReopen:    1,
	}
}

// trip drives cb through cfg.FailureThreshold consecutive failures,
// tripping it from Closed to Open.
func trip(t *testing.T, cb *CircuitBreaker, failures int) {
	t.Helper()
	for i := 0; i < failures; i++ {
		require.True(t, cb.Allow(), "should still be allowed while tripping the breaker")
		cb.Report(false)
	}
}

func TestCircuitBreaker_StartsClosed(t *testing.T) {
	cb := New(testConfig(), nil, "test")
	assert.Equal(t, Closed, cb.State())
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_TripsToOpenAfterThresholdFailures(t *testing.T) {
	cfg := testConfig()
	cb := New(cfg, nil, "test")

	trip(t, cb, cfg.FailureThreshold)

	assert.Equal(t, Open, cb.State(), "breaker should trip after FailureThreshold consecutive failures")
}

func TestCircuitBreaker_SuccessResetsConsecutiveFailureCount(t *testing.T) {
	cfg := testConfig()
	cb := New(cfg, nil, "test")

	// Two failures, then a success: the streak should reset, so one more
	// failure alone must not trip it.
	require.True(t, cb.Allow())
	cb.Report(false)
	require.True(t, cb.Allow())
	cb.Report(false)
	require.True(t, cb.Allow())
	cb.Report(true)

	require.True(t, cb.Allow())
	cb.Report(false)
	assert.Equal(t, Closed, cb.State(), "a success should reset the consecutive-failure count")
}

func TestCircuitBreaker_RequestsFailFastWhileOpen(t *testing.T) {
	cfg := testConfig()
	cb := New(cfg, nil, "test")
	trip(t, cb, cfg.FailureThreshold)
	require.Equal(t, Open, cb.State())

	for i := 0; i < 5; i++ {
		assert.False(t, cb.Allow(), "no request should be let through while Open")
	}
	assert.Equal(t, Open, cb.State(), "state should still be Open before the cooldown elapses")
}

func TestCircuitBreaker_TransitionsToHalfOpenAfterCooldown(t *testing.T) {
	cfg := testConfig()
	cb := New(cfg, nil, "test")
	trip(t, cb, cfg.FailureThreshold)
	require.Equal(t, Open, cb.State())

	time.Sleep(cfg.OpenDuration * 3)

	assert.Equal(t, HalfOpen, cb.State(), "breaker should move to Half-Open once the cooldown elapses")
	assert.True(t, cb.Allow(), "a trial request should be admitted in Half-Open")
}

func TestCircuitBreaker_SuccessfulTrialClosesBreaker(t *testing.T) {
	cfg := testConfig()
	cb := New(cfg, nil, "test")
	trip(t, cb, cfg.FailureThreshold)
	time.Sleep(cfg.OpenDuration * 3)
	require.Equal(t, HalfOpen, cb.State())

	require.True(t, cb.Allow(), "trial request should be admitted")
	cb.Report(true)

	assert.Equal(t, Closed, cb.State(), "a successful trial should close the breaker")

	// Closed means unrestricted again, not still gated by the Half-Open
	// trial limit.
	for i := 0; i < 5; i++ {
		assert.True(t, cb.Allow())
		cb.Report(true)
	}
}

func TestCircuitBreaker_FailedTrialReopensBreaker(t *testing.T) {
	cfg := testConfig()
	cb := New(cfg, nil, "test")
	trip(t, cb, cfg.FailureThreshold)
	time.Sleep(cfg.OpenDuration * 3)
	require.Equal(t, HalfOpen, cb.State())

	require.True(t, cb.Allow(), "trial request should be admitted")
	cb.Report(false)

	assert.Equal(t, Open, cb.State(), "a failed trial should re-open the breaker")
	assert.False(t, cb.Allow(), "the freshly re-opened breaker should fail fast immediately")
}

func TestCircuitBreaker_HalfOpenLimitsConcurrentTrials(t *testing.T) {
	cfg := testConfig()
	cfg.HalfOpenMaxRequests = 2
	cfg.SuccessesToClose = 10 // stay in Half-Open for the duration of this test
	cb := New(cfg, nil, "test")
	trip(t, cb, cfg.FailureThreshold)
	time.Sleep(cfg.OpenDuration * 3)
	require.Equal(t, HalfOpen, cb.State())

	assert.True(t, cb.Allow(), "1st trial slot")
	assert.True(t, cb.Allow(), "2nd trial slot")
	assert.False(t, cb.Allow(), "3rd concurrent trial should be rejected: only 2 slots configured")

	cb.Release() // one of the two in-flight trials is abandoned, not reported
	assert.True(t, cb.Allow(), "a released slot should be reusable")
}

func TestCircuitBreaker_ReleaseDoesNotCountAsAnOutcome(t *testing.T) {
	cfg := testConfig()
	cfg.FailuresToReopen = 1
	cb := New(cfg, nil, "test")
	trip(t, cb, cfg.FailureThreshold)
	time.Sleep(cfg.OpenDuration * 3)
	require.Equal(t, HalfOpen, cb.State())

	require.True(t, cb.Allow())
	cb.Release()

	assert.Equal(t, HalfOpen, cb.State(), "an abandoned trial must not itself reopen or close the breaker")
}

func TestState_String(t *testing.T) {
	assert.Equal(t, "closed", Closed.String())
	assert.Equal(t, "open", Open.String())
	assert.Equal(t, "half_open", HalfOpen.String())
}
