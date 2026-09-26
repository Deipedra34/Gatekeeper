// Package circuitbreaker implements a three-state circuit breaker
// (Closed, Open, Half-Open) that Gatekeeper's proxy wraps around backend
// calls. A struggling backend gets a break from traffic — once it's
// failed enough in a row, further requests fail fast instead of piling
// up behind timeouts and retries, until a cooldown period passes and a
// handful of trial requests confirm it has recovered.
package circuitbreaker

import (
	"sync"
	"time"

	"gatekeeper/internal/metrics"
)

// State is one of the three circuit breaker states.
type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

// String implements fmt.Stringer for logging.
func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	case HalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// Config controls when a breaker trips, how long it stays open, and how
// it decides whether a recovering backend is healthy again.
type Config struct {
	// FailureThreshold is how many failures in a row trip the breaker
	// from Closed to Open. Any success resets the count to zero.
	FailureThreshold int

	// OpenDuration is how long the breaker stays Open before letting a
	// trial request through in Half-Open.
	OpenDuration time.Duration

	// HalfOpenMaxRequests is how many trial requests are let through
	// concurrently while Half-Open; further requests fail fast until one
	// of the in-flight trials completes.
	HalfOpenMaxRequests int

	// SuccessesToClose is how many Half-Open trial successes are needed
	// to close the breaker again.
	SuccessesToClose int

	// FailuresToReopen is how many Half-Open trial failures re-open the
	// breaker, restarting the OpenDuration cooldown.
	FailuresToReopen int
}

// CircuitBreaker is safe for concurrent use.
type CircuitBreaker struct {
	cfg   Config
	label string
	m     *metrics.Metrics

	mu               sync.Mutex
	state            State
	consecutiveFails int
	openedAt         time.Time
	halfOpenInFlight int
	halfOpenSuccess  int
	halfOpenFailure  int
}

// New creates a CircuitBreaker in the Closed state. m and label, when m
// is non-nil, keep the gatekeeper_circuit_breaker_state gauge for this
// route in sync with every transition; m may be nil in tests that don't
// care about metrics.
func New(cfg Config, m *metrics.Metrics, label string) *CircuitBreaker {
	cb := &CircuitBreaker{cfg: cfg, m: m, label: label, state: Closed}
	cb.publishState()
	return cb
}

// State reports the breaker's current state. If it's Open and the
// cooldown has elapsed, this resolves the transition to Half-Open first
// — the same lazy check Allow performs — so a caller inspecting state
// sees the same reality Allow is about to act on.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.maybeExpireOpen(time.Now())
	return cb.state
}

// Allow reports whether a request may proceed right now. In Half-Open it
// also reserves one of the limited trial slots on a true return; the
// caller must then call exactly one of Report or Release for that same
// call before it can be let through again.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.maybeExpireOpen(time.Now())

	switch cb.state {
	case Closed:
		return true
	case HalfOpen:
		if cb.halfOpenInFlight >= cb.cfg.HalfOpenMaxRequests {
			return false
		}
		cb.halfOpenInFlight++
		return true
	default: // Open
		return false
	}
}

// Release undoes the trial-slot reservation from an Allow that returned
// true, for a request that was abandoned (e.g. its context was cancelled
// during retry backoff) before it ever reached the backend — so it
// counts toward neither outcome.
func (cb *CircuitBreaker) Release() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == HalfOpen && cb.halfOpenInFlight > 0 {
		cb.halfOpenInFlight--
	}
}

// Report records the outcome of a call that Allow let through.
func (cb *CircuitBreaker) Report(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case HalfOpen:
		cb.halfOpenInFlight--
		if success {
			cb.halfOpenSuccess++
			if cb.halfOpenSuccess >= cb.cfg.SuccessesToClose {
				cb.toClosed()
			}
		} else {
			cb.halfOpenFailure++
			if cb.halfOpenFailure >= cb.cfg.FailuresToReopen {
				cb.toOpen(time.Now())
			}
		}
	case Closed:
		if success {
			cb.consecutiveFails = 0
			return
		}
		cb.consecutiveFails++
		if cb.consecutiveFails >= cb.cfg.FailureThreshold {
			cb.toOpen(time.Now())
		}
	case Open:
		// Allow() shouldn't have let this through; ignore defensively.
	}
}

// maybeExpireOpen lazily resolves an elapsed Open cooldown into
// Half-Open, the same way MemoryStore lazily expires a stale entry only
// when it's next touched, instead of running a background timer.
func (cb *CircuitBreaker) maybeExpireOpen(now time.Time) {
	if cb.state == Open && now.Sub(cb.openedAt) >= cb.cfg.OpenDuration {
		cb.toHalfOpen()
	}
}

func (cb *CircuitBreaker) toOpen(now time.Time) {
	cb.state = Open
	cb.openedAt = now
	cb.consecutiveFails = 0
	cb.resetHalfOpenCounters()
	cb.publishState()
}

func (cb *CircuitBreaker) toHalfOpen() {
	cb.state = HalfOpen
	cb.resetHalfOpenCounters()
	cb.publishState()
}

func (cb *CircuitBreaker) toClosed() {
	cb.state = Closed
	cb.consecutiveFails = 0
	cb.resetHalfOpenCounters()
	cb.publishState()
}

func (cb *CircuitBreaker) resetHalfOpenCounters() {
	cb.halfOpenInFlight = 0
	cb.halfOpenSuccess = 0
	cb.halfOpenFailure = 0
}

func (cb *CircuitBreaker) publishState() {
	if cb.m == nil {
		return
	}
	cb.m.CircuitBreakerState.WithLabelValues(cb.label).Set(float64(cb.state))
}
