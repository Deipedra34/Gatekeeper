package split

import (
	"errors"
	"time"
)

// Rollout states, reported in RolloutStatus.State.
const (
	RolloutRunning   = "running"
	RolloutPaused    = "paused"
	RolloutCompleted = "completed"
	// RolloutStopped: an operator or a rollback took over the weights.
	RolloutStopped = "stopped"
)

// ErrNoRollout is returned when an action needs a rollout the route
// doesn't have (or that isn't running).
var ErrNoRollout = errors.New("split: no rollout is running on this route")

// rollout is a schedule raising one variant's weight step by step. It's
// evaluated lazily — whenever the weights are read — so it needs no
// goroutine, and a paused or stopped one simply stops advancing.
type rollout struct {
	variant  int
	steps    []int
	interval time.Duration

	step        int       // index into steps
	stepStarted time.Time // when the current step began
	pausedAt    time.Time // zero unless paused
	state       string
}

func newRollout(variant int, steps []int, interval time.Duration, now time.Time) *rollout {
	ro := &rollout{variant: variant, steps: steps, interval: interval, stepStarted: now, state: RolloutRunning}
	if len(steps) == 1 {
		ro.state = RolloutCompleted
	}
	return ro
}

// advance moves through every step whose interval has passed by now,
// returning how many steps it took.
func (ro *rollout) advance(now time.Time) int {
	moved := 0
	for ro.state == RolloutRunning && ro.step < len(ro.steps)-1 && !now.Before(ro.stepStarted.Add(ro.interval)) {
		ro.step++
		ro.stepStarted = ro.stepStarted.Add(ro.interval)
		moved++
	}
	if ro.state == RolloutRunning && ro.step == len(ro.steps)-1 {
		ro.state = RolloutCompleted
	}
	return moved
}

// share is the rollout variant's current weight.
func (ro *rollout) share() int { return ro.steps[ro.step] }

func (ro *rollout) pause(now time.Time) error {
	if ro.state != RolloutRunning {
		return ErrNoRollout
	}
	ro.state, ro.pausedAt = RolloutPaused, now
	return nil
}

// unpause carries on where the rollout paused: the time already spent on
// the current step still counts.
func (ro *rollout) unpause(now time.Time) {
	ro.stepStarted = ro.stepStarted.Add(now.Sub(ro.pausedAt))
	ro.pausedAt = time.Time{}
	ro.state = RolloutRunning
}

// nextStepAt is when the next step is due, or zero if none is.
func (ro *rollout) nextStepAt() time.Time {
	if ro.state != RolloutRunning || ro.step >= len(ro.steps)-1 {
		return time.Time{}
	}
	return ro.stepStarted.Add(ro.interval)
}

// RolloutStatus describes a route's rollout.
type RolloutStatus struct {
	Variant    string     `json:"variant"`
	Steps      []int      `json:"steps"`
	Interval   string     `json:"interval"`
	Step       int        `json:"step"`
	Weight     int        `json:"weight"`
	State      string     `json:"state"`
	NextStepAt *time.Time `json:"next_step_at,omitempty"`
}

func (ro *rollout) status(name string) *RolloutStatus {
	st := &RolloutStatus{
		Variant: name, Steps: append([]int(nil), ro.steps...), Interval: ro.interval.String(),
		Step: ro.step, Weight: ro.share(), State: ro.state,
	}
	if t := ro.nextStepAt(); !t.IsZero() {
		t = t.UTC()
		st.NextStepAt = &t
	}
	return st
}
