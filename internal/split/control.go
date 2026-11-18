package split

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by the operator controls.
var (
	// ErrInvalidWeights: weights that aren't one whole percentage per
	// variant adding up to 100.
	ErrInvalidWeights = errors.New("split: weights must give every variant 0-100 and add up to 100")
	// ErrNothingToResume: the route already runs as configured.
	ErrNothingToResume = errors.New("split: nothing to resume: the route already follows its configured weights")
	// ErrBaseline: the baseline can't be rolled back.
	ErrBaseline = errors.New("split: the baseline can't be rolled back; promote another variant instead")
)

// Rollback records the most recent rollback of a route.
type Rollback struct {
	Variant string    `json:"variant"`
	Trigger string    `json:"trigger"`
	Reason  string    `json:"reason"`
	Auto    bool      `json:"auto"`
	At      time.Time `json:"at"`
}

// SetWeights replaces the weights, taking them out of any rollout's
// hands until Resume.
func (r *Route) SetWeights(w Weights) error {
	if len(w) != len(r.names) {
		return ErrInvalidWeights
	}
	sum := 0
	for _, x := range w {
		if x < 0 || x > 100 {
			return ErrInvalidWeights
		}
		sum += x
	}
	if sum != 100 {
		return ErrInvalidWeights
	}
	r.mu.Lock()
	r.takeOverLocked(w.Clone())
	r.mu.Unlock()
	r.emit(Event{Kind: EventSet}, w)
	return nil
}

// Promote sends all of the route's traffic to variant i.
func (r *Route) Promote(i int) error {
	if i < 0 || i >= len(r.names) {
		return fmt.Errorf("split: no variant %d", i)
	}
	w := Weights(make([]int, len(r.names))).Only(i)
	r.mu.Lock()
	r.takeOverLocked(w)
	r.mu.Unlock()
	r.emit(Event{Kind: EventPromote, Variant: r.names[i]}, w)
	return nil
}

// Rollback takes all of variant i's traffic away and gives it to the
// baseline, as an operator's decision. It reports false (and changes
// nothing) when i had no traffic to take.
func (r *Route) Rollback(i int, reason string) (bool, error) {
	if i < 0 || i >= len(r.names) {
		return false, fmt.Errorf("split: no variant %d", i)
	}
	if i == r.baseline {
		return false, ErrBaseline
	}
	return r.rollback(i, TriggerManual, reason, false), nil
}

// rollback moves variant i's share to the baseline, recording why.
func (r *Route) rollback(i int, trigger, reason string, auto bool) bool {
	r.mu.Lock()
	r.advanceLocked()
	cur := r.currentLocked()
	if cur[i] == 0 {
		r.mu.Unlock()
		return false
	}
	w := cur.Without(i, r.baseline)
	r.takeOverLocked(w)
	r.last = &Rollback{Variant: r.names[i], Trigger: trigger, Reason: reason, Auto: auto, At: r.now().UTC()}
	r.mu.Unlock()
	r.emit(Event{Kind: EventRollback, Variant: r.names[i], Trigger: trigger, Reason: reason, Auto: auto}, w)
	return true
}

// takeOverLocked makes w the weights and stops a rollout from changing
// them.
func (r *Route) takeOverLocked(w Weights) {
	r.base = w
	r.manual = true
	if r.ro != nil && r.ro.state != RolloutStopped {
		r.ro.state = RolloutStopped
		r.ro.pausedAt = time.Time{}
	}
}

// Resume returns the route to its configured behaviour: a paused rollout
// carries on; a rollout an operator or a rollback stopped starts again
// from its first step; without a rollout, the configured weights come
// back.
func (r *Route) Resume() error {
	r.mu.Lock()
	var variant string
	switch {
	case r.ro != nil && r.ro.state == RolloutPaused:
		r.ro.unpause(r.now())
		variant = r.rolloutVariantLocked()
	case r.manual:
		r.base = r.configured.Clone()
		r.manual = false
		if r.ro != nil {
			r.ro = newRollout(r.ro.variant, r.ro.steps, r.ro.interval, r.now())
			variant = r.rolloutVariantLocked()
		}
	default:
		r.mu.Unlock()
		return ErrNothingToResume
	}
	w := r.currentLocked()
	r.mu.Unlock()
	r.emit(Event{Kind: EventResume, Variant: variant}, w)
	return nil
}

// Status is a route's traffic split as the admin API shows it.
type Status struct {
	Route    string          `json:"route"`
	Baseline string          `json:"baseline"`
	Variants []VariantStatus `json:"variants"`
	// Manual is set while an operator (or a rollback) controls the
	// weights instead of the config; Resume undoes it.
	Manual       bool           `json:"manual"`
	Rollout      *RolloutStatus `json:"rollout,omitempty"`
	LastRollback *Rollback      `json:"last_rollback,omitempty"`
}

// VariantStatus is one variant's share.
type VariantStatus struct {
	Name             string `json:"name"`
	Weight           int    `json:"weight"`
	ConfiguredWeight int    `json:"configured_weight"`
}

// Status returns the route's current traffic split.
func (r *Route) Status() Status {
	r.mu.Lock()
	r.advanceLocked()
	w := r.currentLocked()
	st := Status{Route: r.label, Baseline: r.names[r.baseline], Manual: r.manual}
	for i, n := range r.names {
		st.Variants = append(st.Variants, VariantStatus{Name: n, Weight: w[i], ConfiguredWeight: r.configured[i]})
	}
	if r.ro != nil {
		st.Rollout = r.ro.status(r.names[r.ro.variant])
	}
	if r.last != nil {
		lr := *r.last
		st.LastRollback = &lr
	}
	r.mu.Unlock()
	return st
}
