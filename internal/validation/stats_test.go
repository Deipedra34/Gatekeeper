package validation

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStats_CountsByResultAndReason(t *testing.T) {
	var s Stats
	s.Record(Result{Outcome: Passed}, ResultPassed)
	s.Record(Result{Outcome: Unmatched}, ResultUnmatched)
	s.Record(Result{Outcome: Invalid, Reason: ReasonBody}, ResultRejected)
	s.Record(Result{Outcome: Invalid, Reason: ReasonBody}, ResultRejected)
	s.Record(Result{Outcome: Invalid, Reason: ReasonParameter}, ResultRejected)
	s.Record(Result{Outcome: Invalid, Reason: ReasonTimeout}, ResultReportOnly)

	assert.Equal(t, StatsSnapshot{
		Validated: 6, Passed: 1, Rejected: 3, ReportOnly: 1, Unmatched: 1,
		RejectedByReason:   map[string]uint64{ReasonBody: 2, ReasonParameter: 1},
		ReportOnlyByReason: map[string]uint64{ReasonTimeout: 1},
	}, s.Snapshot())
}

func TestStatsRegistry_OneStatsPerRoute(t *testing.T) {
	reg := NewStatsRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.For("/api").Record(Result{Outcome: Passed}, ResultPassed)
		}()
	}
	wg.Wait()
	assert.Same(t, reg.For("/api"), reg.For("/api"))
	assert.NotSame(t, reg.For("/api"), reg.For("/other"))
	assert.EqualValues(t, 16, reg.For("/api").Snapshot().Passed)
}

func TestReasons_MatchTheReasonNames(t *testing.T) {
	assert.Equal(t, reasonNames[:], Reasons())
	assert.Len(t, reasonMessages, len(reasonNames), "every reason has an error message")
	for _, r := range Reasons() {
		assert.Contains(t, reasonMessages, r)
	}
}
