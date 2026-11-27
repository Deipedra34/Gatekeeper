package validation

import (
	"sync"
	"sync/atomic"
)

// Reasons lists every reason a request can be invalid, in order of
// precedence.
func Reasons() []string { return append([]string(nil), reasonOrder...) }

// Stats counts one route's validation results. It's safe for concurrent
// use.
type Stats struct {
	passed, rejected, reportOnly, unmatched atomic.Uint64

	// byReason counts invalid requests by reason, indexed like
	// reasonNames.
	byReason [len(reasonNames)]struct{ rejected, reportOnly atomic.Uint64 }
}

// reasonNames are the reasons, in order of precedence.
var reasonNames = [...]string{
	ReasonUnknownOperation, ReasonContentType, ReasonBodyTooLarge,
	ReasonParameter, ReasonBody, ReasonTimeout, ReasonInternal,
}

// Record counts a request checked with result res, labelled result (see
// Result.Label).
func (s *Stats) Record(res Result, result string) {
	switch result {
	case ResultPassed:
		s.passed.Add(1)
	case ResultUnmatched:
		s.unmatched.Add(1)
	case ResultRejected:
		s.rejected.Add(1)
		if i := reasonRank(res.Reason); i < len(s.byReason) {
			s.byReason[i].rejected.Add(1)
		}
	case ResultReportOnly:
		s.reportOnly.Add(1)
		if i := reasonRank(res.Reason); i < len(s.byReason) {
			s.byReason[i].reportOnly.Add(1)
		}
	}
}

// StatsSnapshot is a route's counts at one moment.
type StatsSnapshot struct {
	// Validated is every request checked: the sum of the four below.
	Validated  uint64 `json:"validated"`
	Passed     uint64 `json:"passed"`
	Rejected   uint64 `json:"rejected"`
	ReportOnly uint64 `json:"report_only"`
	Unmatched  uint64 `json:"unmatched"`
	// RejectedByReason and ReportOnlyByReason break Rejected and
	// ReportOnly down by reason, listing only reasons seen.
	RejectedByReason   map[string]uint64 `json:"rejected_by_reason"`
	ReportOnlyByReason map[string]uint64 `json:"report_only_by_reason"`
}

// Snapshot returns s's counts.
func (s *Stats) Snapshot() StatsSnapshot {
	out := StatsSnapshot{
		Passed:             s.passed.Load(),
		Rejected:           s.rejected.Load(),
		ReportOnly:         s.reportOnly.Load(),
		Unmatched:          s.unmatched.Load(),
		RejectedByReason:   map[string]uint64{},
		ReportOnlyByReason: map[string]uint64{},
	}
	out.Validated = out.Passed + out.Rejected + out.ReportOnly + out.Unmatched
	for i, name := range reasonNames {
		if n := s.byReason[i].rejected.Load(); n > 0 {
			out.RejectedByReason[name] = n
		}
		if n := s.byReason[i].reportOnly.Load(); n > 0 {
			out.ReportOnlyByReason[name] = n
		}
	}
	return out
}

// StatsRegistry holds every route's Stats. The gateway keeps one for its
// whole life, so counts survive config reloads.
type StatsRegistry struct {
	mu     sync.Mutex
	routes map[string]*Stats
}

// NewStatsRegistry returns an empty registry.
func NewStatsRegistry() *StatsRegistry {
	return &StatsRegistry{routes: map[string]*Stats{}}
}

// For returns route's Stats, creating them on first use.
func (r *StatsRegistry) For(route string) *Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.routes[route]
	if !ok {
		s = &Stats{}
		r.routes[route] = s
	}
	return s
}
