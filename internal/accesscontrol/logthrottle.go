package accesscontrol

import (
	"log"
	"sync"
	"time"
)

// LogThrottle rate limits log lines, so a flood of blocked requests
// can't flood the log (and fill the disk) with them. It's a token
// bucket: Burst lines may be written at once, then one per Interval.
// Lines over the limit are dropped and counted, and the next line that
// gets through says how many were dropped since the last one.
type LogThrottle struct {
	logger   *log.Logger
	interval time.Duration
	burst    float64

	mu         sync.Mutex
	tokens     float64
	last       time.Time
	suppressed int
	now        func() time.Time
}

// NewLogThrottle returns a LogThrottle writing to logger.
func NewLogThrottle(logger *log.Logger, interval time.Duration, burst int) *LogThrottle {
	if logger == nil {
		logger = log.Default()
	}
	return &LogThrottle{logger: logger, interval: interval, burst: float64(burst), tokens: float64(burst), now: time.Now}
}

// Printf logs like log.Printf, unless the limit has been reached.
func (t *LogThrottle) Printf(format string, args ...any) {
	if t == nil {
		return
	}
	t.mu.Lock()
	now := t.now()
	if !t.last.IsZero() && t.interval > 0 {
		t.tokens = min(t.burst, t.tokens+float64(now.Sub(t.last))/float64(t.interval))
	}
	t.last = now
	if t.tokens < 1 {
		t.suppressed++
		t.mu.Unlock()
		return
	}
	t.tokens--
	dropped := t.suppressed
	t.suppressed = 0
	t.mu.Unlock()

	if dropped > 0 {
		t.logger.Printf(format+" (%d similar lines suppressed)", append(args, dropped)...)
		return
	}
	t.logger.Printf(format, args...)
}
