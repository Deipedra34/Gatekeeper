package accesscontrol

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogThrottle(t *testing.T) {
	var buf bytes.Buffer
	lt := NewLogThrottle(log.New(&buf, "", 0), time.Second, 3)
	now := time.Unix(1_700_000_000, 0)
	lt.now = func() time.Time { return now }

	// A flood of 1000 lines in one instant: only the burst gets through.
	for range 1000 {
		lt.Printf("blocked %s", "203.0.113.7")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 3)

	// A second later one more line is allowed, and it says how many were
	// dropped in between.
	now = now.Add(time.Second)
	buf.Reset()
	lt.Printf("blocked %s", "203.0.113.8")
	assert.Equal(t, "blocked 203.0.113.8 (997 similar lines suppressed)\n", buf.String())

	// The counter starts over after being reported.
	now = now.Add(time.Second)
	buf.Reset()
	lt.Printf("blocked %s", "203.0.113.9")
	assert.Equal(t, "blocked 203.0.113.9\n", buf.String())

	// Tokens refill up to the burst, never beyond.
	now = now.Add(time.Hour)
	buf.Reset()
	for range 10 {
		lt.Printf("x")
	}
	assert.Equal(t, 3, strings.Count(buf.String(), "\n"))
}

func TestLogThrottle_NilIsSilent(t *testing.T) {
	var lt *LogThrottle
	lt.Printf("nothing %d", 1) // must not panic
}
