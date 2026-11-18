package split

import (
	"math"
	"sync"
	"time"
)

// Latency histogram layout: bucket k holds latencies in
// (latencyBound(k-1), latencyBound(k)], growing 25% per bucket from 1ms,
// which covers 1ms to ~70s; the last bucket takes anything slower.
const (
	latencyBuckets = 50
	latencyBase    = float64(time.Millisecond)
	latencyGrowth  = 1.25
)

func latencyBound(k int) float64 {
	if k < 0 {
		return 0
	}
	return latencyBase * math.Pow(latencyGrowth, float64(k))
}

func latencyBucket(d time.Duration) int {
	if float64(d) <= latencyBase {
		return 0
	}
	k := int(math.Ceil(math.Log(float64(d)/latencyBase) / math.Log(latencyGrowth)))
	if k >= latencyBuckets {
		return latencyBuckets - 1
	}
	return k
}

// windowSlots is how many slices a rolling window is cut into: old
// requests leave the window a slice at a time.
const windowSlots = 10

// slot is one slice of a window.
type slot struct {
	id     int64 // which slice of time this is: start / slice length
	total  uint64
	errors uint64
	hist   [latencyBuckets]uint64
}

// window counts requests, 5xx responses, and latencies over the last
// length of time, in windowSlots slices.
type window struct {
	mu    sync.Mutex
	slice time.Duration
	slots [windowSlots]slot
}

func newWindow(length time.Duration) *window {
	slice := length / windowSlots
	if slice <= 0 {
		slice = 1
	}
	w := &window{slice: slice}
	for i := range w.slots {
		w.slots[i].id = -1
	}
	return w
}

// record counts one request that finished at now.
func (w *window) record(now time.Time, latency time.Duration, isError bool) {
	id := now.UnixNano() / int64(w.slice)
	w.mu.Lock()
	s := &w.slots[id%windowSlots]
	if s.id != id {
		*s = slot{id: id}
	}
	s.total++
	if isError {
		s.errors++
	}
	s.hist[latencyBucket(latency)]++
	w.mu.Unlock()
}

// reset forgets everything recorded so far.
func (w *window) reset() {
	w.mu.Lock()
	for i := range w.slots {
		w.slots[i] = slot{id: -1}
	}
	w.mu.Unlock()
}

// Sample is a window's totals.
type Sample struct {
	Requests uint64        `json:"requests"`
	Errors   uint64        `json:"errors"`
	P95      time.Duration `json:"-"`
}

// ErrorRate is the share of requests that failed with a 5xx (0 without
// requests).
func (s Sample) ErrorRate() float64 {
	if s.Requests == 0 {
		return 0
	}
	return float64(s.Errors) / float64(s.Requests)
}

// sample sums the slices still inside the window at now.
func (w *window) sample(now time.Time) Sample {
	newest := now.UnixNano() / int64(w.slice)
	var out Sample
	var hist [latencyBuckets]uint64
	w.mu.Lock()
	for i := range w.slots {
		s := &w.slots[i]
		if s.id < 0 || s.id > newest || newest-s.id >= windowSlots {
			continue
		}
		out.Requests += s.total
		out.Errors += s.errors
		for k, c := range s.hist {
			hist[k] += c
		}
	}
	w.mu.Unlock()
	out.P95 = percentile(hist, out.Requests, 0.95)
	return out
}

// percentile estimates the q-quantile of a histogram holding total
// observations, interpolating linearly inside the bucket it falls in.
func percentile(hist [latencyBuckets]uint64, total uint64, q float64) time.Duration {
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum float64
	for k, c := range hist {
		if c == 0 {
			continue
		}
		if cum+float64(c) >= target {
			lo, hi := latencyBound(k-1), latencyBound(k)
			return time.Duration(lo + (hi-lo)*(target-cum)/float64(c))
		}
		cum += float64(c)
	}
	return time.Duration(latencyBound(latencyBuckets - 1))
}
