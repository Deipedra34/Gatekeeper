package lb

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/circuitbreaker"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
)

var quiet = log.New(io.Discard, "", 0)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

// backends makes n backends named b0..bn-1 with the given weights
// (missing weights are 1).
func backends(t *testing.T, n int, weights ...int) []*Backend {
	t.Helper()
	out := make([]*Backend, n)
	for i := range out {
		w := 1
		if i < len(weights) {
			w = weights[i]
		}
		out[i] = NewBackend("/r", mustURL(t, fmt.Sprintf("http://b%d:80", i)), Settings{Weight: w, Transport: http.DefaultTransport})
	}
	return out
}

func newPool(strategy string, bs []*Backend) *Pool {
	return NewPool(PoolConfig{Route: "/r", Strategy: strategy}, bs, nil, quiet)
}

func req(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":5555"
	return r
}

func countPicks(t *testing.T, p *Pool, n int, r func(i int) *http.Request) map[*Backend]int {
	t.Helper()
	counts := map[*Backend]int{}
	for i := 0; i < n; i++ {
		b, err := p.Pick(r(i), nil, nil)
		require.NoError(t, err)
		counts[b]++
	}
	return counts
}

func sameReq(i int) *http.Request { return req("10.0.0.1") }

func TestRoundRobinCyclesEvenly(t *testing.T) {
	bs := backends(t, 3, 9, 1, 1) // weights are ignored by round_robin
	p := newPool(config.LBRoundRobin, bs)
	var order []*Backend
	for i := 0; i < 6; i++ {
		b, err := p.Pick(req("10.0.0.1"), nil, nil)
		require.NoError(t, err)
		order = append(order, b)
	}
	assert.Equal(t, []*Backend{bs[0], bs[1], bs[2], bs[0], bs[1], bs[2]}, order)
}

func TestWeightedRoundRobinRespectsWeightsSmoothly(t *testing.T) {
	bs := backends(t, 3, 5, 3, 1)
	p := newPool(config.LBWeightedRoundRobin, bs)
	counts := countPicks(t, p, 90, sameReq)
	assert.Equal(t, 50, counts[bs[0]])
	assert.Equal(t, 30, counts[bs[1]])
	assert.Equal(t, 10, counts[bs[2]])

	// Smooth: within any window of sum(weights)=9 picks, each backend
	// appears exactly weight times, and the heavy one is never picked
	// more than twice in a row.
	var seq []*Backend
	for i := 0; i < 18; i++ {
		b, _ := p.Pick(req("10.0.0.1"), nil, nil)
		seq = append(seq, b)
	}
	run := 0
	for i := range seq {
		if i > 0 && seq[i] == seq[i-1] {
			run++
		} else {
			run = 0
		}
		assert.Less(t, run, 2, "smooth WRR interleaves rather than bursting")
	}
}

func TestRandomIsWeighted(t *testing.T) {
	bs := backends(t, 2, 3, 1)
	p := newPool(config.LBRandom, bs)
	counts := countPicks(t, p, 8000, sameReq)
	assert.InDelta(t, 6000, counts[bs[0]], 300)
	assert.InDelta(t, 2000, counts[bs[1]], 300)
}

func TestLeastConnectionsPrefersIdleBackends(t *testing.T) {
	bs := backends(t, 3)
	p := newPool(config.LBLeastConnections, bs)
	// b0 is busy with 2, b1 with 1, b2 idle.
	r1, r2, r3 := bs[0].Acquire(), bs[0].Acquire(), bs[1].Acquire()
	b, err := p.Pick(req("10.0.0.1"), nil, nil)
	require.NoError(t, err)
	assert.Same(t, bs[2], b)

	r4 := bs[2].Acquire()
	r5 := bs[2].Acquire()
	b, _ = p.Pick(req("10.0.0.1"), nil, nil)
	assert.Same(t, bs[1], b, "b1 has 1 in flight, b0 and b2 have 2")
	for _, r := range []func(){r1, r2, r3, r4, r5} {
		r()
	}

	// Equal load: picks rotate rather than always taking the first.
	counts := countPicks(t, p, 300, sameReq)
	for _, b := range bs {
		assert.Equal(t, 100, counts[b])
	}

	// Weight-aware: with weights 2:1 and equal load, the heavy backend
	// is allowed twice the connections.
	ws := backends(t, 2, 2, 1)
	wp := newPool(config.LBLeastConnections, ws)
	var held []func()
	for i := 0; i < 30; i++ {
		b, _ := wp.Pick(req("10.0.0.1"), nil, nil)
		held = append(held, b.Acquire())
	}
	assert.Equal(t, int64(20), ws[0].InFlight())
	assert.Equal(t, int64(10), ws[1].InFlight())
	for _, r := range held {
		r()
	}
}

func TestIPHashIsStickyAndMovesOnlyAffectedKeys(t *testing.T) {
	bs := backends(t, 4)
	p := newPool(config.LBIPHash, bs)

	assign := map[string]*Backend{}
	spread := map[*Backend]int{}
	for i := 0; i < 400; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i%256) + fmt.Sprintf("-%d", i/256)
		r := req("10.1.0.1")
		r.Header.Set("X-Forwarded-For", ip+", 10.9.9.9")
		b, err := p.Pick(r, nil, nil)
		require.NoError(t, err)
		assign[ip] = b
		spread[b]++
		for j := 0; j < 3; j++ {
			again, _ := p.Pick(r, nil, nil)
			require.Same(t, b, again, "the same client always lands on the same backend")
		}
	}
	for _, b := range bs {
		assert.Greater(t, spread[b], 40, "clients spread across all backends: %v", spread)
	}

	// Take b1 out of rotation: only clients that were on b1 move.
	bs[1].activeHealthy.Store(false)
	moved := 0
	for ip, before := range assign {
		r := req("10.1.0.1")
		r.Header.Set("X-Forwarded-For", ip)
		after, _ := p.Pick(r, nil, nil)
		if before == bs[1] {
			assert.NotSame(t, bs[1], after)
			moved++
			continue
		}
		assert.Same(t, before, after, "a client not on the removed backend stays put")
	}
	assert.Equal(t, spread[bs[1]], moved)

	// And when b1 comes back, its clients return to it.
	bs[1].activeHealthy.Store(true)
	for ip, before := range assign {
		r := req("10.1.0.1")
		r.Header.Set("X-Forwarded-For", ip)
		after, _ := p.Pick(r, nil, nil)
		assert.Same(t, before, after)
	}
}

func TestConsistentHashOnHeaderFallsBackToIP(t *testing.T) {
	bs := backends(t, 3)
	p := NewPool(PoolConfig{Route: "/r", Strategy: config.LBConsistentHash, HashHeader: "X-User-ID"}, bs, nil, quiet)

	users := map[string]*Backend{}
	for i := 0; i < 50; i++ {
		user := fmt.Sprintf("user-%d", i)
		for j := 0; j < 5; j++ {
			r := req(fmt.Sprintf("10.0.0.%d", j)) // different IPs, same user
			r.Header.Set("X-User-ID", user)
			b, err := p.Pick(r, nil, nil)
			require.NoError(t, err)
			if prev, ok := users[user]; ok {
				require.Same(t, prev, b, "sticky on the header, not the IP")
			}
			users[user] = b
		}
	}

	// Without the header, the client IP is the key.
	first, _ := p.Pick(req("203.0.113.7"), nil, nil)
	for i := 0; i < 10; i++ {
		b, _ := p.Pick(req("203.0.113.7"), nil, nil)
		assert.Same(t, first, b)
	}
}

func TestPickAvoidExcludeAndErrors(t *testing.T) {
	bs := backends(t, 2)
	p := newPool(config.LBRoundRobin, bs)

	avoid0 := func(b *Backend) bool { return b == bs[0] }
	for i := 0; i < 5; i++ {
		b, err := p.Pick(req("10.0.0.1"), avoid0, nil)
		require.NoError(t, err)
		assert.Same(t, bs[1], b, "a retry prefers the backend it hasn't tried")
	}
	all := func(*Backend) bool { return true }
	b, err := p.Pick(req("10.0.0.1"), all, nil)
	require.NoError(t, err, "but falls back to tried ones rather than giving up")
	assert.NotNil(t, b)

	// Every backend unhealthy or draining: ErrNoHealthyBackend.
	bs[0].activeHealthy.Store(false)
	bs[1].draining.Store(true)
	_, err = p.Pick(req("10.0.0.1"), nil, nil)
	assert.ErrorIs(t, err, ErrNoHealthyBackend)
	bs[0].activeHealthy.Store(true)
	bs[1].draining.Store(false)

	// Healthy but every breaker open (or refusing): ErrAllCircuitsOpen.
	cbCfg := circuitbreaker.Config{FailureThreshold: 1, OpenDuration: time.Hour, HalfOpenMaxRequests: 1, SuccessesToClose: 1, FailuresToReopen: 1}
	for _, b := range bs {
		s := *b.Settings()
		s.Breaker = circuitbreaker.New(cbCfg, nil, "/r")
		b.settings.Store(&s)
	}
	bs[0].Breaker().Report(false)
	b, err = p.Pick(req("10.0.0.1"), nil, nil)
	require.NoError(t, err)
	assert.Same(t, bs[1], b, "a backend with an open breaker is skipped")
	_, err = p.Pick(req("10.0.0.1"), nil, func(b *Backend) bool { return b == bs[1] })
	assert.ErrorIs(t, err, ErrAllCircuitsOpen)
}

func TestPassiveEjectionAndRecovery(t *testing.T) {
	m := metrics.New()
	bs := backends(t, 2)
	p := NewPool(PoolConfig{
		Route: "/r", PassiveEnabled: true,
		Passive: config.PassiveHealthConfig{ConsecutiveFailures: 3, EjectionDuration: config.Duration{Duration: 100 * time.Millisecond}},
	}, bs, m, quiet)

	p.Report(bs[0], false)
	p.Report(bs[0], false)
	p.Report(bs[0], true) // a success resets the streak
	p.Report(bs[0], false)
	p.Report(bs[0], false)
	assert.True(t, bs[0].Healthy(), "only consecutive failures count")
	p.Report(bs[0], false)
	assert.False(t, bs[0].Healthy(), "ejected after 3 in a row")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.BackendEjections.WithLabelValues("/r", "http://b0:80")))

	for i := 0; i < 10; i++ {
		b, err := p.Pick(req("10.0.0.1"), nil, nil)
		require.NoError(t, err)
		assert.Same(t, bs[1], b)
	}
	require.Eventually(t, bs[0].Healthy, time.Second, 10*time.Millisecond, "returns once the ejection period is over")
	assert.Equal(t, 5.0, testutil.ToFloat64(m.BackendRequests.WithLabelValues("/r", "http://b0:80", "failure")))

	// Disabled: failures never eject.
	off := NewPool(PoolConfig{Route: "/r", Passive: config.PassiveHealthConfig{ConsecutiveFailures: 1}}, backends(t, 1), nil, quiet)
	for i := 0; i < 10; i++ {
		off.Report(off.Backends()[0], false)
	}
	assert.True(t, off.Backends()[0].Healthy())
}

// toggleServer is a backend whose health endpoint can be failed.
type toggleServer struct {
	srv     *httptest.Server
	failing atomic.Bool
	probes  atomic.Int32
}

func newToggleServer(t *testing.T) *toggleServer {
	ts := &toggleServer{}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/healthz") { // probes go to <target path>/healthz
			ts.probes.Add(1)
			if ts.failing.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func TestActiveHealthChecksRemoveAndReAdd(t *testing.T) {
	m := metrics.New()
	a, b := newToggleServer(t), newToggleServer(t)
	bs := []*Backend{
		NewBackend("/r", mustURL(t, a.srv.URL), Settings{Weight: 1, Transport: http.DefaultTransport}),
		NewBackend("/r", mustURL(t, b.srv.URL+"/base"), Settings{Weight: 1, Transport: http.DefaultTransport}),
	}
	p := NewPool(PoolConfig{Route: "/r", HealthCheck: config.HealthCheckConfig{
		Enabled: true, Path: "/healthz",
		Interval: config.Duration{Duration: 20 * time.Millisecond}, Timeout: config.Duration{Duration: 10 * time.Millisecond},
		HealthyThreshold: 2, UnhealthyThreshold: 2,
	}}, bs, m, quiet)
	p.Start()
	t.Cleanup(p.Stop)

	require.Eventually(t, func() bool { return a.probes.Load() >= 2 && b.probes.Load() >= 2 }, 2*time.Second, 5*time.Millisecond)
	assert.True(t, bs[0].Healthy())
	assert.True(t, bs[1].Healthy())

	b.failing.Store(true)
	require.Eventually(t, func() bool { return !bs[1].Healthy() }, 2*time.Second, 5*time.Millisecond, "failing probes take it out")
	for i := 0; i < 10; i++ {
		got, err := p.Pick(req("10.0.0.1"), nil, nil)
		require.NoError(t, err)
		assert.Same(t, bs[0], got)
	}

	a.failing.Store(true)
	require.Eventually(t, func() bool { return !bs[0].Healthy() }, 2*time.Second, 5*time.Millisecond)
	_, err := p.Pick(req("10.0.0.1"), nil, nil)
	assert.ErrorIs(t, err, ErrNoHealthyBackend, "all unhealthy fails fast")

	b.failing.Store(false)
	require.Eventually(t, func() bool { return bs[1].Healthy() }, 2*time.Second, 5*time.Millisecond, "recovery puts it back")
	got, err := p.Pick(req("10.0.0.1"), nil, nil)
	require.NoError(t, err)
	assert.Same(t, bs[1], got)

	assert.Greater(t, testutil.ToFloat64(m.HealthChecks.WithLabelValues("/r", bs[1].Label(), "failure")), 1.0)
	assert.Greater(t, testutil.ToFloat64(m.HealthChecks.WithLabelValues("/r", bs[1].Label(), "success")), 1.0)

	// Expected status codes are configurable.
	assert.True(t, statusExpected(204, nil))
	assert.False(t, statusExpected(404, nil))
	assert.True(t, statusExpected(418, []int{418}))
	assert.False(t, statusExpected(200, []int{204}))
}

func TestSetReusesDrainsAndDiscards(t *testing.T) {
	reg := NewRegistry()
	build := func(prev *Settings) (Settings, error) {
		return Settings{Weight: 1, Transport: http.DefaultTransport, DrainTimeout: 200 * time.Millisecond}, nil
	}
	s1 := NewSet(reg, nil, quiet)
	a, _ := s1.Backend("/r", mustURL(t, "http://a"), build)
	b, _ := s1.Backend("/r", mustURL(t, "http://b"), build)
	s1.Activate()
	require.Len(t, reg.Snapshot(), 2)

	// Reload: keep a, drop b, add c.
	s2 := NewSet(reg, s1, quiet)
	var sawPrev *Settings
	a2, _ := s2.Backend("/r", mustURL(t, "http://a"), func(prev *Settings) (Settings, error) {
		sawPrev = prev
		return Settings{Weight: 7, Transport: http.DefaultTransport}, nil
	})
	c, _ := s2.Backend("/r", mustURL(t, "http://c"), build)
	assert.Same(t, a, a2, "an unchanged backend is reused")
	assert.NotNil(t, sawPrev)
	assert.Equal(t, 1, a.Settings().Weight, "new settings wait for Activate")

	held := b.Acquire()
	s2.Activate()
	s1.Retire(s2)
	assert.Equal(t, 7, a.Settings().Weight)
	require.Eventually(t, b.Draining, time.Second, 5*time.Millisecond)
	assert.False(t, b.Available(), "a draining backend gets no new traffic")
	assert.NoError(t, b.Context().Err(), "but what it's doing is left alone")
	time.Sleep(50 * time.Millisecond)
	held() // the in-flight request finishes
	require.Eventually(t, func() bool { return len(reg.Snapshot()) == 2 }, time.Second, 5*time.Millisecond, "b is forgotten once drained")
	_ = c

	// A reload that fails: staged settings are dropped, new backends forgotten.
	s3 := NewSet(reg, s2, quiet)
	_, _ = s3.Backend("/r", mustURL(t, "http://a"), func(*Settings) (Settings, error) {
		return Settings{Weight: 99, Transport: http.DefaultTransport}, nil
	})
	_, _ = s3.Backend("/r", mustURL(t, "http://d"), build)
	s3.Discard()
	assert.Equal(t, 7, a.Settings().Weight)
	assert.Len(t, reg.Snapshot(), 2)
}

func TestDrainTimeoutCancelsStragglers(t *testing.T) {
	b := NewBackend("/r", mustURL(t, "http://slow"), Settings{Transport: http.DefaultTransport})
	release := b.Acquire()
	defer release()
	start := time.Now()
	forced := b.Drain(100 * time.Millisecond)
	assert.True(t, forced)
	assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
	assert.Error(t, b.Context().Err(), "work still running is cancelled at the deadline")
}

func TestRegistryMergesDuplicateLabels(t *testing.T) {
	reg := NewRegistry()
	old := NewBackend("/r", mustURL(t, "http://a"), Settings{})
	cur := NewBackend("/r", mustURL(t, "http://a"), Settings{})
	reg.add(old)
	reg.add(cur)
	r1 := old.Acquire()
	r2 := cur.Acquire()
	defer r1()
	defer r2()
	old.draining.Store(true)
	snap := reg.Snapshot()
	require.Len(t, snap, 1, "never two series with the same labels")
	assert.Equal(t, int64(2), snap[0].InFlight)
	assert.False(t, snap[0].Draining)
	assert.True(t, snap[0].InRotation)
}

func TestConcurrentPicksAndCountersAreSafe(t *testing.T) {
	for _, strategy := range []string{config.LBRoundRobin, config.LBLeastConnections, config.LBWeightedRoundRobin, config.LBRandom, config.LBIPHash, config.LBConsistentHash} {
		t.Run(strategy, func(t *testing.T) {
			bs := backends(t, 4, 1, 2, 3, 4)
			p := NewPool(PoolConfig{Route: "/r", Strategy: strategy, PassiveEnabled: true,
				Passive: config.PassiveHealthConfig{ConsecutiveFailures: 1000, EjectionDuration: config.Duration{Duration: time.Second}}}, bs, nil, quiet)
			var wg sync.WaitGroup
			var total atomic.Int64
			for g := 0; g < 32; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					for i := 0; i < 500; i++ {
						b, err := p.Pick(req(fmt.Sprintf("10.0.%d.%d", g, i%7)), nil, nil)
						if err != nil {
							t.Error(err)
							return
						}
						release := b.Acquire()
						p.Report(b, i%3 != 0)
						total.Add(1)
						release()
					}
				}(g)
			}
			wg.Wait()
			assert.Equal(t, int64(32*500), total.Load())
			for _, b := range bs {
				assert.Zero(t, b.InFlight(), "every Acquire was released")
			}
		})
	}
}
