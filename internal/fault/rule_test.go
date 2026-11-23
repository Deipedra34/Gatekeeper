package fault

import (
	"math"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

func dur(d time.Duration) config.Duration { return config.Duration{Duration: d} }

// fixedSampler returns the same sample every time: 0 hits every
// percentage above 0, 0.999 misses everything below 100.
func fixedSampler(v float64) Sampler { return func() float64 { return v } }

// sequenceSampler returns vs in turn, cycling.
func sequenceSampler(vs ...float64) Sampler {
	i := 0
	return func() float64 {
		v := vs[i%len(vs)]
		i++
		return v
	}
}

func request(method, target string) Request {
	return Request{HTTP: httptest.NewRequest(method, target, nil)}
}

func TestDecide_Percentages(t *testing.T) {
	cfg := config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 10, Fixed: dur(500 * time.Millisecond)},
		Abort: &config.FaultAbort{Percentage: 50, Status: 503},
	}
	r := NewRule("r", "/api", SourceConfig, cfg, time.Now())

	d, ok := r.decide(fixedSampler(0))
	require.True(t, ok)
	assert.Equal(t, 500*time.Millisecond, d.Delay)
	assert.Equal(t, 503, d.AbortStatus)
	assert.Equal(t, []string{TypeDelay, TypeAbort}, d.Types())
	assert.Equal(t, "delay,abort", d.Label())

	// 0.2 is above the delay's 10% but below the abort's 50%.
	d, ok = r.decide(fixedSampler(0.2))
	require.True(t, ok)
	assert.Zero(t, d.Delay)
	assert.Equal(t, 503, d.AbortStatus)
	assert.Equal(t, "abort", d.Label())

	_, ok = r.decide(fixedSampler(0.999))
	assert.False(t, ok, "missed every roll")
}

func TestDecide_ZeroAndFullPercentages(t *testing.T) {
	zero := NewRule("z", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 0, Status: 500},
	}, time.Now())
	full := NewRule("f", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
	}, time.Now())
	for _, v := range []float64{0, 0.5, 0.999999} {
		_, ok := zero.decide(fixedSampler(v))
		assert.False(t, ok, "0%% never fires (sample %v)", v)
		_, ok = full.decide(fixedSampler(v))
		assert.True(t, ok, "100%% always fires (sample %v)", v)
	}
}

func TestDecide_ResetBeatsAbort(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort:           &config.FaultAbort{Percentage: 100, Status: 500},
		ConnectionReset: &config.FaultReset{Percentage: 100},
	}, time.Now())
	d, ok := r.decide(fixedSampler(0))
	require.True(t, ok)
	assert.True(t, d.Reset)
	assert.Zero(t, d.AbortStatus, "a reset leaves nothing to abort")
	assert.Equal(t, "reset", d.Label())
}

func TestDecide_DelayWithinRange(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 100, Min: dur(100 * time.Millisecond), Max: dur(300 * time.Millisecond)},
	}, time.Now())
	lo, hi := time.Hour, time.Duration(0)
	for i := 0; i < 10_000; i++ {
		d, ok := r.decide(DefaultSampler)
		require.True(t, ok)
		require.GreaterOrEqual(t, d.Delay, 100*time.Millisecond)
		require.LessOrEqual(t, d.Delay, 300*time.Millisecond)
		lo, hi = min(lo, d.Delay), max(hi, d.Delay)
	}
	assert.Less(t, lo, 120*time.Millisecond, "the range is used down to its bottom")
	assert.Greater(t, hi, 280*time.Millisecond, "and up to its top")

	// The ends of the sampler's range land on min and (just under) max.
	d, _ := r.decide(sequenceSampler(0, 0))
	assert.Equal(t, 100*time.Millisecond, d.Delay)
}

func TestDecide_DistributionMatchesPercentages(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Delay:           &config.FaultDelay{Percentage: 10, Fixed: dur(time.Millisecond)},
		Abort:           &config.FaultAbort{Percentage: 5, Status: 503},
		ConnectionReset: &config.FaultReset{Percentage: 2},
	}, time.Now())
	const n = 100_000
	var delays, aborts, resets int
	for i := 0; i < n; i++ {
		d, _ := r.decide(DefaultSampler)
		if d.Delay > 0 {
			delays++
		}
		if d.AbortStatus != 0 {
			aborts++
		}
		if d.Reset {
			resets++
		}
	}
	// Expected shares: delay 10%; reset 2%; abort 5% of the 98% not reset.
	within := func(name string, got int, want float64) {
		t.Helper()
		share := float64(got) / n * 100
		// 5 standard deviations of a binomial share at this n: never
		// flaky, and still tight enough to catch a wrong formula.
		tolerance := 5 * math.Sqrt(want*(100-want)/n)
		assert.InDelta(t, want, share, tolerance, "%s share", name)
	}
	within("delay", delays, 10)
	within("reset", resets, 2)
	within("abort", aborts, 5*0.98)
}

func TestMatch_Conditions(t *testing.T) {
	cfg := config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
		Match: config.FaultMatch{
			Header:       &config.ValueMatch{Name: "x-gatekeeper-fault", Value: "true"},
			PathPrefixes: []string{"/api/orders"},
			Methods:      []string{"POST"},
		},
	}
	r := NewRule("r", "/api", SourceConfig, cfg, time.Now())

	req := request("POST", "/api/orders/7")
	assert.False(t, r.Matches(req), "no header")
	req.HTTP.Header.Set("X-Gatekeeper-Fault", "false")
	assert.False(t, r.Matches(req), "wrong header value")
	req.HTTP.Header.Set("X-Gatekeeper-Fault", "true")
	assert.True(t, r.Matches(req), "header, path, and method all match")

	other := request("GET", "/api/orders/7")
	other.HTTP.Header.Set("X-Gatekeeper-Fault", "true")
	assert.False(t, r.Matches(other), "wrong method")

	other = request("POST", "/api/users")
	other.HTTP.Header.Set("X-Gatekeeper-Fault", "true")
	assert.False(t, r.Matches(other), "wrong path")
}

func TestMatch_HeaderPresenceOnly(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
		Match: config.FaultMatch{Header: &config.ValueMatch{Name: "X-Chaos"}},
	}, time.Now())
	req := request("GET", "/")
	assert.False(t, r.Matches(req))
	req.HTTP.Header.Set("X-Chaos", "anything")
	assert.True(t, r.Matches(req), "any value will do when none is configured")
}

func TestMatch_Variants(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
		Match: config.FaultMatch{Variants: []string{"canary"}},
	}, time.Now())
	req := request("GET", "/")
	req.Variant = "stable"
	assert.False(t, r.Matches(req))
	req.Variant = "canary"
	assert.True(t, r.Matches(req))
}

func TestMatch_ClientAllowlist(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
		Match: config.FaultMatch{Clients: &config.FaultClients{
			Tiers:   []string{"internal"},
			APIKeys: []string{"chaos-key"},
			CIDRs:   []string{"10.0.0.0/8"},
		}},
	}, time.Now())
	matches := func(c Client) bool {
		req := request("GET", "/")
		req.Client = func() Client { return c }
		return r.Matches(req)
	}
	assert.True(t, matches(Client{Tier: "internal"}))
	assert.True(t, matches(Client{APIKey: "chaos-key"}))
	assert.True(t, matches(Client{IP: netip.MustParseAddr("10.1.2.3")}))
	assert.True(t, matches(Client{IP: netip.MustParseAddr("::ffff:10.1.2.3")}), "IPv4-mapped addresses count")
	assert.False(t, matches(Client{Tier: "default", APIKey: "other", IP: netip.MustParseAddr("192.168.1.1")}))
	assert.False(t, matches(Client{}), "an unknown client isn't on the list")

	req := request("GET", "/")
	assert.False(t, r.Matches(req), "no client information means no match")
}

func TestMatch_ClientsResolvedOnlyWhenNeeded(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
	}, time.Now())
	req := request("GET", "/")
	req.Client = func() Client { t.Fatal("a rule without an allowlist never looks the client up"); return Client{} }
	assert.True(t, r.Matches(req))
}

func TestDecision_Backends(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
		Match: config.FaultMatch{Backends: []string{"http://b:9000"}},
	}, time.Now())
	d, ok := r.decide(fixedSampler(0))
	require.True(t, ok)
	assert.True(t, d.AppliesTo("http://b:9000"))
	assert.False(t, d.AppliesTo("http://a:9000"), "attempts on other backends go through")

	all := NewRule("all", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
	}, time.Now())
	d, _ = all.decide(fixedSampler(0))
	assert.True(t, d.AppliesTo("http://anything:1"), "no backend targeting covers every backend")
}

func TestDecision_BackendLabelsNormalized(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 100, Status: 500},
		Match: config.FaultMatch{Backends: []string{"http://user:secret@b:9000"}},
	}, time.Now())
	d, _ := r.decide(fixedSampler(0))
	assert.True(t, d.AppliesTo("http://b:9000"), "compared the way the load balancer labels backends")
}
