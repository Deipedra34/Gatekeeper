package fault

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func abort503() *config.RouteFaultConfig {
	return &config.RouteFaultConfig{Enabled: true, Abort: &config.FaultAbort{Percentage: 100, Status: 503}}
}

// gatewayConfig is a config with an "/api" route carrying rule and a "/"
// route without one.
func gatewayConfig(enabled bool, rule *config.RouteFaultConfig) *config.Config {
	return &config.Config{
		FaultInjection: config.FaultInjectionConfig{GlobalEnabled: enabled},
		Metrics:        config.MetricsConfig{Path: "/metrics"},
		Routes: []config.Route{
			{PathPrefix: "/api", Target: "http://api:9000", FaultInjection: rule},
			{PathPrefix: "/", Target: "http://web:9000"},
		},
	}
}

func newTestRegistry(c *clock, opts ...Option) *Registry {
	g := NewRegistry(append([]Option{WithSampler(fixedSampler(0)), WithClock(c.Now)}, opts...)...)
	return g
}

func decide(g *Registry, route, target string) (Decision, bool) {
	return g.Decide(route, request("GET", target))
}

func TestRegistry_KillSwitch(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()

	g.Configure(gatewayConfig(false, abort503()))
	_, ok := decide(g, "/api", "/api/x")
	assert.False(t, ok, "nothing is injected with global_enabled off")
	assert.False(t, g.Enabled())
	assert.Empty(t, g.Active())
	assert.Len(t, g.Rules(), 1, "the rule is held, just not in force")

	g.Configure(gatewayConfig(true, abort503()))
	d, ok := decide(g, "/api", "/api/x")
	require.True(t, ok)
	assert.Equal(t, 503, d.AbortStatus)
	assert.Equal(t, ConfigRuleID("/api"), d.Rule)
	assert.Len(t, g.Active(), 1)

	g.Configure(gatewayConfig(false, abort503()))
	_, ok = decide(g, "/api", "/api/x")
	assert.False(t, ok, "turning the kill switch off stops it straight away")
}

func TestRegistry_RuleMustBeEnabled(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	rule := abort503()
	rule.Enabled = false
	g.Configure(gatewayConfig(true, rule))
	_, ok := decide(g, "/api", "/api/x")
	assert.False(t, ok)
	assert.Empty(t, g.Rules())
}

func TestRegistry_OnlyTheRulesRoute(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	g.Configure(gatewayConfig(true, abort503()))
	_, ok := decide(g, "/", "/index.html")
	assert.False(t, ok, "a route without a rule is untouched")
}

func TestRegistry_ExemptPaths(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	cfg := gatewayConfig(true, abort503())
	cfg.Routes[0].PathPrefix = "/"
	cfg.Routes = cfg.Routes[:1]
	cfg.FaultInjection.ExemptPaths = []string{"/status", "/internal/"}
	g.Configure(cfg)

	for _, path := range []string{
		"/metrics", "/healthz", "/healthz/ready", "/health", "/livez", "/readyz", "/_dashboard",
		"/status", "/internal/jobs",
	} {
		_, ok := decide(g, "/", path)
		assert.False(t, ok, "%s is never faulted", path)
	}
	for _, path := range []string{"/api", "/healthzz", "/statusx", "/internal"} {
		_, ok := decide(g, "/", path)
		assert.True(t, ok, "%s is an ordinary path", path)
	}
}

func TestRegistry_HealthCheckProbesExempt(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	g.Configure(gatewayConfig(true, abort503()))
	for _, ua := range []string{"kube-probe/1.31", "ELB-HealthChecker/2.0", "GoogleHC/1.0", "gatekeeper-health-check"} {
		req := request("GET", "/api/x")
		req.HTTP.Header.Set("User-Agent", ua)
		_, ok := g.Decide("/api", req)
		assert.False(t, ok, "%s is a health check probe", ua)
	}
}

func TestRegistry_MaxDurationExpiry(t *testing.T) {
	c := newClock()
	var mu sync.Mutex
	var events []Event
	g := newTestRegistry(c, WithEvents(func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}))
	defer g.Close()

	rule := abort503()
	rule.MaxDuration = config.Duration{Duration: 10 * time.Minute}
	g.Configure(gatewayConfig(true, rule))
	r, ok := g.Get(ConfigRuleID("/api"))
	require.True(t, ok)
	assert.Equal(t, c.Now().Add(10*time.Minute), r.Expires)

	c.Advance(9 * time.Minute)
	_, ok = decide(g, "/api", "/api/x")
	assert.True(t, ok, "still in force")

	c.Advance(time.Minute)
	_, ok = decide(g, "/api", "/api/x")
	assert.False(t, ok, "expired, even before the expiry timer has fired")

	g.ExpireDue()
	g.ExpireDue()
	mu.Lock()
	require.Len(t, events, 1, "an expiry is reported once")
	assert.Equal(t, EventExpired, events[0].Kind)
	assert.Equal(t, ConfigRuleID("/api"), events[0].Rule.ID)
	mu.Unlock()
	assert.Empty(t, g.Active())
}

func TestRegistry_ReloadKeepsUnchangedRuleCountdown(t *testing.T) {
	c := newClock()
	g := newTestRegistry(c)
	defer g.Close()
	rule := abort503()
	rule.MaxDuration = config.Duration{Duration: 10 * time.Minute}
	g.Configure(gatewayConfig(true, rule))
	start := c.Now()

	c.Advance(8 * time.Minute)
	g.Configure(gatewayConfig(true, abort503WithMax(10*time.Minute)))
	r, _ := g.Get(ConfigRuleID("/api"))
	assert.Equal(t, start, r.Start, "a reload that leaves the rule alone doesn't restart its countdown")

	c.Advance(3 * time.Minute)
	g.Configure(gatewayConfig(true, abort503WithMax(10*time.Minute)))
	_, ok := decide(g, "/api", "/api/x")
	assert.False(t, ok, "so it still expires on time, reload or not")

	changed := abort503WithMax(10 * time.Minute)
	changed.Abort.Status = 500
	g.Configure(gatewayConfig(true, changed))
	d, ok := decide(g, "/api", "/api/x")
	require.True(t, ok, "changing the rule starts it over")
	assert.Equal(t, 500, d.AbortStatus)
}

func abort503WithMax(d time.Duration) *config.RouteFaultConfig {
	r := abort503()
	r.MaxDuration = config.Duration{Duration: d}
	return r
}

func TestRegistry_RuntimeRules(t *testing.T) {
	c := newClock()
	g := newTestRegistry(c)
	defer g.Close()
	g.Configure(gatewayConfig(true, abort503()))

	delay := config.RouteFaultConfig{Delay: &config.FaultDelay{Percentage: 100, Fixed: dur(time.Second)}}
	r, replaced := g.Put("slow-api", "/api", delay, 5*time.Minute)
	assert.False(t, replaced)
	assert.Equal(t, SourceRuntime, r.Source)
	assert.Equal(t, c.Now().Add(5*time.Minute), r.Expires, "the TTL is its max_duration")

	d, ok := decide(g, "/api", "/api/x")
	require.True(t, ok)
	assert.Equal(t, "slow-api", d.Rule, "runtime rules are tried before the config rule")
	assert.Equal(t, time.Second, d.Delay)
	assert.Zero(t, d.AbortStatus)

	c.Advance(time.Second)
	g.Put("newer", "/api", config.RouteFaultConfig{Abort: &config.FaultAbort{Percentage: 100, Status: 500}}, time.Minute)
	d, _ = decide(g, "/api", "/api/x")
	assert.Equal(t, "newer", d.Rule, "newest first")

	_, replaced = g.Put("newer", "/api", config.RouteFaultConfig{Abort: &config.FaultAbort{Percentage: 100, Status: 502}}, time.Minute)
	assert.True(t, replaced)
	d, _ = decide(g, "/api", "/api/x")
	assert.Equal(t, 502, d.AbortStatus, "put replaces a rule by ID")

	_, ok = g.Delete("newer")
	assert.True(t, ok)
	_, ok = g.Delete("newer")
	assert.False(t, ok)

	c.Advance(5 * time.Minute)
	g.ExpireDue()
	_, ok = g.Get("slow-api")
	assert.False(t, ok, "an expired runtime rule is gone")
	d, _ = decide(g, "/api", "/api/x")
	assert.Equal(t, ConfigRuleID("/api"), d.Rule, "the config rule is back in charge")
}

func TestRegistry_RuntimeRuleOnRouteWithoutConfigRule(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	g.Configure(gatewayConfig(true, nil))
	_, ok := decide(g, "/", "/x")
	assert.False(t, ok)
	g.Put("web", "/", config.RouteFaultConfig{Abort: &config.FaultAbort{Percentage: 100, Status: 500}}, time.Minute)
	_, ok = decide(g, "/", "/x")
	assert.True(t, ok)
}

func TestRegistry_RuntimeRulesObeyKillSwitch(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	g.Configure(gatewayConfig(false, nil))
	g.Put("web", "/", config.RouteFaultConfig{Abort: &config.FaultAbort{Percentage: 100, Status: 500}}, time.Minute)
	_, ok := decide(g, "/", "/x")
	assert.False(t, ok, "the kill switch covers runtime rules too")
}

func TestRegistry_ReloadDropsRuntimeRulesOfRemovedRoutes(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	g.Configure(gatewayConfig(true, nil))
	g.Put("api", "/api", config.RouteFaultConfig{Abort: &config.FaultAbort{Percentage: 100, Status: 500}}, time.Minute)
	g.Put("web", "/", config.RouteFaultConfig{Abort: &config.FaultAbort{Percentage: 100, Status: 500}}, time.Minute)

	cfg := gatewayConfig(true, nil)
	cfg.Routes = cfg.Routes[1:] // "/api" removed
	dropped := g.Configure(cfg)
	require.Len(t, dropped, 1)
	assert.Equal(t, "api", dropped[0].ID)
	_, ok := g.Get("web")
	assert.True(t, ok, "rules on routes that are still there survive a reload")
}

func TestRegistry_DeleteConfigRuleUntilReload(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	g.Configure(gatewayConfig(true, abort503()))
	_, ok := g.Delete(ConfigRuleID("/api"))
	require.True(t, ok)
	_, ok = decide(g, "/api", "/api/x")
	assert.False(t, ok)

	g.Configure(gatewayConfig(true, abort503()))
	_, ok = decide(g, "/api", "/api/x")
	assert.True(t, ok, "the config file brings it back on the next reload")
}

func TestRegistry_NoAllocationsWhenNothingIsInForce(t *testing.T) {
	g := newTestRegistry(newClock())
	defer g.Close()
	req := request("GET", "/api/x")

	g.Configure(gatewayConfig(false, abort503()))
	allocs := testing.AllocsPerRun(1000, func() { g.Decide("/api", req) })
	assert.Zero(t, allocs, "kill switch off")

	g.Configure(gatewayConfig(true, nil))
	allocs = testing.AllocsPerRun(1000, func() { g.Decide("/api", req) })
	assert.Zero(t, allocs, "no rule anywhere")

	g.Configure(gatewayConfig(true, abort503()))
	allocs = testing.AllocsPerRun(1000, func() { g.Decide("/", req) })
	assert.Zero(t, allocs, "a route without a rule, while another route has one")
}

func TestRegistry_ConcurrentUse(t *testing.T) {
	g := NewRegistry()
	defer g.Close()
	g.Configure(gatewayConfig(true, abort503()))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				g.Decide("/api", request("GET", "/api/x"))
			}
		}()
	}
	for j := 0; j < 50; j++ {
		g.Put("r", "/api", *abort503(), time.Minute)
		g.Configure(gatewayConfig(j%2 == 0, abort503()))
		g.Delete("r")
		g.Active()
	}
	wg.Wait()
}
