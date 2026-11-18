package split

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

func TestRegistry_ReloadKeepsLiveState(t *testing.T) {
	clock := newFakeClock()
	reg := NewRegistry(WithClock(clock.Now))
	cfg := twoWay()
	cfg.Rollout = &config.RolloutConfig{Variant: "canary", Steps: []int{5, 25, 50}, Interval: config.Duration{Duration: 10 * time.Minute}}

	r1, err := reg.Build("/api", cfg)
	require.NoError(t, err)
	reg.Commit([]*Route{r1})
	clock.Advance(10 * time.Minute)
	assert.Equal(t, Weights{75, 25}, r1.Weights())
	require.NoError(t, r1.Pause())

	// A reload that changes things the state doesn't depend on: backends,
	// stickiness, overrides, rules, the response header.
	changed := cfg
	changed.Variants = append([]config.VariantConfig(nil), cfg.Variants...)
	changed.Variants[1].Target = "http://canary-v2:1"
	changed.Variants[1].LBStrategy = config.LBRandom
	changed.ResponseHeader = "X-Variant"
	changed.Override = config.OverrideConfig{Enabled: true, Header: "X-V", Allow: config.OverrideAllow{Anyone: true}}
	changed.Rules = []config.SplitRule{{Variant: "canary", Match: config.SplitMatch{PathPrefix: "/api/beta"}}}

	r2, err := reg.Build("/api", changed)
	require.NoError(t, err)
	assert.Equal(t, Weights{75, 25}, r2.Weights(), "the rollout's progress carries over")
	assert.Equal(t, RolloutPaused, r2.Rollout().State)

	// Until the commit, the old route is the one served.
	got, ok := reg.Get("/api")
	require.True(t, ok)
	assert.Same(t, r1, got)
	reg.Commit([]*Route{r2})
	got, _ = reg.Get("/api")
	assert.Same(t, r2, got)

	// Old and new share one state: an in-flight request finishing on the
	// old router sees what the admin API does to the new one.
	require.NoError(t, r2.Resume(false))
	assert.Equal(t, RolloutRunning, r1.Rollout().State)
}

func TestRegistry_ChangedWeightsStartFresh(t *testing.T) {
	reg := NewRegistry()
	r1, _ := reg.Build("/api", twoWay())
	reg.Commit([]*Route{r1})
	require.NoError(t, r1.SetWeights(Weights{50, 50}, false))

	cfg := twoWay()
	cfg.Variants = []config.VariantConfig{{Name: "stable", Weight: 80}, {Name: "canary", Weight: 20}}
	r2, err := reg.Build("/api", cfg)
	require.NoError(t, err)
	assert.Equal(t, Weights{80, 20}, r2.Weights(), "an edited config wins over the old state")
	assert.False(t, r2.Status().Manual)
}

func TestRegistry_ReloadDoesNotReshuffleClients(t *testing.T) {
	reg := NewRegistry()
	r1, _ := reg.Build("/api", twoWay())
	reg.Commit([]*Route{r1})

	// An unrelated change, and a weight change.
	same := twoWay()
	same.ResponseHeader = "X-Variant"
	r2, _ := reg.Build("/api", same)
	grown := twoWay()
	grown.Variants = []config.VariantConfig{{Name: "stable", Weight: 75}, {Name: "canary", Weight: 25}}
	r3, _ := reg.Build("/api", grown)

	moved := 0
	for i := range 5000 {
		c := Client{IP: fmt.Sprintf("10.1.%d.%d", i/256, i%256)}
		before := r1.Select(get("/api"), c)
		assert.Equal(t, before, r2.Select(get("/api"), c), "an unrelated reload moves nobody")
		after := r3.Select(get("/api"), c)
		if before.Name == "canary" {
			assert.Equal(t, "canary", after.Name, "canary clients stay as it grows")
		}
		if before.Name != after.Name {
			moved++
		}
	}
	// Only the clients the extra 15% needs move: ~750 of 5000.
	assert.InDelta(t, 750, moved, 150)
}

func TestRegistry_CommitForgetsRemovedRoutes(t *testing.T) {
	reg := NewRegistry()
	a, _ := reg.Build("/a", twoWay())
	b, _ := reg.Build("/b", twoWay())
	reg.Commit([]*Route{b, a})
	assert.Equal(t, []*Route{a, b}, reg.Routes(), "sorted by label")
	reg.Commit([]*Route{a})
	_, ok := reg.Get("/b")
	assert.False(t, ok)
	assert.Len(t, reg.Routes(), 1)

	// A route re-added later starts fresh.
	b2, _ := reg.Build("/b", twoWay())
	assert.NotSame(t, b.state, b2.state)
}

func TestRegistry_SharedGuardrailWindows(t *testing.T) {
	clock := newFakeClock()
	reg := NewRegistry(WithClock(clock.Now))
	cfg := twoWay()
	cfg.Variants[1].AutoRollback = &config.AutoRollbackConfig{Window: config.Duration{Duration: time.Minute}, MinRequests: 100, MaxErrorRateIncrease: 0.05}
	r1, _ := reg.Build("/api", cfg)
	reg.Commit([]*Route{r1})
	serve(r1, 1, 60, time.Millisecond, http.StatusInternalServerError) // before the reload
	r2, _ := reg.Build("/api", cfg)
	reg.Commit([]*Route{r2})
	serve(r2, 1, 60, time.Millisecond, http.StatusInternalServerError) // after
	settle(r2, clock)
	assert.Equal(t, Weights{100, 0}, r2.Weights(), "both halves counted toward min_requests")
	assert.Equal(t, Weights{100, 0}, r1.Weights())
}
