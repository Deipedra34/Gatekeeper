package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/cache"
	"gatekeeper/internal/config"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/split"
	"gatekeeper/internal/websocket/wstest"
)

func TestSplit_CacheNeverMixesVariants(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	rt := splitRoute(stable, canary, 50)
	rt.Cache = config.RouteCache{Enabled: boolPtr(true), TTL: config.Duration{Duration: time.Minute}}
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	router, err := NewRouter([]config.Route{rt}, noRetryProxyConfig(), nil, cache.New(st))
	require.NoError(t, err)
	t.Cleanup(router.Close)

	onStable, onCanary := clientOn(t, router, "stable"), clientOn(t, router, "canary")
	stableHits, canaryHits := stable.hits.Load(), canary.hits.Load()

	// Each variant fills its own entry for the same URL...
	first := from(router, onStable, "/api/items", nil)
	assert.Equal(t, "stable", first.Body.String())
	assert.Equal(t, "MISS", first.Header().Get("X-Cache"))
	got := from(router, onCanary, "/api/items", nil)
	assert.Equal(t, "canary", got.Body.String(), "stable's cached response isn't served to a canary client")
	assert.Equal(t, "MISS", got.Header().Get("X-Cache"))

	// ...and serves it to its own clients only.
	again := from(router, onCanary, "/api/items", nil)
	assert.Equal(t, "canary", again.Body.String())
	assert.Equal(t, "HIT", again.Header().Get("X-Cache"))
	again = from(router, onStable, "/api/items", nil)
	assert.Equal(t, "stable", again.Body.String())
	assert.Equal(t, "HIT", again.Header().Get("X-Cache"))
	assert.Equal(t, stableHits+1, stable.hits.Load())
	assert.Equal(t, canaryHits+1, canary.hits.Load())
}

func TestSplit_RetriesStayInsideTheVariant(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	canary2 := newVariantBackend(t, "canary2")
	rt := splitRoute(stable, canary, 50)
	rt.TrafficSplit.Variants[1].Target = ""
	rt.TrafficSplit.Variants[1].Backends = []config.BackendConfig{{Target: canary.srv.URL}, {Target: canary2.srv.URL}}
	router := newSplitRouter(t, 3, rt)
	onCanary := clientOn(t, router, "canary")

	canary.fail.Store(true)
	canary2.fail.Store(true)
	before := stable.hits.Load()
	rec := from(router, onCanary, "/api", nil)
	assert.Equal(t, http.StatusBadGateway, rec.Code, "the canary's failure is the answer")
	assert.Equal(t, before, stable.hits.Load(), "no retry went to stable")
	assert.GreaterOrEqual(t, canary.hits.Load()+canary2.hits.Load(), int32(4), "retries went to the canary's own backends")
}

// wsVariantBackend is a WebSocket echo backend that counts handshakes.
func wsVariantBackend(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	echo := wstest.EchoHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		echo.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestSplit_WebSocketVariantIsChosenAtTheHandshake(t *testing.T) {
	stableWS, stableN := wsVariantBackend(t)
	canaryWS, canaryN := wsVariantBackend(t)
	rt := config.Route{
		PathPrefix: "/ws",
		TrafficSplit: &config.TrafficSplitConfig{
			Variants: []config.VariantConfig{
				{Name: "stable", Weight: 100, Target: stableWS.URL},
				{Name: "canary", Weight: 0, Target: canaryWS.URL},
			},
			Override: config.OverrideConfig{Enabled: true, Header: config.DefaultVariantHeader, Allow: config.OverrideAllow{Anyone: true}},
		},
	}
	router := newSplitRouter(t, 0, rt)
	gw := gatewayFor(t, router)

	c := dialOK(t, wsURL(gw, "/ws/chat"), http.Header{"X-Gatekeeper-Variant": {"canary"}})
	roundTrip(t, c, "hello")
	roundTrip(t, c, "again")
	assert.Equal(t, int32(1), canaryN.Load(), "one handshake, and every frame after it, on the canary")
	assert.Zero(t, stableN.Load())

	// Changing the weights doesn't move an established connection.
	sr := router.SplitRoutes()[0]
	require.NoError(t, sr.SetWeights(split.Weights{100, 0}, false))
	roundTrip(t, c, "still here")

	c2 := dialOK(t, wsURL(gw, "/ws/chat"), nil)
	roundTrip(t, c2, "hi")
	assert.Equal(t, int32(1), stableN.Load())
}

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestSplit_FailingCanaryIsRolledBackByItsTraffic(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	rt := splitRoute(stable, canary, 50)
	rt.TrafficSplit.Variants[1].AutoRollback = &config.AutoRollbackConfig{
		Window: config.Duration{Duration: time.Minute}, MinRequests: 20, MaxErrorRateIncrease: 0.10,
		Cooldown: config.Duration{Duration: 10 * time.Minute},
	}
	clock := &testClock{now: time.Now()}
	var events []split.Event
	var mu sync.Mutex
	reg := split.NewRegistry(split.WithClock(clock.Now), split.WithEvents(func(e split.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}))
	router, err := NewRouter([]config.Route{rt}, noRetryProxyConfig(), nil, nil, WithSplitRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(router.Close)

	canary.fail.Store(true)
	for i := range 200 {
		from(router, fmt.Sprintf("10.2.%d.%d", i/256, i%256), "/api", nil)
	}
	clock.Advance(2 * time.Second)
	from(router, "10.3.0.1", "/api", nil) // the next request triggers an evaluation

	assert.Equal(t, split.Weights{100, 0}, router.SplitRoutes()[0].Weights())
	mu.Lock()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	mu.Unlock()
	assert.Equal(t, split.EventRollback, last.Kind)
	assert.Equal(t, split.TriggerErrorRate, last.Trigger)

	// From now on, nobody reaches the canary.
	before := canary.hits.Load()
	for i := range 100 {
		assert.Equal(t, "stable", from(router, fmt.Sprintf("10.4.0.%d", i), "/api", nil).Body.String())
	}
	assert.Equal(t, before, canary.hits.Load())
}
