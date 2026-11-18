package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// variantBackend answers with its name and records the override header
// it saw, if any.
type variantBackend struct {
	name string
	srv  *httptest.Server
	hits atomic.Int32
	fail atomic.Bool // answer 502

	mu         sync.Mutex
	sawHeaders []string
}

func newVariantBackend(t *testing.T, name string) *variantBackend {
	t.Helper()
	b := &variantBackend{name: name}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.mu.Lock()
		b.sawHeaders = append(b.sawHeaders, r.Header.Get("X-Gatekeeper-Variant"))
		b.mu.Unlock()
		if b.fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
		}
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *variantBackend) headersSeen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.sawHeaders...)
}

// splitRoute is a "/api" route split weight% to canary, the rest to
// stable, with caching off unless a test turns it on. Defaults are
// filled in as config.Load would.
func splitRoute(stable, canary *variantBackend, weight int) config.Route {
	return config.Route{
		PathPrefix: "/api",
		Cache:      config.RouteCache{Enabled: boolPtr(false)},
		TrafficSplit: &config.TrafficSplitConfig{
			Variants: []config.VariantConfig{
				{Name: "stable", Weight: 100 - weight, Target: stable.srv.URL},
				{Name: "canary", Weight: weight, Target: canary.srv.URL},
			},
			Baseline: "stable",
			Sticky:   config.StickyConfig{By: config.StickyClientIP, Cookie: config.StickyCookieConfig{Name: "gk_variant", Path: "/"}},
			Override: config.OverrideConfig{Header: config.DefaultVariantHeader},
		},
	}
}

func newSplitRouter(t *testing.T, retries int, routes ...config.Route) *Router {
	t.Helper()
	cfg := noRetryProxyConfig()
	cfg.Retry.MaxRetries = retries
	router, err := NewRouter(routes, cfg, nil, nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	return router
}

// from sends a GET for path from the client at ip.
func from(router http.Handler, ip, path string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = ip + ":40000"
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// clientOn finds a client address the split puts on variant.
func clientOn(t *testing.T, router http.Handler, variant string) string {
	t.Helper()
	for i := range 2000 {
		ip := fmt.Sprintf("198.18.%d.%d", i/256, i%256)
		if from(router, ip, "/api", nil).Body.String() == variant {
			return ip
		}
	}
	t.Fatalf("no client lands on %s", variant)
	return ""
}

func TestSplit_DistributionFollowsWeights(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	router := newSplitRouter(t, 0, splitRoute(stable, canary, 10))

	const n = 4000
	for i := range n {
		rec := from(router, fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "/api/items", nil)
		require.Equal(t, http.StatusOK, rec.Code)
	}
	share := float64(canary.hits.Load()) / n
	assert.InDelta(t, 0.10, share, 0.02, "canary got %d of %d", canary.hits.Load(), n)
	assert.Equal(t, int32(n), stable.hits.Load()+canary.hits.Load())
}

func TestSplit_SameClientSameVariant(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	router := newSplitRouter(t, 0, splitRoute(stable, canary, 50))
	for i := range 50 {
		ip := fmt.Sprintf("203.0.113.%d", i)
		first := from(router, ip, "/api", nil).Body.String()
		for range 10 {
			assert.Equal(t, first, from(router, ip, "/api/other", nil).Body.String(), "client %s", ip)
		}
	}
}

func overrideRoute(stable, canary *variantBackend, forward bool) config.Route {
	rt := splitRoute(stable, canary, 0)
	rt.TrafficSplit.Override = config.OverrideConfig{
		Enabled: true, Header: config.DefaultVariantHeader, ForwardHeader: forward,
		Allow: config.OverrideAllow{CIDRs: []string{"10.0.0.0/8"}},
	}
	return rt
}

func TestSplit_OverrideAllowedForListedClients(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	router := newSplitRouter(t, 0, overrideRoute(stable, canary, false))
	force := http.Header{"X-Gatekeeper-Variant": {"canary"}}

	assert.Equal(t, "canary", from(router, "10.1.2.3", "/api", force).Body.String(), "a tester reaches the canary, even at weight 0")
	assert.Equal(t, "stable", from(router, "10.1.2.3", "/api", nil).Body.String())
}

func TestSplit_OverrideDeniedForThePublic(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	router := newSplitRouter(t, 0, overrideRoute(stable, canary, false))
	force := http.Header{"X-Gatekeeper-Variant": {"canary"}}
	for i := range 20 {
		assert.Equal(t, "stable", from(router, fmt.Sprintf("203.0.113.%d", i), "/api", force).Body.String())
	}
	assert.Zero(t, canary.hits.Load())
}

func TestSplit_OverrideHeaderIsStrippedBeforeTheBackend(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	router := newSplitRouter(t, 0, overrideRoute(stable, canary, false))
	force := http.Header{"X-Gatekeeper-Variant": {"canary"}}
	from(router, "10.1.2.3", "/api", force)    // honoured
	from(router, "203.0.113.9", "/api", force) // refused
	assert.Equal(t, []string{""}, canary.headersSeen())
	assert.Equal(t, []string{""}, stable.headersSeen(), "a refused override is stripped too")
}

func TestSplit_OverrideHeaderForwardedWhenConfigured(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	router := newSplitRouter(t, 0, overrideRoute(stable, canary, true))
	from(router, "10.1.2.3", "/api", http.Header{"X-Gatekeeper-Variant": {"canary"}})
	assert.Equal(t, []string{"canary"}, canary.headersSeen())
}

func TestSplit_MatchRulesRouteTesters(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	rt := splitRoute(stable, canary, 0)
	rt.TrafficSplit.Rules = []config.SplitRule{
		{Variant: "canary", Match: config.SplitMatch{Header: &config.ValueMatch{Name: "X-Tester", Value: "true"}}},
		{Variant: "canary", Match: config.SplitMatch{PathPrefix: "/api/beta"}},
	}
	router := newSplitRouter(t, 0, rt)
	assert.Equal(t, "canary", from(router, "203.0.113.1", "/api", http.Header{"X-Tester": {"true"}}).Body.String())
	assert.Equal(t, "stable", from(router, "203.0.113.1", "/api", http.Header{"X-Tester": {"false"}}).Body.String())
	assert.Equal(t, "canary", from(router, "203.0.113.1", "/api/beta/x", nil).Body.String())
	assert.Equal(t, "stable", from(router, "203.0.113.1", "/api/x", nil).Body.String())
}

func TestSplit_ResponseHeaderAndStickyCookie(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	rt := splitRoute(stable, canary, 50)
	rt.TrafficSplit.ResponseHeader = "X-Variant"
	rt.TrafficSplit.Sticky = config.StickyConfig{By: config.StickyCookie, Cookie: config.StickyCookieConfig{
		Name: "gk_variant", Path: "/", Secret: "0123456789abcdef",
	}}
	router := newSplitRouter(t, 0, rt)

	rec := from(router, "203.0.113.1", "/api", nil)
	assert.Equal(t, rec.Body.String(), rec.Header().Get("X-Variant"))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "gk_variant", cookies[0].Name)

	// Back with the cookie: the same variant, from any address, and no
	// new cookie.
	for i := range 20 {
		again := from(router, fmt.Sprintf("192.0.2.%d", i), "/api", http.Header{"Cookie": {cookies[0].Name + "=" + cookies[0].Value}})
		assert.Equal(t, rec.Body.String(), again.Body.String())
		assert.Empty(t, again.Result().Cookies())
	}
}

func TestSplit_RoutesWithoutASplitAreUnchanged(t *testing.T) {
	stable, canary := newVariantBackend(t, "stable"), newVariantBackend(t, "canary")
	plain := newVariantBackend(t, "plain")
	router := newSplitRouter(t, 0,
		splitRoute(stable, canary, 50),
		config.Route{PathPrefix: "/plain", Target: plain.srv.URL, Cache: config.RouteCache{Enabled: boolPtr(false)}},
	)
	for i := range 20 {
		rec := from(router, fmt.Sprintf("203.0.113.%d", i), "/plain/x", http.Header{"X-Gatekeeper-Variant": {"canary"}})
		assert.Equal(t, "plain", rec.Body.String())
		assert.Empty(t, rec.Result().Cookies())
		assert.Empty(t, rec.Header().Get("X-Variant"))
	}
	for _, h := range plain.headersSeen() {
		assert.Equal(t, "canary", h, "an unsplit route forwards the header untouched")
	}
	assert.Len(t, router.SplitRoutes(), 1, "only the split route is listed")
}
