package gateway_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

// splitBackend answers with its name and the path it was asked for.
type splitBackend struct {
	name string
	srv  *httptest.Server

	mu    sync.Mutex
	paths []string
}

func newSplitBackend(t *testing.T, name string) *splitBackend {
	t.Helper()
	b := &splitBackend{name: name}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.paths = append(b.paths, r.URL.Path)
		b.mu.Unlock()
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *splitBackend) hits() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.paths)
}

// seen returns the paths the backend was asked for.
func (b *splitBackend) seen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.paths...)
}

type splitHarness struct {
	gw      *gateway.Gateway
	m       *metrics.Metrics
	logs    *syncBuffer
	cfgPath string
}

func newSplitHarness(t *testing.T, yaml string) *splitHarness {
	t.Helper()
	path := writeConfig(t, t.TempDir(), "config.yaml", yaml)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	logs := &syncBuffer{}
	g, err := gateway.New(cfg, path, st, m, log.New(logs, "", 0))
	require.NoError(t, err)
	t.Cleanup(g.Close)
	return &splitHarness{gw: g, m: m, logs: logs, cfgPath: path}
}

func (h *splitHarness) rewrite(t *testing.T, yaml string) {
	t.Helper()
	require.NoError(t, os.WriteFile(h.cfgPath, []byte(yaml), 0o644))
}

// get sends GET path from remote, with header name/value pairs.
func (h *splitHarness) get(path, remote string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.gw.ServeHTTP(rec, req)
	return rec
}

// splitYAML is a gateway with API key auth and per-key rate limiting
// (tier "internal" for the "tester" key), and "/api" split between two
// backends at the given weights, plus extra settings under traffic_split
// and extra top-level config.
func splitYAML(stable, canary *splitBackend, stableWeight, canaryWeight, burst int, splitExtra, extra string) string {
	return splitYAMLFor(stable.srv.URL, canary.srv.URL, stableWeight, canaryWeight, burst, splitExtra, extra)
}

// splitYAMLFor is splitYAML with backend URLs.
func splitYAMLFor(stableURL, canaryURL string, stableWeight, canaryWeight, burst int, splitExtra, extra string) string {
	return fmt.Sprintf(`
rate_limit:
  scope: api_key
  tiers:
    default: {requests_per_second: 0.0001, burst: %d}
    internal: {requests_per_second: 0.0001, burst: 1000}
  clients: {tester: internal}
auth:
  enabled: true
  api_keys: [tester, alice, bob, carol]
routes:
  - path_prefix: "/api"
    cache: {enabled: false}
    transform: {request: {strip_prefix: true}}
    traffic_split:
      variants:
        - {name: stable, weight: %d, target: %q}
        - {name: canary, weight: %d, target: %q}
%s
%s`, burst, stableWeight, stableURL, canaryWeight, canaryURL, splitExtra, extra)
}

func TestGatewaySplit_AuthRunsBeforeTheSplit(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 50, 50, 100, "", ""))
	for i := range 20 {
		assert.Equal(t, http.StatusUnauthorized, h.get("/api/x", fmt.Sprintf("10.0.0.%d:1", i)).Code)
	}
	assert.Zero(t, stable.hits()+canary.hits(), "unauthenticated requests reach no variant")
}

func TestGatewaySplit_AccessControlRunsBeforeTheSplit(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 50, 50, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.0/24"]}
`))
	assert.Equal(t, http.StatusForbidden, h.get("/api/x", "198.51.100.7:1", "X-API-Key", "alice").Code)
	assert.Zero(t, stable.hits()+canary.hits())
}

func TestGatewaySplit_RateLimitsStayPerClient(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 50, 50, 3, `      override: {enabled: true, allow: {anyone: true}}`, ""))

	// One client, alternating variants by override: its budget is one
	// bucket across both, not one per variant.
	codes := []int{}
	for i, v := range []string{"stable", "canary", "stable", "canary", "stable"} {
		codes = append(codes, h.get("/api/x", fmt.Sprintf("10.0.0.%d:1", i), "X-API-Key", "alice", "X-Gatekeeper-Variant", v).Code)
	}
	assert.Equal(t, []int{200, 200, 200, 429, 429}, codes)
	assert.Equal(t, 3, stable.hits()+canary.hits())

	// Another client still has its own.
	assert.Equal(t, http.StatusOK, h.get("/api/x", "10.0.0.9:1", "X-API-Key", "bob").Code)
}

func TestGatewaySplit_StickyByAPIKeyAcrossAddresses(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 50, 50, 100, `      sticky: {by: api_key}`, ""))
	for _, key := range []string{"alice", "bob", "carol"} {
		first := h.get("/api/x", "10.0.0.1:1", "X-API-Key", key).Body.String()
		for i := range 10 {
			assert.Equal(t, first, h.get("/api/x", fmt.Sprintf("192.0.2.%d:1", i), "X-API-Key", key).Body.String(), key)
		}
	}
}

func TestGatewaySplit_OverrideByRateLimitTier(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 100, 0, 100, `      override: {enabled: true, allow: {tiers: [internal]}}`, ""))
	assert.Equal(t, "canary", h.get("/api/x", "203.0.113.1:1", "X-API-Key", "tester", "X-Gatekeeper-Variant", "canary").Body.String())
	assert.Equal(t, "stable", h.get("/api/x", "203.0.113.1:1", "X-API-Key", "alice", "X-Gatekeeper-Variant", "canary").Body.String(),
		"a default-tier client can't pick the canary")
}

func TestGatewaySplit_TransformsApplyToEveryVariant(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 50, 50, 100, `      override: {enabled: true, allow: {anyone: true}}`, ""))
	h.get("/api/items/7", "10.0.0.1:1", "X-API-Key", "alice", "X-Gatekeeper-Variant", "stable")
	h.get("/api/items/7", "10.0.0.1:1", "X-API-Key", "bob", "X-Gatekeeper-Variant", "canary")
	assert.Equal(t, []string{"/items/7"}, stable.seen(), "strip_prefix applied")
	assert.Equal(t, []string{"/items/7"}, canary.seen())
}

func TestGatewaySplit_MetricsAndLogs(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 90, 10, 100, "", ""))
	for i, key := range []string{"alice", "bob", "carol"} {
		h.get("/api/x", fmt.Sprintf("10.0.%d.1:1", i), "X-API-Key", key)
	}

	weights := `
# HELP gatekeeper_variant_weight_percent Current share of a split route's traffic each variant gets, in percent.
# TYPE gatekeeper_variant_weight_percent gauge
gatekeeper_variant_weight_percent{route="/api",variant="canary"} 10
gatekeeper_variant_weight_percent{route="/api",variant="stable"} 90
`
	require.NoError(t, testutil.CollectAndCompare(h.m.VariantWeightCollector(), strings.NewReader(weights)))
	total := testutil.ToFloat64(h.m.VariantRequests.WithLabelValues("/api", "stable")) + testutil.ToFloat64(h.m.VariantRequests.WithLabelValues("/api", "canary"))
	assert.Equal(t, 3.0, total)
	assert.Regexp(t, `GET /api/x 200 \S+ 10\.0\.0\.1:1 variant=(stable|canary)`, h.logs.String())

	// An admin change shows up in the gauge at the next scrape, and in
	// the log.
	sr, ok := h.gw.TrafficSplit("/api")
	require.True(t, ok)
	_, err := sr.Rollback(1, "testing")
	require.NoError(t, err)
	assert.Equal(t, 0.0, testutil.ToFloat64(h.m.VariantRollbacks.WithLabelValues("/api", "canary", "error_rate")))
	assert.Equal(t, 1.0, testutil.ToFloat64(h.m.VariantRollbacks.WithLabelValues("/api", "canary", "manual")))
	assert.Contains(t, h.logs.String(), "split: route /api: variant canary rolled back by an operator: testing; weights now canary=0 stable=100")
	require.NoError(t, testutil.CollectAndCompare(h.m.VariantWeightCollector(), strings.NewReader(strings.NewReplacer("} 10", "} 0", "} 90", "} 100").Replace(weights))))
}

func TestGatewaySplit_NoSplitNoChange(t *testing.T) {
	be := newSplitBackend(t, "plain")
	h := newSplitHarness(t, fmt.Sprintf(`
rate_limit: {tiers: {default: {requests_per_second: 0.0001, burst: 100}}}
routes:
  - path_prefix: "/"
    target: %q
`, be.srv.URL))
	rec := h.get("/x", "10.0.0.1:1", "X-Gatekeeper-Variant", "canary")
	assert.Equal(t, "plain", rec.Body.String())
	assert.Empty(t, rec.Result().Cookies())
	assert.Empty(t, h.gw.TrafficSplits())
	assert.NotContains(t, h.logs.String(), "variant=")
	assert.Zero(t, testutil.CollectAndCount(h.m.VariantWeightCollector()))
}
