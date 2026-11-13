package gateway_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

// acBackend is a backend that counts the requests reaching it.
type acBackend struct {
	srv  *httptest.Server
	hits atomic.Int32
}

func newACBackend(t *testing.T) *acBackend {
	t.Helper()
	b := &acBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// acYAML is a config with an "/admin" route and a "/" route on backend,
// rate limited per X-Client-ID header to burst requests, plus extra
// (top-level YAML) and adminExtra (indented under the /admin route).
func acYAML(backend string, burst int, adminExtra, extra string) string {
	return fmt.Sprintf(`
storage:
  backend: memory
rate_limit:
  algorithm: token_bucket
  scope: header
  header_name: X-Client-ID
  tiers:
    # Refills so slowly that no test sees a token come back.
    default: {requests_per_second: 0.0001, burst: %d}
auth:
  enabled: false
routes:
  - path_prefix: "/admin"
    target: %q
    cache: {enabled: false}
%s
  - path_prefix: "/"
    target: %q
    cache: {enabled: false}
proxy:
  retry: {max_retries: 0}
%s
`, burst, backend, adminExtra, backend, extra)
}

type acHarness struct {
	gw      *gateway.Gateway
	m       *metrics.Metrics
	st      store.Store
	logs    *syncBuffer
	cfgPath string
}

func newACHarness(t *testing.T, yaml string) *acHarness {
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
	return &acHarness{gw: g, m: m, st: st, logs: logs, cfgPath: path}
}

// get sends GET path from remote (host:port), with header name/value
// pairs.
func (h *acHarness) get(path, remote string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.gw.ServeHTTP(rec, req)
	return rec
}

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func (h *acHarness) blocked(reason string) float64 {
	return testutil.ToFloat64(h.m.AccessBlocked.WithLabelValues(reason))
}

func TestAccessControl_Denylist(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control:
  mode: denylist
  deny: ["198.51.100.0/24", "2001:db8:bad::/48", "203.0.113.66"]
`))

	for _, remote := range []string{"198.51.100.7:5000", "[2001:db8:bad::1]:5000", "203.0.113.66:1", "[::ffff:198.51.100.8]:1"} {
		rec := h.get("/anything", remote)
		assert.Equal(t, http.StatusForbidden, rec.Code, remote)
		assert.Equal(t, "access denied\n", rec.Body.String())
	}
	assert.EqualValues(t, 0, be.hits.Load(), "blocked requests never reach the backend")
	assert.Equal(t, 4.0, h.blocked("deny_list"))

	for _, remote := range []string{"203.0.113.67:1", "[2001:db8:900d::1]:1", "192.0.2.1:1"} {
		assert.Equal(t, http.StatusOK, h.get("/anything", remote).Code, remote)
	}
	assert.EqualValues(t, 3, be.hits.Load())
}

func TestAccessControl_CustomDenyStatus(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.7"], deny_status: 451}
`))
	assert.Equal(t, http.StatusUnavailableForLegalReasons, h.get("/", "198.51.100.7:1").Code)
}

func TestAccessControl_AllowlistOnlyAdminRouteOverridesGlobal(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, `
    access_control:
      mode: allowlist_only
      allow: ["10.0.0.0/8", "2001:db8:a::/48"]
      deny_status: 404
`, `
access_control:
  mode: denylist
  deny: ["198.51.100.0/24", "10.6.6.6"]
`))

	// /admin: only the allowlist gets in, and the global deny list still
	// applies, since the route doesn't override it — deny wins over allow.
	assert.Equal(t, http.StatusOK, h.get("/admin/users", "10.1.2.3:1").Code)
	assert.Equal(t, http.StatusOK, h.get("/admin/users", "[2001:db8:a::9]:1").Code)
	assert.Equal(t, http.StatusNotFound, h.get("/admin/users", "203.0.113.1:1").Code)
	assert.Equal(t, http.StatusNotFound, h.get("/admin/users", "10.6.6.6:1").Code, "denied even though allowlisted")
	assert.Equal(t, http.StatusNotFound, h.get("/admin/users", "198.51.100.1:1").Code)

	// Everything else: the global deny list only.
	assert.Equal(t, http.StatusOK, h.get("/public", "203.0.113.1:1").Code)
	assert.Equal(t, http.StatusForbidden, h.get("/public", "198.51.100.1:1").Code)

	// The deny list is checked first, so 198.51.100.1 on /admin counts as
	// deny_list, not not_in_allowlist.
	assert.Equal(t, 1.0, h.blocked("not_in_allowlist"))
	assert.Equal(t, 3.0, h.blocked("deny_list"))
}

func TestAccessControl_SpoofedForwardedForIsIgnoredFromUntrustedPeers(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control:
  mode: allowlist_only
  allow: ["10.0.0.0/8"]
  trusted_proxies: ["192.0.2.10", "192.0.2.11"]
`))

	// A client claiming an allowlisted address in its own headers.
	for _, hdr := range [][]string{
		{"X-Forwarded-For", "10.0.0.5"},
		{"X-Real-IP", "10.0.0.5"},
		{"X-Forwarded-For", "10.0.0.5", "X-Real-IP", "10.0.0.5"},
	} {
		assert.Equal(t, http.StatusForbidden, h.get("/", "203.0.113.1:4000", hdr...).Code, hdr)
	}

	// The same claim relayed by a trusted proxy, which appends the
	// address it really received the request from: still blocked.
	assert.Equal(t, http.StatusForbidden,
		h.get("/", "192.0.2.10:4000", "X-Forwarded-For", "10.0.0.5, 203.0.113.1").Code)

	// A genuine allowlisted client behind one or two trusted proxies.
	assert.Equal(t, http.StatusOK, h.get("/", "192.0.2.10:4000", "X-Forwarded-For", "10.0.0.5").Code)
	assert.Equal(t, http.StatusOK, h.get("/", "192.0.2.10:4000", "X-Forwarded-For", "6.6.6.6, 10.0.0.5, 192.0.2.11").Code)
	assert.Equal(t, http.StatusOK, h.get("/", "192.0.2.11:4000", "X-Real-IP", "10.0.0.5").Code)
	assert.EqualValues(t, 3, be.hits.Load())
}

func TestAccessControl_BlockedRequestsDontConsumeRateLimitTokens(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 2, "", `
access_control: {mode: denylist, deny: ["198.51.100.7"]}
`))

	// A denied address hammers the gateway as client "shared".
	for range 20 {
		require.Equal(t, http.StatusForbidden, h.get("/", "198.51.100.7:1", "X-Client-ID", "shared").Code)
	}
	assert.Equal(t, 0.0, testutil.ToFloat64(h.m.RequestsRejected.WithLabelValues("shared", "default")))
	assert.Equal(t, 0.0, testutil.ToFloat64(h.m.RequestsAllowed.WithLabelValues("shared", "default")))

	// The same client from an allowed address still has its whole burst.
	for i := range 2 {
		rec := h.get("/", "203.0.113.1:1", "X-Client-ID", "shared")
		require.Equal(t, http.StatusOK, rec.Code, "request %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, h.get("/", "203.0.113.1:1", "X-Client-ID", "shared").Code)
	assert.EqualValues(t, 2, be.hits.Load())
}

func TestAccessControl_RateLimitsByResolvedAddress(t *testing.T) {
	be := newACBackend(t)
	yaml := strings.Replace(acYAML(be.srv.URL, 2, "", `
access_control: {trusted_proxies: ["192.0.2.10"]}
`), "scope: header", "scope: ip", 1)
	h := newACHarness(t, yaml)

	// A client rotating spoofed X-Forwarded-For values shares one bucket.
	codes := []int{}
	for i := range 4 {
		codes = append(codes, h.get("/", "203.0.113.1:1", "X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i)).Code)
	}
	assert.Equal(t, []int{200, 200, 429, 429}, codes)

	// Behind the trusted proxy, each real client gets its own bucket.
	assert.Equal(t, http.StatusOK, h.get("/", "192.0.2.10:1", "X-Forwarded-For", "198.51.100.1").Code)
	assert.Equal(t, http.StatusOK, h.get("/", "192.0.2.10:1", "X-Forwarded-For", "198.51.100.2").Code)
}

func TestAccessControl_AutoBanOnRateLimitRejections(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 1, "", `
access_control:
  auto_ban: {enabled: true, threshold: 3, window: 1m, ban_duration: 10m}
`))
	client := []string{"X-Client-ID", "greedy"}

	assert.Equal(t, http.StatusOK, h.get("/", "203.0.113.9:1", client...).Code)
	for range 3 {
		assert.Equal(t, http.StatusTooManyRequests, h.get("/", "203.0.113.9:1", client...).Code)
	}
	// The third rejection banned the address.
	rec := h.get("/", "203.0.113.9:1", client...)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	retry := rec.Header().Get("Retry-After")
	assert.NotEmpty(t, retry)
	assert.Contains(t, []string{"599", "600"}, retry)
	assert.Empty(t, rec.Header().Get("X-RateLimit-Limit"), "the rate limiter never saw it")
	assert.Equal(t, 1.0, h.blocked("auto_ban"))
	assert.Equal(t, 1.0, testutil.ToFloat64(h.m.BansIssued.WithLabelValues("auto")))
	assert.Contains(t, h.logs.String(), "access_control: auto-banned 203.0.113.9")

	// Another address — even with the same client ID — is unaffected by
	// the ban (it's still over its rate limit, though).
	assert.Equal(t, http.StatusTooManyRequests, h.get("/", "203.0.113.10:1", client...).Code)
	assert.EqualValues(t, 1, be.hits.Load())
}

func TestAccessControl_AutoBanOnAuthFailures(t *testing.T) {
	be := newACBackend(t)
	yaml := strings.Replace(acYAML(be.srv.URL, 100, "", `
access_control:
  auto_ban:
    enabled: true
    threshold: 3
    triggers: [auth_failure]
    never_ban: ["192.0.2.0/24"]
`), "auth:\n  enabled: false", "auth:\n  enabled: true\n  api_keys: [\"good-key\"]", 1)
	h := newACHarness(t, yaml)

	for range 3 {
		assert.Equal(t, http.StatusUnauthorized, h.get("/", "203.0.113.9:1", "X-API-Key", "guess").Code)
	}
	assert.Equal(t, http.StatusForbidden, h.get("/", "203.0.113.9:1", "X-API-Key", "good-key").Code,
		"banned: even the right key no longer helps")

	// never_ban: an operator fat-fingering their key isn't locked out.
	for range 10 {
		assert.Equal(t, http.StatusUnauthorized, h.get("/", "192.0.2.5:1", "X-API-Key", "typo").Code)
	}
	assert.Equal(t, http.StatusOK, h.get("/", "192.0.2.5:1", "X-API-Key", "good-key").Code)
}

func TestAccessControl_AutoBanOnDeniedRequests(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, `
    access_control: {mode: allowlist_only, allow: ["10.0.0.0/8"]}
`, `
access_control:
  auto_ban: {enabled: true, threshold: 2, triggers: [denied]}
`))
	// A scanner probing the admin route is banned from the whole gateway.
	assert.Equal(t, http.StatusForbidden, h.get("/admin", "203.0.113.9:1").Code)
	assert.Equal(t, http.StatusForbidden, h.get("/admin", "203.0.113.9:1").Code)
	assert.Equal(t, http.StatusForbidden, h.get("/public", "203.0.113.9:1").Code)
	assert.Equal(t, 2.0, h.blocked("not_in_allowlist"))
	assert.Equal(t, 1.0, h.blocked("auto_ban"))
}

func TestAccessControl_ActiveBansGauge(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control: {}
`))
	assert.Equal(t, 0.0, testutil.ToFloat64(h.m.ActiveBansCollector()))
	c := h.gw.AccessControl()
	require.NotNil(t, c)
	ctx := t.Context()
	_, err := c.Ban(ctx, netipAddr("203.0.113.1"), time.Hour, "")
	require.NoError(t, err)
	_, err = c.Ban(ctx, netipAddr("2001:db8::1"), time.Hour, "")
	require.NoError(t, err)
	assert.Equal(t, 2.0, testutil.ToFloat64(h.m.ActiveBansCollector()))

	assert.Equal(t, http.StatusForbidden, h.get("/", "203.0.113.1:1").Code)
	assert.Equal(t, 1.0, h.blocked("manual_ban"))
}

func TestAccessControl_BlockedRequestsAreLoggedAtALimitedRate(t *testing.T) {
	be := newACBackend(t)
	h := newACHarness(t, acYAML(be.srv.URL, 100, "", `
access_control: {mode: denylist, deny: ["198.51.100.7"]}
`))
	for range 500 {
		h.get("/secret?token=abc", "198.51.100.7:1", "Authorization", "Bearer do-not-log-me")
	}
	logs := h.logs.String()
	lines := strings.Count(logs, "access_control: blocked")
	assert.LessOrEqual(t, lines, 12, "a flood doesn't turn into one log line per request")
	assert.GreaterOrEqual(t, lines, 1)
	assert.Contains(t, logs, `access_control: blocked GET "/secret" from 198.51.100.7: deny_list (status 403)`)
	assert.NotContains(t, logs, "do-not-log-me", "headers are never logged")
	assert.NotContains(t, logs, "token=abc", "nor the query")
	assert.Equal(t, 500.0, h.blocked("deny_list"), "metrics still count every one")
}

// TestAccessControl_NotConfiguredBehavesAsBefore checks that a config
// without access_control gets no access control at all: nothing is
// blocked, the rate limiter still keys on X-Forwarded-For as it always
// has, and /metrics has no access control series.
func TestAccessControl_NotConfiguredBehavesAsBefore(t *testing.T) {
	be := newACBackend(t)
	yaml := strings.Replace(acYAML(be.srv.URL, 1, "", ""), "scope: header", "scope: ip", 1)
	h := newACHarness(t, yaml)
	assert.Nil(t, h.gw.AccessControl())

	assert.Equal(t, http.StatusOK, h.get("/", "198.51.100.7:1", "X-Forwarded-For", "1.1.1.1").Code)
	assert.Equal(t, http.StatusOK, h.get("/", "198.51.100.7:1", "X-Forwarded-For", "2.2.2.2").Code,
		"a different X-Forwarded-For is a different client, exactly as before")
	assert.Equal(t, http.StatusTooManyRequests, h.get("/", "198.51.100.7:1", "X-Forwarded-For", "1.1.1.1").Code)
	assert.Equal(t, 1.0, testutil.ToFloat64(h.m.RequestsAllowed.WithLabelValues("1.1.1.1", "default")))

	rec := httptest.NewRecorder()
	h.m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	assert.NotContains(t, rec.Body.String(), "gatekeeper_access_control")
	assert.NotContains(t, h.logs.String(), "access_control")
}
