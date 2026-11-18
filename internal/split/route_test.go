package split

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// twoWay is a 90/10 stable/canary split.
func twoWay() config.TrafficSplitConfig {
	return config.TrafficSplitConfig{
		Variants: []config.VariantConfig{
			{Name: "stable", Weight: 90, Target: "http://stable:1"},
			{Name: "canary", Weight: 10, Target: "http://canary:1"},
		},
		Baseline: "stable",
		Sticky:   config.StickyConfig{By: config.StickyClientIP, Cookie: config.StickyCookieConfig{Name: "gk_variant", Path: "/"}},
		Override: config.OverrideConfig{Header: config.DefaultVariantHeader},
	}
}

func newRoute(t *testing.T, cfg config.TrafficSplitConfig, opts ...Option) *Route {
	t.Helper()
	r, err := NewRoute("/api", cfg, opts...)
	require.NoError(t, err)
	return r
}

func get(path string) *http.Request { return httptest.NewRequest(http.MethodGet, path, nil) }

func TestRoute_SameClientSameVariant(t *testing.T) {
	r := newRoute(t, twoWay())
	for i := range 500 {
		c := Client{IP: fmt.Sprintf("198.51.100.%d", i%256), Tier: "default"}
		first := r.Select(get("/api"), c)
		assert.Equal(t, SourceWeight, first.Source)
		for range 5 {
			assert.Equal(t, first, r.Select(get("/api/other?x=1"), c), "client %s", c.IP)
		}
	}
}

func TestRoute_DistributionFollowsWeights(t *testing.T) {
	r := newRoute(t, twoWay())
	const n = 50000
	canary := 0
	for i := range n {
		if r.Select(get("/api"), Client{IP: fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)}).Name == "canary" {
			canary++
		}
	}
	assert.InDelta(t, 0.10, float64(canary)/n, 0.01)
}

func TestRoute_StickyByIdentity(t *testing.T) {
	for _, tc := range []struct {
		by     string
		client func(i int) Client
	}{
		{config.StickyAPIKey, func(i int) Client { return Client{APIKey: fmt.Sprintf("key-%d", i), IP: fmt.Sprintf("10.0.0.%d", i%7)} }},
		{config.StickyJWTSubject, func(i int) Client { return Client{JWTSubject: fmt.Sprintf("user-%d", i), IP: "10.0.0.1"} }},
		{config.StickyClientCert, func(i int) Client { return Client{CertID: fmt.Sprintf("svc-%d", i), IP: "10.0.0.1"} }},
	} {
		t.Run(tc.by, func(t *testing.T) {
			cfg := twoWay()
			cfg.Sticky.By = tc.by
			r := newRoute(t, cfg)
			canary := 0
			for i := range 4000 {
				c := tc.client(i)
				d := r.Select(get("/api"), c)
				// The same identity from another address keeps its variant.
				c.IP = "203.0.113.99"
				assert.Equal(t, d, r.Select(get("/api"), c))
				if d.Name == "canary" {
					canary++
				}
			}
			assert.InDelta(t, 400, canary, 120, "the identity, not the shared IP, decides")
		})
	}
}

func TestRoute_MissingIdentityFallsBackToIP(t *testing.T) {
	cfg := twoWay()
	cfg.Sticky.By = config.StickyAPIKey
	r := newRoute(t, cfg)
	byIP := newRoute(t, twoWay())
	for i := range 200 {
		c := Client{IP: fmt.Sprintf("192.0.2.%d", i)}
		assert.Equal(t, byIP.Select(get("/"), c), r.Select(get("/"), c))
	}
}

func TestRoute_SaltDefaultsToTheLabel(t *testing.T) {
	cfg := twoWay()
	a := newRoute(t, cfg)
	cfg.Sticky.Salt = "/api"
	b := newRoute(t, cfg)
	cfg.Sticky.Salt = "reshuffle"
	c := newRoute(t, cfg)
	moved := 0
	for i := range 1000 {
		cl := Client{IP: fmt.Sprintf("192.0.2.%d", i%256) + fmt.Sprint(i/256)}
		assert.Equal(t, a.Select(get("/"), cl), b.Select(get("/"), cl))
		if a.Select(get("/"), cl) != c.Select(get("/"), cl) {
			moved++
		}
	}
	assert.Positive(t, moved, "a new salt reshuffles")
}

func TestRoute_Accessors(t *testing.T) {
	r := newRoute(t, twoWay())
	assert.Equal(t, "/api", r.Label())
	assert.Equal(t, []string{"stable", "canary"}, r.Names())
	assert.Equal(t, 0, r.Baseline())
	i, ok := r.Index("canary")
	assert.True(t, ok)
	assert.Equal(t, 1, i)
	_, ok = r.Index("blue")
	assert.False(t, ok)
	assert.Equal(t, Weights{90, 10}, r.Weights())
}

func cookieRoute(t *testing.T, secret string) *Route {
	t.Helper()
	cfg := twoWay()
	cfg.Sticky.By = config.StickyCookie
	cfg.Sticky.Cookie.Secret = secret
	cfg.Sticky.Cookie.TTL.Duration = time.Hour
	return newRoute(t, cfg)
}

func TestRoute_CookieStickiness(t *testing.T) {
	r := cookieRoute(t, "0123456789abcdef")

	first := r.Select(get("/api"), Client{IP: "10.0.0.1"})
	require.NotNil(t, first.SetCookie, "a new client gets a cookie")
	ck := first.SetCookie
	assert.Equal(t, "gk_variant", ck.Name)
	assert.Equal(t, "/", ck.Path)
	assert.Equal(t, 3600, ck.MaxAge)
	assert.True(t, ck.HttpOnly)

	// With the cookie, the client keeps its variant from any address,
	// and isn't sent a new cookie.
	for i := range 20 {
		req := get("/api")
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		d := r.Select(req, Client{IP: fmt.Sprintf("192.0.2.%d", i)})
		assert.Equal(t, first.Name, d.Name)
		assert.Nil(t, d.SetCookie)
	}
}

func TestRoute_CookieClientsSpreadByWeight(t *testing.T) {
	r := cookieRoute(t, "0123456789abcdef")
	canary := 0
	for range 20000 {
		if r.Select(get("/api"), Client{IP: "10.0.0.1"}).Name == "canary" {
			canary++
		}
	}
	assert.InDelta(t, 2000, canary, 300, "new clients are placed at random, by weight, even from one address")
}

func TestRoute_ForgedOrForeignCookiesAreReplaced(t *testing.T) {
	r := cookieRoute(t, "0123456789abcdef")
	other := cookieRoute(t, "fedcba9876543210")
	for _, v := range []string{"9999", "9999.AAAAAAAAAAAAAAAA", other.signer.Sign("/api", 9999)} {
		req := get("/api")
		req.AddCookie(&http.Cookie{Name: "gk_variant", Value: v})
		d := r.Select(req, Client{IP: "10.0.0.1"})
		assert.NotNil(t, d.SetCookie, "%q is not trusted", v)
	}
}

func TestRoute_CookieWithoutSecretUsesOneSecretPerProcess(t *testing.T) {
	a := cookieRoute(t, "")
	b := cookieRoute(t, "") // the same route rebuilt, as a reload would
	assert.True(t, a.RandomCookieSecret())
	assert.False(t, cookieRoute(t, "0123456789abcdef").RandomCookieSecret())
	assert.False(t, newRoute(t, twoWay()).RandomCookieSecret())

	d := a.Select(get("/api"), Client{})
	req := get("/api")
	req.AddCookie(d.SetCookie)
	assert.Nil(t, b.Select(req, Client{}).SetCookie, "a rebuilt route still accepts the cookie")
}

func overrideRoute(t *testing.T, allow config.OverrideAllow) *Route {
	t.Helper()
	cfg := twoWay()
	cfg.Override.Enabled = true
	cfg.Override.Allow = allow
	return newRoute(t, cfg)
}

// stableClient finds a client the weights put on stable.
func stableClient(t *testing.T, r *Route, base Client) Client {
	t.Helper()
	for i := range 1000 {
		c := base
		c.IP = fmt.Sprintf("10.9.%d.%d", i/256, i%256)
		if base.IP != "" {
			c.IP = base.IP
		}
		if r.byWeight(get("/api"), c).Name == "stable" {
			return c
		}
		if base.IP != "" {
			break
		}
	}
	t.Fatal("no stable client found")
	return Client{}
}

func withVariantHeader(v string) *http.Request {
	req := get("/api")
	req.Header.Set("X-Gatekeeper-Variant", v)
	return req
}

func TestRoute_OverrideAllowed(t *testing.T) {
	r := overrideRoute(t, config.OverrideAllow{
		Tiers: []string{"internal"}, APIKeys: []string{"tester-key"}, CIDRs: []string{"10.20.0.0/16", "2001:db8::/32"},
	})
	for name, c := range map[string]Client{
		"tier":      {Tier: "internal", IP: "203.0.113.1"},
		"api key":   {APIKey: "tester-key", IP: "203.0.113.1"},
		"ipv4 cidr": {IP: "10.20.3.4"},
		"ipv6 cidr": {IP: "2001:db8::42"},
		"mapped":    {IP: "::ffff:10.20.3.4"},
	} {
		t.Run(name, func(t *testing.T) {
			d := r.Select(withVariantHeader("canary"), c)
			assert.Equal(t, "canary", d.Name)
			assert.Equal(t, SourceOverride, d.Source)
			assert.False(t, d.OverrideRefused)

			// Testers can force stable too, and it beats stickiness.
			assert.Equal(t, "stable", r.Select(withVariantHeader("stable"), c).Name)
		})
	}
}

func TestRoute_OverrideDenied(t *testing.T) {
	r := overrideRoute(t, config.OverrideAllow{Tiers: []string{"internal"}, APIKeys: []string{"tester-key"}, CIDRs: []string{"10.20.0.0/16"}})
	for name, c := range map[string]Client{
		"public client":  {Tier: "default", IP: "203.0.113.1"},
		"wrong key":      {APIKey: "tester-key-2", IP: "203.0.113.1"},
		"key prefix":     {APIKey: "tester", IP: "203.0.113.1"},
		"outside cidr":   {IP: "10.21.0.1"},
		"no information": {},
	} {
		t.Run(name, func(t *testing.T) {
			c := stableClient(t, r, c)
			d := r.Select(withVariantHeader("canary"), c)
			assert.Equal(t, "stable", d.Name, "the header is ignored")
			assert.Equal(t, SourceWeight, d.Source)
			assert.True(t, d.OverrideRefused)
		})
	}
}

func TestRoute_OverrideOfAnUnknownVariantIsIgnored(t *testing.T) {
	r := overrideRoute(t, config.OverrideAllow{Anyone: true})
	c := stableClient(t, r, Client{})
	d := r.Select(withVariantHeader("blue"), c)
	assert.Equal(t, "stable", d.Name)
	assert.True(t, d.OverrideRefused)
}

func TestRoute_OverrideDisabledIgnoresTheHeader(t *testing.T) {
	r := newRoute(t, twoWay())
	c := stableClient(t, r, Client{})
	d := r.Select(withVariantHeader("canary"), c)
	assert.Equal(t, "stable", d.Name)
	assert.False(t, d.OverrideRefused, "nothing to refuse when overrides are off")
	assert.Equal(t, "X-Gatekeeper-Variant", r.OverrideHeader())
	assert.False(t, r.ForwardOverrideHeader())
}
