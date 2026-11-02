package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/ratelimiter/store"
)

func TestCache_GetSetRoundTrip(t *testing.T) {
	c := New(store.NewMemoryStore())
	ctx := context.Background()

	_, hit, err := c.Get(ctx, "missing")
	require.NoError(t, err)
	assert.False(t, hit)

	entry := &Entry{StatusCode: http.StatusOK, Header: http.Header{"X-Test": []string{"1"}}, Body: []byte("hello")}
	require.NoError(t, c.Set(ctx, "key", entry, time.Minute))

	got, hit, err := c.Get(ctx, "key")
	require.NoError(t, err)
	require.True(t, hit)
	assert.Equal(t, http.StatusOK, got.StatusCode)
	assert.Equal(t, []byte("hello"), got.Body)
	assert.Equal(t, "1", got.Header.Get("X-Test"))
}

func TestCache_RedisBacked(t *testing.T) {
	mr := miniredis.RunT(t)
	c := New(store.NewRedisStore(mr.Addr(), "", 0, time.Second))
	ctx := context.Background()

	entry := &Entry{StatusCode: http.StatusOK, Body: []byte("from redis")}
	require.NoError(t, c.Set(ctx, "key", entry, time.Minute))

	got, hit, err := c.Get(ctx, "key")
	require.NoError(t, err)
	require.True(t, hit)
	assert.Equal(t, []byte("from redis"), got.Body)

	mr.FastForward(2 * time.Minute)
	_, hit, err = c.Get(ctx, "key")
	require.NoError(t, err)
	assert.False(t, hit, "entry should be gone once its ttl has elapsed")
}

func TestKey_DiffersOnMethodURLTargetAndVaryHeaders(t *testing.T) {
	base := httptest.NewRequest(http.MethodGet, "/widgets?x=1", nil)
	sameAsBase := httptest.NewRequest(http.MethodGet, "/widgets?x=1", nil)
	assert.Equal(t, Key("/api", "http://backend", base), Key("/api", "http://backend", sameAsBase),
		"identical requests against the same route/target must produce the same key")

	differentQuery := httptest.NewRequest(http.MethodGet, "/widgets?x=2", nil)
	assert.NotEqual(t, Key("/api", "http://backend", base), Key("/api", "http://backend", differentQuery))

	differentTarget := Key("/api", "http://other-backend", base)
	assert.NotEqual(t, Key("/api", "http://backend", base), differentTarget,
		"a route repointed at a different backend on reload must not reuse the old cache entry")

	withAuth := httptest.NewRequest(http.MethodGet, "/widgets?x=1", nil)
	withAuth.Header.Set("Authorization", "Bearer abc")
	assert.NotEqual(t, Key("/api", "http://backend", base), Key("/api", "http://backend", withAuth),
		"different Authorization header must produce a different key")
}

func TestStorable_RejectsNoStore(t *testing.T) {
	assert.True(t, Storable(http.Header{}))
	assert.True(t, Storable(http.Header{"Cache-Control": []string{"max-age=60"}}))
	assert.False(t, Storable(http.Header{"Cache-Control": []string{"no-store"}}))
	assert.False(t, Storable(http.Header{"Cache-Control": []string{"private, no-store"}}))
}

func TestBypass(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, Bypass(r))
	r.Header.Set(BypassHeader, "1")
	assert.True(t, Bypass(r))
}

func TestCache_PurgeByRouteAndURLPrefix(t *testing.T) {
	c := New(store.NewMemoryStore())
	ctx := context.Background()
	entry := &Entry{StatusCode: http.StatusOK, Body: []byte("x")}
	put := func(key, route, uri string) {
		t.Helper()
		require.NoError(t, c.SetFor(ctx, key, Meta{Route: route, URI: uri}, entry, time.Minute))
	}
	present := func(key string) bool {
		_, hit, err := c.Get(ctx, key)
		require.NoError(t, err)
		return hit
	}
	put("u1", "/api/users", "/api/users/1")
	put("u2", "/api/users", "/api/users/2?full=1")
	put("o1", "/api/orders", "/api/orders/9")

	n, err := c.Purge(ctx, PurgeFilter{Route: "/api/users"}, true)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "dry run reports what would go")
	assert.True(t, present("u1"), "dry run deletes nothing")

	n, err = c.Purge(ctx, PurgeFilter{URLPrefix: "/api/users/2"}, false)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.False(t, present("u2"))
	assert.True(t, present("u1"))

	n, err = c.Purge(ctx, PurgeFilter{}, false)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "an empty filter purges everything")
	assert.False(t, present("u1"))
	assert.False(t, present("o1"))

	stats := c.Stats()
	assert.Equal(t, 0, stats.Entries)
	assert.Equal(t, int64(3), stats.Writes)
	assert.Equal(t, int64(3), stats.Purged)
}

func TestCache_StatsCountHitsMissesAndEntriesByRoute(t *testing.T) {
	c := New(store.NewMemoryStore())
	ctx := context.Background()
	entry := &Entry{StatusCode: http.StatusOK}
	require.NoError(t, c.SetFor(ctx, "a", Meta{Route: "/a", URI: "/a/1"}, entry, time.Minute))
	require.NoError(t, c.SetFor(ctx, "b", Meta{Route: "/a", URI: "/a/2"}, entry, time.Minute))
	require.NoError(t, c.SetFor(ctx, "c", Meta{Route: "/b", URI: "/b"}, entry, time.Minute))

	_, _, _ = c.Get(ctx, "a")
	_, _, _ = c.Get(ctx, "missing")

	stats := c.Stats()
	assert.Equal(t, 3, stats.Entries)
	assert.Equal(t, map[string]int{"/a": 2, "/b": 1}, stats.EntriesByRoute)
	assert.Equal(t, int64(1), stats.Hits)
	assert.Equal(t, int64(1), stats.Misses)
}
