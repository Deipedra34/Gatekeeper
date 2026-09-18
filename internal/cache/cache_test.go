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
