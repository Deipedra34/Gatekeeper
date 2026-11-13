package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/ratelimiter/store"
)

func acController(t *testing.T, s accesscontrol.Settings) *accesscontrol.Controller {
	t.Helper()
	c, err := accesscontrol.NewController(s)
	require.NoError(t, err)
	return c
}

func serveAC(c *accesscontrol.Controller, remote string, next http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	AccessControl(c, nil)(next).ServeHTTP(rec, req)
	return rec
}

func TestAccessControlMiddleware_RecordsTheClientAddress(t *testing.T) {
	c := acController(t, accesscontrol.Settings{TrustedProxies: []string{"10.0.0.1"}})
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := ClientAddrFrom(r.Context())
		require.True(t, ok)
		got = a.String()
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	AccessControl(c, nil)(next).ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "198.51.100.4", got)

	_, ok := ClientAddrFrom(context.Background())
	assert.False(t, ok, "nothing without the middleware")
}

func TestAccessControlMiddleware_UnknownPeer(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, ok := ClientAddrFrom(r.Context())
		assert.False(t, ok)
	})
	allowlist := acController(t, accesscontrol.Settings{Global: accesscontrol.PolicySettings{
		Mode: accesscontrol.ModeAllowlistOnly, Allow: []string{"0.0.0.0/0", "::/0"}}})
	assert.Equal(t, http.StatusForbidden, serveAC(allowlist, "@unix", next).Code, "allowlist_only fails closed")
	assert.False(t, reached)

	denylist := acController(t, accesscontrol.Settings{Global: accesscontrol.PolicySettings{
		Mode: accesscontrol.ModeDenylist, Deny: []string{"0.0.0.0/0"}}})
	assert.Equal(t, http.StatusOK, serveAC(denylist, "@unix", next).Code)
	assert.True(t, reached)
}

// failingStore fails every operation, like an unreachable Redis.
type failingStore struct{ store.Store }

var errDown = errors.New("store down")

func (failingStore) Load(context.Context, string) ([]byte, error) { return nil, errDown }
func (failingStore) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, errDown
}

func TestAccessControlMiddleware_StoreFailureLetsRequestsThrough(t *testing.T) {
	c := acController(t, accesscontrol.Settings{Store: failingStore{}, AutoBan: &accesscontrol.AutoBanSettings{
		Threshold: 1, Window: time.Minute, BanDuration: time.Minute, Triggers: []accesscontrol.Offense{accesscontrol.OffenseRateLimit}}})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportOffense(r, accesscontrol.OffenseRateLimit) // must not panic or block
	})
	assert.Equal(t, http.StatusOK, serveAC(c, "203.0.113.7:1", next).Code)
}

func TestReportOffense_NoOpWithoutAccessControl(t *testing.T) {
	reportOffense(httptest.NewRequest(http.MethodGet, "/", nil), accesscontrol.OffenseAuthFailure)
}
