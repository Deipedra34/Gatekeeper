package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// backend starts an httptest server that always responds with name in
// the body, so a test can tell which backend actually served a request.
func backend(t *testing.T, name string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", name)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(name))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRouter_RoutesByLongestPathPrefix(t *testing.T) {
	users := backend(t, "users")
	usersVIP := backend(t, "users-vip")
	catchAll := backend(t, "catch-all")

	router, err := NewRouter([]config.Route{
		{PathPrefix: "/api/users", Target: users.URL},
		{PathPrefix: "/api/users/vip", Target: usersVIP.URL},
		{PathPrefix: "/", Target: catchAll.URL},
	})
	require.NoError(t, err)

	cases := []struct {
		path string
		want string
	}{
		{"/api/users/42", "users"},
		{"/api/users/vip/42", "users-vip"},
		{"/anything-else", "catch-all"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equalf(t, tc.want, rec.Header().Get("X-Backend"), "path %s should route to %s", tc.path, tc.want)
	}
}

func TestRouter_RoutesByHostBeforePathPrefix(t *testing.T) {
	byHost := backend(t, "by-host")
	byPath := backend(t, "by-path")

	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: byPath.URL},
		{Host: "orders.example.com", Target: byHost.URL},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Host = "orders.example.com"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, "by-host", rec.Header().Get("X-Backend"), "a host match should win over a path-prefix match")
}

func TestRouter_ReturnsNotFoundWhenNoRouteMatches(t *testing.T) {
	router, err := NewRouter([]config.Route{
		{PathPrefix: "/api", Target: backend(t, "api").URL},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/unrouted", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRouter_ReturnsBadGatewayWhenBackendIsDown(t *testing.T) {
	down := backend(t, "will-be-closed")
	down.Close() // close immediately so the target is unreachable

	router, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: down.URL},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestRouter_ForwardsRequestBodyAndMethod(t *testing.T) {
	var gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	router, err := NewRouter([]config.Route{{PathPrefix: "/", Target: srv.URL}})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "hello", gotBody)
}

func TestNewRouter_RejectsInvalidTargetURL(t *testing.T) {
	_, err := NewRouter([]config.Route{
		{PathPrefix: "/", Target: "://not-a-valid-url"},
	})
	assert.Error(t, err)
}
