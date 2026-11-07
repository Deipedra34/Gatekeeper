package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func compile(t *testing.T, rt config.Route, global config.TransformConfig) (*Request, *Response) {
	t.Helper()
	req, resp, err := Compile(rt, global)
	require.NoError(t, err)
	return req, resp
}

func TestCompile_NoTransformIsNil(t *testing.T) {
	req, resp := compile(t, config.Route{PathPrefix: "/api"}, config.TransformConfig{})
	assert.Nil(t, req)
	assert.Nil(t, resp)

	r := httptest.NewRequest(http.MethodGet, "/api/x?a=1", nil)
	assert.Equal(t, Result{}, req.Apply(r, Vars{}), "a nil transform changes nothing")
	assert.Equal(t, "/api/x", r.URL.Path)
	assert.Nil(t, req.CacheVary(r, Vars{}))
}

func TestRequest_StripPrefix(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/api", Transform: config.RouteTransform{
		Request: config.RequestTransform{StripPrefix: true},
	}}, config.TransformConfig{})

	for in, want := range map[string]string{
		"/api/users":       "/users",
		"/api/users/":      "/users/",
		"/api":             "/",
		"/api/":            "/",
		"/api/a%2Fb/c":     "/a/b/c",
		"/api/v1/x?q=keep": "/v1/x",
	} {
		r := httptest.NewRequest(http.MethodGet, in, nil)
		res := req.Apply(r, Vars{})
		assert.Equal(t, want, r.URL.Path, in)
		assert.True(t, res.PathChanged, in)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/a%2Fb", nil)
	req.Apply(r, Vars{})
	assert.Equal(t, "/a%2Fb", r.URL.EscapedPath(), "an encoded slash stays encoded")

	r = httptest.NewRequest(http.MethodGet, "/api/v1/x?q=keep", nil)
	req.Apply(r, Vars{})
	assert.Equal(t, "q=keep", r.URL.RawQuery, "the query is untouched")
}

func TestRequest_RegexRewriteWithCaptureGroups(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Request: config.RequestTransform{Rewrite: &config.PathRewrite{
			Pattern: `^/api/v1/(?P<resource>[a-z]+)/(\d+)$`, Replacement: "/v2/${resource}/item-$2",
		}},
	}}, config.TransformConfig{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/users/42?x=1", nil)
	res := req.Apply(r, Vars{})
	assert.True(t, res.PathChanged)
	assert.Equal(t, "/v2/users/item-42", r.URL.Path)
	assert.Equal(t, "x=1", r.URL.RawQuery)

	r = httptest.NewRequest(http.MethodGet, "/other/path", nil)
	res = req.Apply(r, Vars{})
	assert.False(t, res.PathChanged, "a path the pattern doesn't match is left alone")
	assert.Equal(t, "/other/path", r.URL.Path)
}

func TestRequest_StripPrefixThenRewrite(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/api", Transform: config.RouteTransform{
		Request: config.RequestTransform{
			StripPrefix: true,
			Rewrite:     &config.PathRewrite{Pattern: `^/v1/(.*)$`, Replacement: "/v2/$1"},
		},
	}}, config.TransformConfig{})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/orders", nil)
	req.Apply(r, Vars{})
	assert.Equal(t, "/v2/orders", r.URL.Path)
}

func TestCleanPath(t *testing.T) {
	assert.Equal(t, "/", cleanPath(""))
	assert.Equal(t, "/a/b", cleanPath("a/b"))
	assert.Equal(t, "/b", cleanPath("/a/../b"))
	assert.Equal(t, "/b/", cleanPath("/a/../b/"))
	assert.Equal(t, "/", cleanPath("/../.."))
}

func TestRequest_QueryParams(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Request: config.RequestTransform{
			AddQueryParams:    map[string]string{"source": "gateway", "tenant": "${client_id}"},
			RemoveQueryParams: []string{"debug", "token"},
		},
	}}, config.TransformConfig{})

	r := httptest.NewRequest(http.MethodGet, "/x?debug=1&token=abc&keep=yes&tenant=forged", nil)
	res := req.Apply(r, Vars{ClientID: "key:0123456789ab"})
	assert.True(t, res.Query)
	q := r.URL.Query()
	assert.Empty(t, q.Get("debug"))
	assert.Empty(t, q.Get("token"))
	assert.Equal(t, "yes", q.Get("keep"))
	assert.Equal(t, "gateway", q.Get("source"))
	assert.Equal(t, []string{"key:0123456789ab"}, q["tenant"], "a client can't pre-empt a parameter the gateway sets")
}

func TestRequest_HeadersAddSetRemoveAndVariables(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Request: config.RequestTransform{
			AddHeaders:    map[string]string{"X-Gateway": "gatekeeper", "X-Keep": "ours"},
			SetHeaders:    map[string]string{"X-Client": "${client_id}/${client_tier}@${client_ip} on ${route} rid=${request_id} trace=${trace_id}"},
			RemoveHeaders: []string{"X-Debug", "cookie"},
		},
	}}, config.TransformConfig{})

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Keep", "client's")
	r.Header.Set("X-Client", "forged")
	r.Header.Set("X-Debug", "1")
	r.Header.Set("Cookie", "session=abc")
	vars := Vars{ClientID: "jwt:alice", ClientTier: "premium", ClientIP: "203.0.113.9", Route: "/", RequestID: "rid-1", TraceID: "abc"}
	res := req.Apply(r, vars)

	assert.True(t, res.Headers)
	assert.Equal(t, "gatekeeper", r.Header.Get("X-Gateway"))
	assert.Equal(t, "client's", r.Header.Get("X-Keep"), "add_headers never overwrites")
	assert.Equal(t, []string{"jwt:alice/premium@203.0.113.9 on / rid=rid-1 trace=abc"}, r.Header.Values("X-Client"), "set_headers replaces")
	assert.Empty(t, r.Header.Get("X-Debug"))
	assert.Empty(t, r.Header.Get("Cookie"))
}

func TestVariables_ControlCharactersAreDropped(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Request: config.RequestTransform{SetHeaders: map[string]string{"X-Client": "${client_id}"}},
	}}, config.TransformConfig{})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Apply(r, Vars{ClientID: "tenant\r\nX-Injected: 1"})
	assert.Equal(t, "tenantX-Injected: 1", r.Header.Get("X-Client"))
	assert.Empty(t, r.Header.Get("X-Injected"))
}

func TestRequest_SetHeaderSurvivesClientConnectionHeader(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Request: config.RequestTransform{SetHeaders: map[string]string{"X-Internal": "yes"}},
	}}, config.TransformConfig{})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Connection", "keep-alive, X-Internal, X-Other")
	req.Apply(r, Vars{})
	assert.Equal(t, "keep-alive, X-Other", r.Header.Get("Connection"),
		"a header the gateway sets is taken off the client's hop-by-hop list")
}

func TestUnlistFromConnection_DropsHeaderWhenNothingLeft(t *testing.T) {
	h := http.Header{"Connection": {"X-Real-IP"}}
	UnlistFromConnection(h, "x-real-ip")
	_, ok := h["Connection"]
	assert.False(t, ok)
}

func TestCacheVary_IgnoresPerRequestIDsButKeysOnClient(t *testing.T) {
	req, _ := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Request: config.RequestTransform{
			SetHeaders: map[string]string{"X-Client": "${client_id}", "X-Corr": "${request_id}"},
			AddHeaders: map[string]string{"X-Tier": "${client_tier}"},
		},
	}}, config.TransformConfig{RequestID: config.RequestIDConfig{Enabled: true}})

	vary := func(v Vars) []string {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Apply(r, v)
		return req.CacheVary(r, v)
	}
	a1 := vary(Vars{ClientID: "a", ClientTier: "free", RequestID: "1", TraceID: "t1"})
	a2 := vary(Vars{ClientID: "a", ClientTier: "free", RequestID: "2", TraceID: "t2"})
	b := vary(Vars{ClientID: "b", ClientTier: "free", RequestID: "3"})
	assert.Equal(t, a1, a2, "request and trace IDs don't split the cache")
	assert.NotEqual(t, a1, b, "different clients never share an entry")
}

func TestForwardedHeaders_ReplacesClientSuppliedValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/x", nil)
	r.RemoteAddr = "198.51.100.7:4567"
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	r.Header.Set("X-Real-IP", "6.6.6.6")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Forwarded", "for=6.6.6.6")
	r.Header.Set("Connection", "X-Real-IP")

	ForwardedHeaders(r)
	assert.Empty(t, r.Header.Get("X-Forwarded-For"), "the proxy sets it from the connection")
	assert.Empty(t, r.Header.Get("Forwarded"))
	assert.Equal(t, "198.51.100.7", r.Header.Get("X-Real-IP"))
	assert.Equal(t, "api.example.com", r.Header.Get("X-Forwarded-Host"))
	assert.Equal(t, "http", r.Header.Get("X-Forwarded-Proto"))
	assert.Empty(t, r.Header.Get("Connection"))
}

func TestClientIP_TrustedOrNot(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", " 203.0.113.5 , 10.0.0.9")
	assert.Equal(t, "10.0.0.1", ClientIP(r, false))
	assert.Equal(t, "203.0.113.5", ClientIP(r, true))

	r.Header.Set("X-Forwarded-For", "not-an-ip")
	assert.Equal(t, "10.0.0.1", ClientIP(r, true), "an unparseable header falls back to the peer")
}

func TestResponse_HeadersAndSecurityDefaults(t *testing.T) {
	_, resp := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Response: config.ResponseTransform{
			AddHeaders:    map[string]string{"X-Served-By": "gatekeeper", "Cache-Control": "no-store"},
			SetHeaders:    map[string]string{"X-Route": "${route}"},
			RemoveHeaders: []string{"Server", "X-Powered-By"},
		},
	}}, config.TransformConfig{SecurityHeaders: config.SecurityHeadersConfig{
		Enabled: boolPtr(true), ContentTypeOptions: "nosniff", FrameOptions: "DENY", ReferrerPolicy: "no-referrer",
	}})
	require.NotNil(t, resp)

	h := http.Header{}
	h.Set("Server", "nginx/1.2.3")
	h.Set("X-Powered-By", "PHP/5")
	h.Set("Cache-Control", "max-age=60")
	h.Set("X-Route", "backend's")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	resp.ApplyHeaders(h, Vars{Route: "/api"})

	assert.Empty(t, h.Get("Server"))
	assert.Empty(t, h.Get("X-Powered-By"))
	assert.Equal(t, "gatekeeper", h.Get("X-Served-By"))
	assert.Equal(t, "max-age=60", h.Get("Cache-Control"), "add_headers keeps the backend's value")
	assert.Equal(t, "/api", h.Get("X-Route"), "set_headers replaces it")
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", h.Get("X-Frame-Options"), "a backend's own security header wins")
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
}

func TestResponse_RouteCanTurnOffGlobalSecurityHeaders(t *testing.T) {
	global := config.TransformConfig{SecurityHeaders: config.SecurityHeadersConfig{Enabled: boolPtr(true)}}
	_, resp := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Response: config.ResponseTransform{SecurityHeaders: config.SecurityHeadersConfig{Enabled: boolPtr(false)}},
	}}, global)
	assert.Nil(t, resp)

	_, inherited := compile(t, config.Route{PathPrefix: "/"}, global)
	assert.NotNil(t, inherited, "a route without its own setting inherits the global one")
}

func TestResponse_WrapAppliesOnceAndSkipsInformational(t *testing.T) {
	_, resp := compile(t, config.Route{PathPrefix: "/", Transform: config.RouteTransform{
		Response: config.ResponseTransform{SetHeaders: map[string]string{"X-A": "1"}},
	}}, config.TransformConfig{})

	rec := httptest.NewRecorder()
	calls := 0
	w := resp.Wrap(rec, Vars{}, func() { calls++ })
	w.WriteHeader(http.StatusEarlyHints)
	assert.Equal(t, 0, calls, "1xx responses pass through")
	_, _ = w.Write([]byte("body"))
	_, _ = w.Write([]byte("more"))
	assert.Equal(t, 1, calls)
	assert.Equal(t, "1", rec.Header().Get("X-A"))
	assert.Equal(t, "bodymore", rec.Body.String())
}
