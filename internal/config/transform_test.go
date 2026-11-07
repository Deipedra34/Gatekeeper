package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// routeWith is a one-route config whose route gets routeExtra (indented
// under the route) and the given top-level extra.
func routeWith(routeExtra, topLevel string) string {
	return `
routes:
  - path_prefix: "/api"
    target: "http://localhost:9000"
` + routeExtra + "\n" + topLevel
}

func TestTransformConfig_DefaultsLeaveEverythingOff(t *testing.T) {
	cfg, err := loadYAML(t, minimalRoutes)
	require.NoError(t, err)
	assert.False(t, cfg.Transform.TrustForwardedHeaders, "forwarding headers are not trusted by default")
	assert.False(t, cfg.Transform.RequestID.Enabled)
	assert.Equal(t, "X-Request-ID", cfg.Transform.RequestID.Header)
	assert.Nil(t, cfg.Transform.SecurityHeaders.Enabled)
	assert.True(t, cfg.Routes[0].Transform.IsZero(), "a route without transform has none")
}

func TestTransformConfig_ValidFullExampleLoads(t *testing.T) {
	cfg, err := loadYAML(t, routeWith(`
    cache: {enabled: false}
    transform:
      request:
        strip_prefix: true
        rewrite: {pattern: "^/v1/(?P<rest>.*)$", replacement: "/v2/${rest}"}
        add_headers: {X-Gateway: "gatekeeper"}
        set_headers: {X-Client: "${client_id} (${client_tier}) via ${route}", X-Correlation-ID: "${request_id}"}
        remove_headers: ["X-Debug", "Cookie"]
        add_query_params: {source: "gw", rid: "${request_id}"}
        remove_query_params: ["debug"]
      response:
        set_headers: {X-Served-By: "gatekeeper", X-Trace: "${trace_id}"}
        remove_headers: ["Server", "X-Powered-By"]
        security_headers: {enabled: true, frame_options: SAMEORIGIN}`, `
transform:
  trust_forwarded_headers: true
  request_id: {enabled: true}
  security_headers: {enabled: false}`))
	require.NoError(t, err)
	sec := cfg.Routes[0].Transform.Response.SecurityHeaders
	assert.Equal(t, "nosniff", sec.ContentTypeOptions)
	assert.Equal(t, "SAMEORIGIN", sec.FrameOptions)
	assert.Equal(t, "no-referrer", sec.ReferrerPolicy)
}

func TestTransformConfig_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name, route, top, wantErr string
	}{
		{"invalid regex", `
    transform: {request: {rewrite: {pattern: "^/api/(.*", replacement: "/$1"}}}`, "", "invalid pattern"},
		{"replacement group out of range", `
    transform: {request: {rewrite: {pattern: "^/api/(.*)$", replacement: "/v2/$2"}}}`, "", "only 1 capture group"},
		{"replacement unknown named group", `
    transform: {request: {rewrite: {pattern: "^/api/(.*)$", replacement: "/v2/${rest}"}}}`, "", "no capture group named"},
		{"replacement with a query", `
    transform: {request: {rewrite: {pattern: "^/api/(.*)$", replacement: "/v2/$1?x=1"}}}`, "", "path only"},
		{"overlong pattern", `
    transform: {request: {rewrite: {pattern: "` + strings.Repeat("a", 1025) + `", replacement: "/x"}}}`, "", "longer than 1024"},
		{"unknown variable", `
    transform: {request: {set_headers: {X-Secret: "${header.authorization}"}}}`, "", "unknown variable ${header.authorization}"},
		{"unknown variable in response", `
    transform: {response: {add_headers: {X-Env: "${env}"}}}`, "", "unknown variable ${env}"},
		{"unknown variable in query", `
    transform: {request: {add_query_params: {k: "${api_key}"}}}`, "", "unknown variable ${api_key}"},
		{"unterminated variable", `
    transform: {request: {set_headers: {X-A: "${client_ip"}}}`, "", "unterminated"},
		{"header injection", `
    transform: {request: {set_headers: {X-A: "ok\r\nX-Injected: 1"}}}`, "", "control character"},
		{"request_id variable without request_id", `
    transform: {request: {set_headers: {X-Corr: "${request_id}"}}}`, "", "needs transform.request_id.enabled"},
		{"per-request query value on a cached route", `
    transform: {request: {add_query_params: {t: "${trace_id}"}}}`, "", "cache miss"},
		{"strip_prefix on a host route", "", "", ""}, // filled in below
		{"Host", `
    transform: {request: {set_headers: {Host: "evil.example"}}}`, "", "Host can't be changed"},
		{"hop-by-hop", `
    transform: {request: {remove_headers: ["Connection"]}}`, "", "hop-by-hop"},
		{"forwarding header", `
    transform: {request: {set_headers: {X-Forwarded-For: "1.2.3.4"}}}`, "", "trust_forwarded_headers"},
		{"X-Real-IP", `
    transform: {request: {remove_headers: ["X-Real-IP"]}}`, "", "trust_forwarded_headers"},
		{"websocket handshake header", `
    transform: {request: {remove_headers: ["Sec-WebSocket-Key"]}}`, "", "WebSocket handshake"},
		{"content-length", `
    transform: {response: {set_headers: {Content-Length: "0"}}}`, "", "frames the message body"},
		{"rate limit response header", `
    transform: {response: {remove_headers: ["X-RateLimit-Remaining"]}}`, "", "rate limiter sets it"},
		{"request id header", `
    transform: {response: {remove_headers: ["X-Request-ID"]}}`, `
transform: {request_id: {enabled: true}}`, "request ID"},
		{"same header in two operations", `
    transform: {request: {set_headers: {X-A: "1"}, remove_headers: ["x-a"]}}`, "", "both set_headers and remove_headers"},
		{"invalid header name", `
    transform: {request: {add_headers: {"Bad Header": "1"}}}`, "", "not a valid header name"},
		{"bad frame options", `
    transform: {response: {security_headers: {enabled: true, frame_options: ALLOW}}}`, "", "frame_options"},
		{"bad global referrer policy", "", `
transform: {security_headers: {enabled: true, referrer_policy: everywhere}}`, "referrer_policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := routeWith(tc.route, tc.top)
			if tc.name == "strip_prefix on a host route" {
				yaml = `
routes:
  - host: "api.example.com"
    target: "http://localhost:9000"
    transform: {request: {strip_prefix: true}}
`
				tc.wantErr = "needs the route to have a path_prefix"
			}
			_, err := loadYAML(t, yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestTemplate_ParseAndExpand(t *testing.T) {
	tpl, err := ParseTemplate("id=${client_id}; cost $5; route ${route}")
	require.NoError(t, err)
	assert.True(t, tpl.Uses(VarClientID))
	assert.False(t, tpl.Uses(VarRequestID))
	got := tpl.Expand(func(name string) string { return "<" + name + ">" })
	assert.Equal(t, "id=<client_id>; cost $5; route <route>", got, "a $ not followed by { is literal")

	for _, v := range TransformVariables {
		_, err := ParseTemplate("${" + v + "}")
		assert.NoError(t, err, v)
	}
	_, err = ParseTemplate("${}")
	assert.Error(t, err)
}
