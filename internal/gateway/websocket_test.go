package gateway_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/websocket"
	"gatekeeper/internal/websocket/wstest"
)

// wsGatewayConfig is a config with API key auth on, CORS on, and an
// api_key-scoped rate limit whose default tier allows burst handshakes.
// The "/ws" route proxies to an echo backend; "/" serves plain HTTP.
func wsGatewayConfig(wsBackend, httpBackend string, burst int, routeExtra string) string {
	return fmt.Sprintf(`
storage:
  backend: memory
rate_limit:
  algorithm: fixed_window
  scope: api_key
  tiers:
    default: {requests_per_second: 1, burst: %d}
auth:
  enabled: true
  header: "X-API-Key"
  api_keys: ["key-alice", "key-bob"]
cors:
  enabled: true
  allowed_origins: ["*"]
  allowed_methods: ["GET"]
  allowed_headers: ["X-API-Key"]
routes:
  - path_prefix: "/ws"
    target: "%s"
%s
  - path_prefix: "/"
    target: "%s"
`, burst, wsBackend, routeExtra, httpBackend)
}

// startWSGateway loads cfgYAML into a gateway served over a real HTTP
// server and returns its base ws:// URL, the gateway, and its metrics.
func startWSGateway(t *testing.T, cfgYAML string) (string, *gateway.Gateway, *metrics.Metrics) {
	t.Helper()
	path := writeConfig(t, t.TempDir(), "config.yaml", cfgYAML)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	g, err := gateway.New(cfg, path, st, m, nil)
	require.NoError(t, err)

	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), g, m
}

func keyHeader(key string) http.Header {
	h := http.Header{}
	if key != "" {
		h.Set("X-API-Key", key)
	}
	return h
}

func echoServers(t *testing.T) (ws, plain *httptest.Server) {
	t.Helper()
	ws = httptest.NewServer(wstest.EchoHandler())
	t.Cleanup(ws.Close)
	plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain-http"))
	}))
	t.Cleanup(plain.Close)
	return ws, plain
}

func mustRoundTrip(t *testing.T, c *wstest.Conn, msg string) {
	t.Helper()
	require.NoError(t, c.WriteText(msg))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	got, err := c.ReadText()
	require.NoError(t, err)
	assert.Equal(t, msg, got)
}

func refusedWith(t *testing.T, url string, h http.Header) int {
	t.Helper()
	c, resp, err := wstest.Dial(url, h)
	if err == nil {
		c.Close()
		t.Fatalf("expected handshake to %s to be refused", url)
	}
	require.ErrorIs(t, err, wstest.ErrBadHandshake)
	return resp.StatusCode
}

func TestGateway_WebSocketThroughFullChain(t *testing.T) {
	wsBackend, plain := echoServers(t)
	base, _, m := startWSGateway(t, wsGatewayConfig(wsBackend.URL, plain.URL, 100, ""))

	c, resp, err := wstest.Dial(base+"/ws/chat", http.Header{
		"X-API-Key": {"key-alice"},
		"Origin":    {"https://app.example.com"},
	})
	require.NoError(t, err)
	defer c.Close()

	// The 101 carries the headers the chain added before the upgrade.
	assert.Equal(t, "100", resp.Header.Get("X-Ratelimit-Limit"))
	assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))

	mustRoundTrip(t, c, "through the whole chain")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketActive.WithLabelValues("/ws")))

	// Plain HTTP on the same gateway is unaffected.
	httpURL := "http" + strings.TrimPrefix(base, "ws") + "/hello"
	req, _ := http.NewRequest(http.MethodGet, httpURL, nil)
	req.Header.Set("X-API-Key", "key-alice")
	httpResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	httpResp.Body.Close()
	assert.Equal(t, http.StatusOK, httpResp.StatusCode)
}

func TestGateway_WebSocketHandshakeRequiresAuth(t *testing.T) {
	wsBackend, plain := echoServers(t)
	base, _, m := startWSGateway(t, wsGatewayConfig(wsBackend.URL, plain.URL, 100, ""))

	assert.Equal(t, http.StatusUnauthorized, refusedWith(t, base+"/ws", keyHeader("")), "missing key")
	assert.Equal(t, http.StatusUnauthorized, refusedWith(t, base+"/ws", keyHeader("not-a-key")), "invalid key")
	assert.Equal(t, 2.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectAuth)))
	assert.Equal(t, 0.0, testutil.ToFloat64(m.WebSocketOpened.WithLabelValues("/ws")), "nothing reached the backend")
}

func TestGateway_WebSocketHandshakeRequiresValidJWT(t *testing.T) {
	wsBackend, _ := echoServers(t)
	base, _, m := startWSGateway(t, `
rate_limit:
  algorithm: fixed_window
  scope: ip
  tiers:
    default: {requests_per_second: 100, burst: 100}
auth:
  enabled: true
  jwt:
    algorithm: HS256
    secret: "`+gatewayTestSecret+`"
routes:
  - path_prefix: "/ws"
    target: "`+wsBackend.URL+`"
    auth_mode: jwt
`)
	h := http.Header{"Authorization": {"Bearer not.a.jwt"}}
	assert.Equal(t, http.StatusUnauthorized, refusedWith(t, base+"/ws", h))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectAuth)))
}

func TestGateway_WebSocketHandshakeIsRateLimitedNotFrames(t *testing.T) {
	wsBackend, plain := echoServers(t)
	// Burst 1: exactly one handshake per second per client.
	base, _, m := startWSGateway(t, wsGatewayConfig(wsBackend.URL, plain.URL, 1, ""))

	c, _, err := wstest.Dial(base+"/ws", keyHeader("key-alice"))
	require.NoError(t, err)
	defer c.Close()

	// Frames on the established connection never touch the limiter.
	for i := 0; i < 25; i++ {
		mustRoundTrip(t, c, fmt.Sprintf("frame %d", i))
	}
	assert.Equal(t, 1.0, testutil.ToFloat64(m.RequestsAllowed.WithLabelValues("key-alice", "default")),
		"one token for the handshake, none for frames")

	// A second handshake from the same client, though, costs a token it
	// doesn't have.
	assert.Equal(t, http.StatusTooManyRequests, refusedWith(t, base+"/ws", keyHeader("key-alice")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectRateLimit)))

	// The open connection is unaffected by the rejection.
	mustRoundTrip(t, c, "still open")
}

func TestGateway_WebSocketPerClientLimitUsesRateLimitIdentity(t *testing.T) {
	wsBackend, plain := echoServers(t)
	base, _, m := startWSGateway(t, wsGatewayConfig(wsBackend.URL, plain.URL, 100,
		"    ws_max_connections_per_client: 1"))

	alice, _, err := wstest.Dial(base+"/ws", keyHeader("key-alice"))
	require.NoError(t, err)
	defer alice.Close()

	// Same client (same API key, same rate-limit identity): over the cap.
	assert.Equal(t, http.StatusTooManyRequests, refusedWith(t, base+"/ws", keyHeader("key-alice")))
	// Different API key from the same IP: a different client.
	bob, _, err := wstest.Dial(base+"/ws", keyHeader("key-bob"))
	require.NoError(t, err)
	defer bob.Close()
	mustRoundTrip(t, bob, "bob")

	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectMaxConnections)))
}

func TestGateway_WebSocketOriginAndReloadKeepsConnections(t *testing.T) {
	wsBackend, plain := echoServers(t)
	cfgYAML := wsGatewayConfig(wsBackend.URL, plain.URL, 100,
		`    ws_allowed_origins: ["https://app.example.com"]`)
	path := writeConfig(t, t.TempDir(), "config.yaml", cfgYAML)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	m := metrics.New()
	g, err := gateway.New(cfg, path, st, m, nil)
	require.NoError(t, err)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	base := "ws" + strings.TrimPrefix(srv.URL, "http")

	h := keyHeader("key-alice")
	h.Set("Origin", "https://evil.example.com")
	assert.Equal(t, http.StatusForbidden, refusedWith(t, base+"/ws", h))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectOrigin)))

	h.Set("Origin", "https://app.example.com")
	c, _, err := wstest.Dial(base+"/ws", h)
	require.NoError(t, err)
	defer c.Close()

	// A SIGHUP-style reload doesn't drop the established connection.
	require.NoError(t, g.Reload())
	mustRoundTrip(t, c, "survived reload")

	// And graceful shutdown closes it with a Close frame.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, g.ShutdownWebSockets(ctx))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	op, payload, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, byte(wstest.OpClose), op)
	code, _ := wstest.CloseCode(payload)
	assert.Equal(t, 1001, code)
}
