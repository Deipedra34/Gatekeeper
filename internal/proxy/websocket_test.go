package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/cache"
	"gatekeeper/internal/circuitbreaker"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/websocket"
	"gatekeeper/internal/websocket/wstest"
)

// wsURL turns an httptest server URL into a ws:// URL for path.
func wsURL(srv *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

// echoBackend starts a backend whose every request is a WebSocket echo.
func echoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(wstest.EchoHandler())
	t.Cleanup(srv.Close)
	return srv
}

// gatewayFor serves router through a real HTTP server, so connections
// can be hijacked the way they are in production.
func gatewayFor(t *testing.T, router http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func dialOK(t *testing.T, url string, header http.Header) *wstest.Conn {
	t.Helper()
	c, resp, err := wstest.Dial(url, header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (status %d: %s)", url, err, status, wstest.ResponseBody(resp))
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// dialStatus attempts a handshake that's expected to be refused and
// returns the status code it was refused with.
func dialStatus(t *testing.T, url string, header http.Header) int {
	t.Helper()
	c, resp, err := wstest.Dial(url, header)
	if err == nil {
		c.Close()
		t.Fatalf("dial %s: expected handshake to be refused, got 101", url)
	}
	require.ErrorIs(t, err, wstest.ErrBadHandshake)
	return resp.StatusCode
}

func roundTrip(t *testing.T, c *wstest.Conn, msg string) {
	t.Helper()
	require.NoError(t, c.WriteText(msg))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	got, err := c.ReadText()
	require.NoError(t, err)
	assert.Equal(t, msg, got)
}

// expectClose reads until a Close frame arrives and returns its code and
// reason, then confirms the connection is closed after it.
func expectClose(t *testing.T, c *wstest.Conn, within time.Duration) (int, string) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(within)))
	for {
		op, payload, err := c.ReadMessage()
		require.NoError(t, err, "expected a Close frame before the connection ended")
		if op != wstest.OpClose {
			continue
		}
		code, reason := wstest.CloseCode(payload)
		expectEOF(t, c, 5*time.Second)
		return code, reason
	}
}

// expectEOF confirms the connection is torn down (not merely quiet).
func expectEOF(t *testing.T, c *wstest.Conn, within time.Duration) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(within)))
	for {
		_, _, err := c.ReadMessage()
		if err == nil {
			continue
		}
		var timeout interface{ Timeout() bool }
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("connection still open after %s", within)
		}
		return
	}
}

func eventuallyGauge(t *testing.T, want float64, get func() float64) {
	t.Helper()
	require.Eventually(t, func() bool { return get() == want }, 5*time.Second, 10*time.Millisecond,
		"metric never reached %v (last %v)", want, get())
}

func TestWebSocket_RelaysMessagesInBothDirections(t *testing.T) {
	seen := make(chan *http.Request, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(context.Background())
		w.Header().Set("Sec-WebSocket-Protocol", "chat")
		c, err := wstest.Upgrade(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		// Backend speaks first, so the backend->client direction is
		// exercised independently of any echo.
		if c.WriteText("welcome") != nil {
			return
		}
		for {
			op, payload, err := c.ReadMessage()
			if err != nil {
				return
			}
			if op == wstest.OpClose {
				_ = c.WriteMessage(wstest.OpClose, payload)
				return
			}
			_ = c.WriteMessage(op, append([]byte("echo:"), payload...))
		}
	}))
	t.Cleanup(backend.Close)

	m := metrics.New()
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	h := http.Header{}
	h.Set("Sec-WebSocket-Protocol", "chat")
	h.Set("X-Custom", "passed-through")
	c, resp, err := wstest.Dial(wsURL(gw, "/ws/room?id=7"), h)
	require.NoError(t, err)
	defer c.Close()
	assert.Equal(t, "chat", resp.Header.Get("Sec-WebSocket-Protocol"), "backend's handshake headers reach the client")

	got := <-seen
	assert.Equal(t, "/ws/room", got.URL.Path)
	assert.Equal(t, "id=7", got.URL.RawQuery)
	assert.Equal(t, "passed-through", got.Header.Get("X-Custom"))
	assert.Equal(t, "chat", got.Header.Get("Sec-WebSocket-Protocol"))
	assert.Equal(t, "127.0.0.1", got.Header.Get("X-Forwarded-For"))
	assert.Equal(t, strings.TrimPrefix(gw.URL, "http://"), got.Host, "incoming Host header is kept, as for HTTP routes")

	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	welcome, err := c.ReadText()
	require.NoError(t, err)
	assert.Equal(t, "welcome", welcome)

	for _, msg := range []string{"one", "two", "three"} {
		require.NoError(t, c.WriteText(msg))
		got, err := c.ReadText()
		require.NoError(t, err)
		assert.Equal(t, "echo:"+msg, got)
	}

	// A payload larger than the relay buffer and needing a 64-bit length
	// field goes through intact.
	big := bytes.Repeat([]byte("0123456789abcdef"), 70_000/16+1)
	require.NoError(t, c.WriteMessage(wstest.OpBinary, big))
	op, payload, err := c.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, byte(wstest.OpBinary), op)
	assert.Equal(t, append([]byte("echo:"), big...), payload)

	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketActive.WithLabelValues("/ws")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketOpened.WithLabelValues("/ws")))

	// Client-initiated closing handshake is relayed both ways.
	require.NoError(t, c.WriteClose(1000, "bye"))
	code, reason := expectClose(t, c, 5*time.Second)
	assert.Equal(t, 1000, code)
	assert.Equal(t, "bye", reason)

	eventuallyGauge(t, 0, func() float64 { return testutil.ToFloat64(m.WebSocketActive.WithLabelValues("/ws")) })
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketClosed.WithLabelValues("/ws", websocket.CloseReasonClient)))
	assert.Equal(t, 1, testutil.CollectAndCount(m.WebSocketDuration), "one duration observation for the route")
}

func TestWebSocket_OriginCheck(t *testing.T) {
	backend := echoBackend(t)
	m := metrics.New()
	router, err := NewRouter([]config.Route{{
		PathPrefix:       "/ws",
		Target:           backend.URL,
		WSAllowedOrigins: []string{"https://app.example.com"},
	}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	evil := http.Header{"Origin": {"https://evil.example.com"}}
	assert.Equal(t, http.StatusForbidden, dialStatus(t, wsURL(gw, "/ws"), evil))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectOrigin)))

	good := http.Header{"Origin": {"https://APP.example.com"}}
	roundTrip(t, dialOK(t, wsURL(gw, "/ws"), good), "allowed origin")

	// Non-browser clients send no Origin and aren't affected.
	roundTrip(t, dialOK(t, wsURL(gw, "/ws"), nil), "no origin")
}

func TestWebSocket_MaxConnectionsPerRoute(t *testing.T) {
	backend := echoBackend(t)
	m := metrics.New()
	router, err := NewRouter([]config.Route{{
		PathPrefix:       "/ws",
		Target:           backend.URL,
		WSMaxConnections: 2,
	}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	first := dialOK(t, wsURL(gw, "/ws"), nil)
	dialOK(t, wsURL(gw, "/ws"), nil)
	assert.Equal(t, http.StatusServiceUnavailable, dialStatus(t, wsURL(gw, "/ws"), nil))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectMaxConnections)))

	// Closing a connection frees its slot.
	require.NoError(t, first.Close())
	eventuallyGauge(t, 1, func() float64 { return testutil.ToFloat64(m.WebSocketActive.WithLabelValues("/ws")) })
	roundTrip(t, dialOK(t, wsURL(gw, "/ws"), nil), "slot reused")
}

func TestWebSocket_MaxConnectionsPerClient(t *testing.T) {
	backend := echoBackend(t)
	m := metrics.New()
	router, err := NewRouter([]config.Route{{
		PathPrefix:                "/ws",
		Target:                    backend.URL,
		WSMaxConnectionsPerClient: 1,
	}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)

	// Stand in for the middleware chain: tag the handshake with a client
	// identity the way the rate limiter does.
	gw := gatewayFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = websocket.Annotate(r, "/ws")
		hs, _ := websocket.HandshakeFrom(r.Context())
		hs.SetClient(r.Header.Get("X-Client"))
		router.ServeHTTP(w, r)
	}))

	alice := http.Header{"X-Client": {"alice"}}
	bob := http.Header{"X-Client": {"bob"}}
	dialOK(t, wsURL(gw, "/ws"), alice)
	assert.Equal(t, http.StatusTooManyRequests, dialStatus(t, wsURL(gw, "/ws"), alice))
	roundTrip(t, dialOK(t, wsURL(gw, "/ws"), bob), "bob has his own allowance")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectMaxConnections)))
}

func TestWebSocket_IdleTimeoutClosesConnection(t *testing.T) {
	backend := echoBackend(t)
	m := metrics.New()
	router, err := NewRouter([]config.Route{{
		PathPrefix:    "/ws",
		Target:        backend.URL,
		WSIdleTimeout: config.Duration{Duration: 300 * time.Millisecond},
	}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	c := dialOK(t, wsURL(gw, "/ws"), nil)

	// Traffic keeps the connection alive well past the idle timeout.
	for i := 0; i < 6; i++ {
		roundTrip(t, c, "keepalive")
		time.Sleep(100 * time.Millisecond)
	}

	// Then silence closes it with 1001 Going Away.
	start := time.Now()
	code, reason := expectClose(t, c, 5*time.Second)
	assert.Equal(t, 1001, code)
	assert.Equal(t, "idle timeout", reason)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond)

	eventuallyGauge(t, 1, func() float64 {
		return testutil.ToFloat64(m.WebSocketClosed.WithLabelValues("/ws", websocket.CloseReasonIdleTimeout))
	})
	assert.Equal(t, 0.0, testutil.ToFloat64(m.WebSocketActive.WithLabelValues("/ws")))
}

func TestWebSocket_BackendDisconnectClosesClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := wstest.Upgrade(w, r)
		if err != nil {
			return
		}
		// Read one message, then drop the TCP connection without any
		// closing handshake.
		_, _, _ = c.ReadMessage()
		c.Close()
	}))
	t.Cleanup(backend.Close)

	m := metrics.New()
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	c := dialOK(t, wsURL(gw, "/ws"), nil)
	require.NoError(t, c.WriteText("hello"))

	code, _ := expectClose(t, c, 5*time.Second)
	assert.Equal(t, 1014, code, "client is told the backend went away")
	eventuallyGauge(t, 1, func() float64 {
		return testutil.ToFloat64(m.WebSocketClosed.WithLabelValues("/ws", websocket.CloseReasonBackend))
	})
}

func TestWebSocket_ClientDisconnectClosesBackend(t *testing.T) {
	backendSaw := make(chan int, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := wstest.Upgrade(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			op, payload, err := c.ReadMessage()
			if err != nil {
				backendSaw <- 0
				return
			}
			if op == wstest.OpClose {
				code, _ := wstest.CloseCode(payload)
				backendSaw <- code
				return
			}
		}
	}))
	t.Cleanup(backend.Close)

	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, noRetryProxyConfig(), nil, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	c := dialOK(t, wsURL(gw, "/ws"), nil)
	require.NoError(t, c.WriteText("hi"))
	require.NoError(t, c.Close()) // abrupt: no Close frame

	select {
	case code := <-backendSaw:
		assert.Equal(t, 1001, code, "backend is sent a Close frame when the client vanishes")
	case <-time.After(5 * time.Second):
		t.Fatal("backend connection was never closed")
	}
}

func TestWebSocket_UpgradeIsNeverRetriedOrCached(t *testing.T) {
	var hits atomic.Int32
	var mode atomic.Value // "fail" or "plain"
	mode.Store("fail")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if mode.Load() == "fail" {
			http.Error(w, "upstream broke", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("not a websocket server"))
	}))
	t.Cleanup(backend.Close)

	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	cfg := noRetryProxyConfig()
	cfg.Retry.MaxRetries = 3
	// Cache enabled (the default) and retries on: neither may touch an
	// upgrade request.
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, cfg, nil, cache.New(st))
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	assert.Equal(t, http.StatusServiceUnavailable, dialStatus(t, wsURL(gw, "/ws"), nil))
	assert.Equal(t, int32(1), hits.Load(), "a failed handshake is not retried")

	mode.Store("plain")
	for i := 0; i < 2; i++ {
		_, resp, err := wstest.Dial(wsURL(gw, "/ws"), nil)
		require.ErrorIs(t, err, wstest.ErrBadHandshake)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("X-Cache"), "upgrade requests bypass the cache entirely")
	}
	assert.Equal(t, int32(3), hits.Load(), "every handshake reaches the backend")
}

func TestWebSocket_SurvivesProxyAndServerTimeouts(t *testing.T) {
	backend := echoBackend(t)
	cfg := noRetryProxyConfig()
	cfg.Timeout = config.Duration{Duration: 100 * time.Millisecond}
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, cfg, nil, nil)
	require.NoError(t, err)

	gw := httptest.NewUnstartedServer(router)
	gw.Config.ReadTimeout = 100 * time.Millisecond
	gw.Config.WriteTimeout = 100 * time.Millisecond
	gw.Start()
	t.Cleanup(gw.Close)

	c := dialOK(t, wsURL(gw, "/ws"), nil)
	for i := 0; i < 3; i++ {
		time.Sleep(250 * time.Millisecond) // well past every timeout above
		roundTrip(t, c, "still here")
	}
}

func TestWebSocket_CircuitBreakerCountsHandshakesNotConnections(t *testing.T) {
	var hits atomic.Int32
	var failing atomic.Bool
	echo := wstest.EchoHandler()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if failing.Load() {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		echo.ServeHTTP(w, r)
	}))
	t.Cleanup(backend.Close)

	m := metrics.New()
	router, err := NewRouter([]config.Route{{
		PathPrefix: "/ws",
		Target:     backend.URL,
		CircuitBreaker: config.RouteCircuitBreaker{
			FailureThreshold:         2,
			OpenDuration:             config.Duration{Duration: time.Minute},
			HalfOpenMaxRequests:      1,
			HalfOpenSuccessesToClose: 1,
			HalfOpenFailuresToReopen: 1,
		},
	}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)
	breaker := router.routes[0].breaker

	// Long-lived connections that end in every way — client close,
	// client vanishing — never count against the breaker.
	for i := 0; i < 3; i++ {
		c := dialOK(t, wsURL(gw, "/ws"), nil)
		roundTrip(t, c, "hello")
		time.Sleep(50 * time.Millisecond)
		if i%2 == 0 {
			require.NoError(t, c.WriteClose(1000, ""))
			expectClose(t, c, 5*time.Second)
		} else {
			require.NoError(t, c.Close())
		}
	}
	assert.Equal(t, circuitbreaker.Closed, breaker.State())

	// Failed handshakes do.
	failing.Store(true)
	assert.Equal(t, http.StatusBadGateway, dialStatus(t, wsURL(gw, "/ws"), nil))
	assert.Equal(t, http.StatusBadGateway, dialStatus(t, wsURL(gw, "/ws"), nil))
	assert.Equal(t, circuitbreaker.Open, breaker.State())

	before := hits.Load()
	assert.Equal(t, http.StatusServiceUnavailable, dialStatus(t, wsURL(gw, "/ws"), nil))
	assert.Equal(t, before, hits.Load(), "an open circuit fails the handshake without contacting the backend")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectCircuitOpen)))
}

func TestWebSocket_DisabledRoute(t *testing.T) {
	backend := echoBackend(t)
	disabled := false
	m := metrics.New()
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL, WebSocket: &disabled}}, noRetryProxyConfig(), m, nil)
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	assert.Equal(t, http.StatusForbidden, dialStatus(t, wsURL(gw, "/ws"), nil))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.WebSocketRejections.WithLabelValues("/ws", websocket.RejectDisabled)))
}

func TestWebSocket_ShutdownClosesConnectionsGracefully(t *testing.T) {
	backend := echoBackend(t)
	m := metrics.New()
	hub := websocket.NewHub(m)
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, noRetryProxyConfig(), m, nil, WithWebSocketHub(hub))
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	conns := []*wstest.Conn{dialOK(t, wsURL(gw, "/ws"), nil), dialOK(t, wsURL(gw, "/ws"), nil)}
	for _, c := range conns {
		roundTrip(t, c, "before shutdown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- hub.Shutdown(ctx) }()

	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c *wstest.Conn) {
			defer wg.Done()
			code, reason := expectClose(t, c, 5*time.Second)
			assert.Equal(t, 1001, code)
			assert.Equal(t, "server shutting down", reason)
		}(c)
	}
	wg.Wait()

	select {
	case err := <-shutdownErr:
		assert.NoError(t, err, "connections closed within the deadline")
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return")
	}
	assert.Equal(t, 0, hub.Active())
	assert.Equal(t, 2.0, testutil.ToFloat64(m.WebSocketClosed.WithLabelValues("/ws", websocket.CloseReasonShutdown)))

	// No new connections once shutdown has begun.
	assert.Equal(t, http.StatusServiceUnavailable, dialStatus(t, wsURL(gw, "/ws"), nil))
}

func TestWebSocket_ShutdownForcesStragglersAtDeadline(t *testing.T) {
	// A backend that never reads, so it never answers the Close frame.
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := wstest.Upgrade(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		<-release
	}))
	t.Cleanup(backend.Close)
	t.Cleanup(func() { close(release) })

	hub := websocket.NewHub(nil)
	router, err := NewRouter([]config.Route{{PathPrefix: "/ws", Target: backend.URL}}, noRetryProxyConfig(), nil, nil, WithWebSocketHub(hub))
	require.NoError(t, err)
	gw := gatewayFor(t, router)

	c := dialOK(t, wsURL(gw, "/ws"), nil) // never answers the Close either

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = hub.Shutdown(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 3*time.Second)
	assert.Equal(t, 0, hub.Active())

	// The client still got its Close frame before being cut off.
	code, _ := expectClose(t, c, 5*time.Second)
	assert.Equal(t, 1001, code)
}

func TestWebSocket_PlainHTTPOnWebSocketRouteUnchanged(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "plain:"+r.Header.Get("Upgrade"))
	}))
	t.Cleanup(backend.Close)

	st := store.NewMemoryStore()
	t.Cleanup(func() { st.Close() })
	router, err := NewRouter([]config.Route{{
		PathPrefix:       "/ws",
		Target:           backend.URL,
		Cache:            config.RouteCache{TTL: config.Duration{Duration: time.Minute}},
		WSAllowedOrigins: []string{"https://only.example.com"},
	}}, noRetryProxyConfig(), nil, cache.New(st))
	require.NoError(t, err)

	get := func(header http.Header) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/ws/data", nil)
		req.Header = header
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Ordinary GETs are still proxied and cached as before, and the
	// WebSocket origin list doesn't apply to them.
	rec := get(http.Header{"Origin": {"https://elsewhere.example.com"}})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "MISS", rec.Header().Get("X-Cache"))
	rec = get(http.Header{"Origin": {"https://elsewhere.example.com"}})
	assert.Equal(t, "HIT", rec.Header().Get("X-Cache"))
	assert.Equal(t, int32(1), hits.Load())

	// An Upgrade to some other protocol isn't a WebSocket handshake and
	// takes the ordinary HTTP path.
	rec = get(http.Header{"Connection": {"Upgrade"}, "Upgrade": {"h2c"}, "X-Bypass-Cache": {"1"}})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(2), hits.Load())
}
