package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/config"
	"gatekeeper/internal/lb"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket"
)

// wsSettings is a route's WebSocket configuration, compiled from
// config.Route.
type wsSettings struct {
	enabled        bool
	idleTimeout    time.Duration
	limits         websocket.Limits
	allowedOrigins []string
}

func newWSSettings(rt config.Route) wsSettings {
	return wsSettings{
		enabled:     rt.WebSocketEnabled(),
		idleTimeout: rt.EffectiveWSIdleTimeout(),
		limits: websocket.Limits{
			MaxConnections:          rt.WSMaxConnections,
			MaxConnectionsPerClient: rt.WSMaxConnectionsPerClient,
		},
		allowedOrigins: rt.WSAllowedOrigins,
	}
}

// originAllowed reports whether a handshake carrying origin may proceed.
// With no allow-list every origin is accepted; with one, a request
// without an Origin header (i.e. not from a browser, which always sends
// one on a WebSocket handshake) is still accepted, since a non-browser
// client could put any Origin it liked there anyway.
func (s wsSettings) originAllowed(origin string) bool {
	if len(s.allowedOrigins) == 0 || origin == "" {
		return true
	}
	for _, a := range s.allowedOrigins {
		if a == "*" || strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

// serveWebSocket proxies a WebSocket upgrade request. By the time it runs
// the request has already been through the whole middleware chain (CORS,
// auth, rate limiting — one token per handshake), so what's left is
// route-level policy, the backend handshake, and then relaying frames
// until either side goes away.
//
// The backend handshake is a single attempt — upgrades are never retried
// — bounded by proxy.timeout. Once the backend answers 101, every
// deadline is cleared on both connections: neither proxy.timeout nor the
// server's read/write timeouts apply to an established connection, only
// the route's ws_idle_timeout does. The circuit breaker sees the
// handshake outcome only (a dial failure, timeout, or 5xx counts as a
// failure); how long the connection then lives, and how it ends, never
// reaches it.
//
// With tracing on, the upgrade gets a websocket.handshake span (policy
// checks, backend dial, and the 101) and, once established, a
// websocket.connection span lasting until the tunnel closes.
func (r *Router) serveWebSocket(w http.ResponseWriter, req *http.Request, rt *route) {
	hsCtx, hsSpan := tracing.Start(req.Context(), tracing.SpanWebSocketHandshake,
		trace.WithAttributes(tracing.AttrHTTPRoute.String(rt.label)))
	hsEnded := false
	endHandshake := func() {
		if !hsEnded {
			hsSpan.End()
			hsEnded = true
		}
	}
	defer endHandshake()

	reject := func(reason string, status int, msg string) {
		websocket.RecordRejection(r.metrics, rt.label, reason)
		hsSpan.SetAttributes(tracing.AttrWSRejectReason.String(reason), tracing.AttrHTTPStatus.Int(status))
		tracing.Fail(hsSpan, "websocket handshake rejected: "+reason)
		http.Error(w, msg, status)
	}

	if !rt.ws.enabled {
		reject(websocket.RejectDisabled, http.StatusForbidden, "websocket connections are not enabled for this route")
		return
	}
	if !rt.ws.originAllowed(req.Header.Get("Origin")) {
		reject(websocket.RejectOrigin, http.StatusForbidden, "websocket origin not allowed")
		return
	}

	slot, err := r.hub.Reserve(rt.label, wsClientKey(req), rt.ws.limits)
	switch {
	case errors.Is(err, websocket.ErrClientFull):
		reject(websocket.RejectMaxConnections, http.StatusTooManyRequests, "too many websocket connections for this client")
		return
	case errors.Is(err, websocket.ErrRouteFull):
		reject(websocket.RejectMaxConnections, http.StatusServiceUnavailable, "websocket connection limit reached for this route")
		return
	case err != nil:
		reject(websocket.RejectShuttingDown, http.StatusServiceUnavailable, "gateway is shutting down")
		return
	}
	// Serve releases the slot itself; this covers every early return.
	defer slot.Release()

	// The connection is balanced once, here, and stays on this backend
	// for its whole lifetime.
	b, err := pickWebSocketBackend(rt, req)
	switch {
	case errors.Is(err, errCircuitOpen):
		if r.metrics != nil {
			r.metrics.CircuitBreakerRejections.WithLabelValues(rt.label).Inc()
		}
		reject(websocket.RejectCircuitOpen, http.StatusServiceUnavailable, "circuit breaker open: backend temporarily unavailable")
		return
	case err != nil:
		reject(websocket.RejectNoHealthy, http.StatusServiceUnavailable, "no healthy backend available")
		return
	}
	hsSpan.SetAttributes(tracing.AttrBackend.String(b.Label()))
	release := b.Acquire()
	defer release()

	backendConn, backendReader, resp, err := dialBackendWebSocket(hsCtx, req, rt, b)
	if err != nil {
		r.recordHandshake(rt, b, false)
		log.Printf("proxy: websocket backend %s unreachable for %s: %v", b.Label(), req.URL.Path, err)
		reject(websocket.RejectBackend, http.StatusBadGateway, "backend service unavailable")
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The backend declined the upgrade; relay its answer as-is. Only
		// a 5xx says anything about the backend's health.
		r.recordHandshake(rt, b, resp.StatusCode < 500)
		websocket.RecordRejection(r.metrics, rt.label, websocket.RejectBackend)
		hsSpan.SetAttributes(tracing.AttrWSRejectReason.String(websocket.RejectBackend), tracing.AttrHTTPStatus.Int(resp.StatusCode))
		tracing.Fail(hsSpan, "backend refused the upgrade")
		forwardResponse(w, resp)
		_ = backendConn.Close()
		return
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		r.recordHandshake(rt, b, false)
		_ = backendConn.Close()
		log.Printf("proxy: websocket backend %s switched to unexpected protocol %q", b.Label(), resp.Header.Get("Upgrade"))
		reject(websocket.RejectBackend, http.StatusBadGateway, "backend service unavailable")
		return
	}
	r.recordHandshake(rt, b, true)

	clientConn, clientBuf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		_ = backendConn.Close()
		log.Printf("proxy: websocket upgrade for %s: cannot hijack client connection: %v", req.URL.Path, err)
		tracing.Fail(hsSpan, "cannot hijack client connection")
		http.Error(w, "websocket upgrade not supported", http.StatusInternalServerError)
		return
	}
	// The server armed read/write deadlines for an ordinary request;
	// they must not cut a long-lived connection short.
	_ = clientConn.SetDeadline(time.Time{})

	if err := writeSwitchingProtocols(clientBuf.Writer, w.Header(), resp.Header); err != nil {
		tracing.Fail(hsSpan, "writing 101 to client failed")
		_ = clientConn.Close()
		_ = backendConn.Close()
		return
	}
	hsSpan.SetAttributes(tracing.AttrHTTPStatus.Int(http.StatusSwitchingProtocols))
	endHandshake()

	_, connSpan := tracing.Start(req.Context(), tracing.SpanWebSocketConnection,
		trace.WithAttributes(tracing.AttrHTTPRoute.String(rt.label), tracing.AttrBackend.String(b.Label())))
	// b's context ends if a reload removes the backend and its drain
	// timeout runs out; the tunnel then closes with 1001.
	reason := r.hub.Serve(b.Context(), slot,
		websocket.Endpoint{Conn: clientConn, Reader: clientBuf.Reader},
		websocket.Endpoint{Conn: backendConn, Reader: backendReader},
		rt.ws.idleTimeout,
	)
	connSpan.SetAttributes(tracing.AttrWSCloseReason.String(reason))
	connSpan.End()
}

// pickWebSocketBackend balances a WebSocket handshake onto one of rt's
// backends, skipping any whose circuit breaker refuses it.
func pickWebSocketBackend(rt *route, req *http.Request) (*lb.Backend, error) {
	refused := map[*lb.Backend]bool{}
	for {
		b, err := rt.pool.Pick(req, nil, func(b *lb.Backend) bool { return refused[b] })
		switch {
		case errors.Is(err, lb.ErrAllCircuitsOpen):
			return nil, errCircuitOpen
		case err != nil:
			return nil, errNoHealthyBackend
		}
		if cb := b.Breaker(); cb == nil || cb.Allow() {
			return b, nil
		}
		refused[b] = true
	}
}

// recordHandshake reports a backend handshake outcome to b's circuit
// breaker (whose Allow this handshake already passed), its passive
// health check, and the per-route outcome metric. Only the handshake
// counts — how long the connection lives, and how it ends, doesn't.
func (r *Router) recordHandshake(rt *route, b *lb.Backend, success bool) {
	if cb := b.Breaker(); cb != nil {
		cb.Report(success)
	}
	rt.pool.Report(b, success)
	if r.metrics != nil {
		outcome := "failure"
		if success {
			outcome = "success"
		}
		r.metrics.ProxyOutcomes.WithLabelValues(rt.label, outcome).Inc()
	}
}

// wsClientKey identifies the client for per-client connection limits:
// whatever the rate limiter identified it as, if the request came
// through the rate-limit middleware, otherwise its remote IP.
func wsClientKey(req *http.Request) string {
	if hs, ok := websocket.HandshakeFrom(req.Context()); ok {
		if client, ok := hs.Client(); ok {
			return client
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// dialBackendWebSocket connects to backend b of rt and performs the upgrade
// handshake, returning the connection, a reader that may already hold
// frame bytes sent right after the 101, and the backend's response.
// For a 101 the connection's deadlines are cleared; for anything else
// the handshake deadline is left in place to bound reading the body.
//
// ctx carries the handshake span, whose trace context is sent to the
// backend in the upgrade request.
func dialBackendWebSocket(ctx context.Context, req *http.Request, rt *route, b *lb.Backend) (net.Conn, *bufio.Reader, *http.Response, error) {
	if rt.handshakeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, rt.handshakeTimeout)
		defer cancel()
	}

	conn, err := dialTarget(ctx, b.Target(), b.Settings().TLSConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// Abort the handshake promptly if the client goes away mid-way.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })

	out := outgoingUpgradeRequest(req, b.Target())
	tracing.Inject(ctx, out.Header)
	if err := out.Write(conn); err != nil {
		stop()
		_ = conn.Close()
		return nil, nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, out)
	if !stop() && err == nil {
		err = context.Cause(ctx)
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		_ = conn.SetDeadline(time.Time{})
	}
	return conn, br, resp, nil
}

// dialTarget opens a TCP (or, for an https/wss target, TLS) connection
// to target's host. backendTLS, if non-nil, is the route's backend_tls
// config (custom CA, client certificate, server name); otherwise TLS
// uses Go's defaults, verifying against the system trust store.
func dialTarget(ctx context.Context, target *url.URL, backendTLS *tls.Config) (net.Conn, error) {
	useTLS := target.Scheme == "https" || target.Scheme == "wss"
	addr := target.Host
	if target.Port() == "" {
		port := "80"
		if useTLS {
			port = "443"
		}
		addr = net.JoinHostPort(target.Hostname(), port)
	}
	if useTLS {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if backendTLS != nil {
			tc = backendTLS.Clone()
		}
		if tc.ServerName == "" {
			tc.ServerName = target.Hostname()
		}
		// The upgrade is an HTTP/1.1 exchange; never negotiate h2.
		tc.NextProtos = []string{"http/1.1"}
		d := &tls.Dialer{Config: tc}
		return d.DialContext(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// hopHeaders are the hop-by-hop headers (RFC 9110 section 7.6.1) that
// must not be forwarded as-is. Connection and Upgrade are re-added for
// the upgrade itself.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

// outgoingUpgradeRequest builds the handshake sent to the backend,
// rewritten the same way the HTTP path's ReverseProxy rewrites requests:
// target scheme/host/base path, the incoming Host header kept, and the
// client's address appended to X-Forwarded-For. Every end-to-end header
// — Sec-WebSocket-*, Origin, credentials — goes through unchanged.
func outgoingUpgradeRequest(in *http.Request, target *url.URL) *http.Request {
	out := in.Clone(in.Context())
	out.RequestURI = ""
	out.Body = nil
	out.GetBody = nil
	out.ContentLength = 0
	out.Close = false

	(&httputil.ProxyRequest{In: in, Out: out}).SetURL(target)
	out.Host = in.Host

	upgrade := in.Header.Get("Upgrade")
	removeHopHeaders(out.Header)
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", upgrade)
	if _, ok := out.Header["User-Agent"]; !ok {
		// Stop Request.Write from adding Go's default User-Agent.
		out.Header.Set("User-Agent", "")
	}
	if ip, _, err := net.SplitHostPort(in.RemoteAddr); err == nil {
		if prior := in.Header.Values("X-Forwarded-For"); len(prior) > 0 {
			ip = strings.Join(prior, ", ") + ", " + ip
		}
		out.Header.Set("X-Forwarded-For", ip)
	}
	return out
}

// forwardResponse relays a backend's non-101 answer to an upgrade request
// back to the client.
func forwardResponse(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	dst := w.Header()
	for k, v := range resp.Header {
		dst[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// writeSwitchingProtocols writes the 101 response to the hijacked client
// connection: the headers the middleware chain set (rate-limit, CORS)
// merged with the backend's handshake headers, which take precedence.
func writeSwitchingProtocols(bw *bufio.Writer, chainHeader, backendHeader http.Header) error {
	h := chainHeader.Clone()
	for k, v := range backendHeader {
		h[k] = v
	}
	if _, err := bw.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := h.Write(bw); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}
