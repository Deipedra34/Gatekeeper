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

	"gatekeeper/internal/config"
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
func (r *Router) serveWebSocket(w http.ResponseWriter, req *http.Request, rt *route) {
	reject := func(reason string, status int, msg string) {
		websocket.RecordRejection(r.metrics, rt.label, reason)
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

	if rt.breaker != nil && !rt.breaker.Allow() {
		if r.metrics != nil {
			r.metrics.CircuitBreakerRejections.WithLabelValues(rt.label).Inc()
		}
		reject(websocket.RejectCircuitOpen, http.StatusServiceUnavailable, "circuit breaker open: backend temporarily unavailable")
		return
	}

	backendConn, backendReader, resp, err := dialBackendWebSocket(req, rt)
	if err != nil {
		r.recordHandshake(rt, false)
		log.Printf("proxy: websocket backend %s unreachable for %s: %v", rt.target, req.URL.Path, err)
		reject(websocket.RejectBackend, http.StatusBadGateway, "backend service unavailable")
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The backend declined the upgrade; relay its answer as-is. Only
		// a 5xx says anything about the backend's health.
		r.recordHandshake(rt, resp.StatusCode < 500)
		websocket.RecordRejection(r.metrics, rt.label, websocket.RejectBackend)
		forwardResponse(w, resp)
		_ = backendConn.Close()
		return
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		r.recordHandshake(rt, false)
		_ = backendConn.Close()
		log.Printf("proxy: websocket backend %s switched to unexpected protocol %q", rt.target, resp.Header.Get("Upgrade"))
		reject(websocket.RejectBackend, http.StatusBadGateway, "backend service unavailable")
		return
	}
	r.recordHandshake(rt, true)

	clientConn, clientBuf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		_ = backendConn.Close()
		log.Printf("proxy: websocket upgrade for %s: cannot hijack client connection: %v", req.URL.Path, err)
		http.Error(w, "websocket upgrade not supported", http.StatusInternalServerError)
		return
	}
	// The server armed read/write deadlines for an ordinary request;
	// they must not cut a long-lived connection short.
	_ = clientConn.SetDeadline(time.Time{})

	if err := writeSwitchingProtocols(clientBuf.Writer, w.Header(), resp.Header); err != nil {
		_ = clientConn.Close()
		_ = backendConn.Close()
		return
	}

	r.hub.Serve(slot,
		websocket.Endpoint{Conn: clientConn, Reader: clientBuf.Reader},
		websocket.Endpoint{Conn: backendConn, Reader: backendReader},
		rt.ws.idleTimeout,
	)
}

// recordHandshake reports a backend handshake outcome to the circuit
// breaker (whose Allow this handshake already passed) and to the
// per-route outcome metric.
func (r *Router) recordHandshake(rt *route, success bool) {
	if rt.breaker != nil {
		rt.breaker.Report(success)
	}
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

// dialBackendWebSocket connects to rt's backend and performs the upgrade
// handshake, returning the connection, a reader that may already hold
// frame bytes sent right after the 101, and the backend's response.
// For a 101 the connection's deadlines are cleared; for anything else
// the handshake deadline is left in place to bound reading the body.
func dialBackendWebSocket(req *http.Request, rt *route) (net.Conn, *bufio.Reader, *http.Response, error) {
	ctx := req.Context()
	if rt.handshakeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, rt.handshakeTimeout)
		defer cancel()
	}

	conn, err := dialTarget(ctx, rt.target)
	if err != nil {
		return nil, nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// Abort the handshake promptly if the client goes away mid-way.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })

	out := outgoingUpgradeRequest(req, rt.target)
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
// to target's host.
func dialTarget(ctx context.Context, target *url.URL) (net.Conn, error) {
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
		d := &tls.Dialer{Config: &tls.Config{ServerName: target.Hostname()}}
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
