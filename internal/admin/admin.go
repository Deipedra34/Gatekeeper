// Package admin serves Gatekeeper's admin API: read-only views of the
// running gateway (status, redacted config, routes, backends, rate limit
// state, cache stats) and operator actions (reload, cache purge, rate
// limit reset, backend drain/enable, circuit breaker reset).
//
// It runs on its own listener, never on the proxy's, so no backend route
// can shadow it and no public client can reach it. Every request is
// authenticated — a bearer token checked against SHA-256 hashes, or a
// verified client certificate — optionally restricted to source CIDRs,
// rate limited on failed attempts per source IP, traced, counted in
// /metrics, and written to an audit log.
package admin

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/server"
	"gatekeeper/internal/tracing"
)

// Options configures New.
type Options struct {
	// Config is the admin section, as loaded at startup.
	Config config.AdminConfig
	// Gateway is the gateway being administered.
	Gateway *gateway.Gateway
	// Reload applies the config file exactly as SIGHUP does. Nil means
	// Gateway.Reload.
	Reload func() error
	// Metrics receives the admin request and auth failure counts. May be
	// nil.
	Metrics *metrics.Metrics
	// Logger receives startup warnings and, without admin.audit_log, the
	// audit log. Nil means log.Default().
	Logger *log.Logger
}

// Server is the admin API's listener and handler.
type Server struct {
	cfg     config.AdminConfig
	gw      *gateway.Gateway
	reload  func() error
	metrics *metrics.Metrics
	logger  *log.Logger

	auth    *authenticator
	audit   *auditLog
	mux     *http.ServeMux
	srv     *server.Server
	started time.Time
}

// New builds the admin server. With admin TLS it loads the certificate
// and client CA bundle now, failing on a broken setup instead of on the
// first handshake.
func New(opts Options) (*Server, error) {
	if !opts.Config.Enabled {
		return nil, errors.New("admin: admin.enabled is false")
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	if opts.Reload == nil {
		opts.Reload = opts.Gateway.Reload
	}
	auth, err := newAuthenticator(opts.Config)
	if err != nil {
		return nil, err
	}
	audit, err := newAuditLog(opts.Config.AuditLog, opts.Logger)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: opts.Config, gw: opts.Gateway, reload: opts.Reload, metrics: opts.Metrics, logger: opts.Logger,
		auth: auth, audit: audit, mux: http.NewServeMux(), started: time.Now(),
	}
	s.routes()

	// The admin listener is a server.Server of its own, so TLS, client
	// certificate verification, and certificate hot reload work exactly
	// as on the main listener. TLS metrics stay the main listener's.
	listener := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:   opts.Config.Listen,
			ReadTimeout:  opts.Config.ReadTimeout,
			WriteTimeout: opts.Config.WriteTimeout,
			IdleTimeout:  opts.Config.IdleTimeout,
		},
		TLS: opts.Config.TLS,
	}
	if s.srv, err = server.New(listener, s, nil, opts.Logger); err != nil {
		audit.Close()
		return nil, err
	}

	if host, _, _ := net.SplitHostPort(opts.Config.Listen); !opts.Config.TLS.Enabled && !isLoopback(host) {
		opts.Logger.Printf("admin: WARNING: admin API on %s without TLS; tokens cross the network in plain text", opts.Config.Listen)
	}
	return s, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Listen opens the admin listener, so a port already in use fails
// startup synchronously.
func (s *Server) Listen() (net.Listener, error) {
	return net.Listen("tcp", s.cfg.Listen)
}

// Serve serves the admin API on ln until Shutdown, then returns nil.
func (s *Server) Serve(ln net.Listener) error {
	return s.srv.Serve(ln, nil)
}

// TLSEnabled reports whether the admin API is served over HTTPS.
func (s *Server) TLSEnabled() bool { return s.srv.TLSEnabled() }

// ReloadCertificates re-reads the admin certificate and key (on SIGHUP).
func (s *Server) ReloadCertificates() error { return s.srv.ReloadCertificates("", "") }

// Shutdown stops the admin listener, waiting for in-flight requests up
// to ctx's deadline, then closes the audit log.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	return errors.Join(err, s.audit.Close())
}

// ServeHTTP runs every admin request through the same steps: a tracing
// span, the size limit, authentication, the endpoint, then metrics and
// an audit record — whatever the outcome.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	_, pattern := s.mux.Handler(r)
	route := "unmatched"
	if _, path, ok := strings.Cut(pattern, " "); ok {
		route = path
	}
	routeFor := func(*http.Request) (string, bool) { return route, true }
	s.gw.Tracer().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serve(w, r, start, pattern)
	}), routeFor).ServeHTTP(w, r)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, start time.Time, pattern string) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h := rec.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if s.cfg.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(rec, r.Body, s.cfg.MaxBodyBytes)
	}

	ip := sourceIP(r)
	d := s.auth.authenticate(r, ip)
	span := trace.SpanFromContext(r.Context())
	result, reason := "success", ""
	switch {
	case d.status != 0:
		result, reason = "denied", d.reason
		if s.metrics != nil {
			s.metrics.AdminAuthFailures.WithLabelValues(d.reason).Inc()
		}
		writeDenied(rec, d)
	case pattern == "":
		s.unmatched(rec, r)
	default:
		span.SetAttributes(tracing.AttrAdminIdentity.String(d.identity))
		s.mux.ServeHTTP(rec, r)
	}
	if result == "success" && rec.status >= 400 {
		result, reason = "error", rec.errCode
	}
	span.SetAttributes(tracing.AttrAdminResult.String(result))

	endpoint := pattern
	if endpoint == "" {
		endpoint = "unmatched"
	}
	if s.metrics != nil {
		s.metrics.AdminRequests.WithLabelValues(endpoint, strconv.Itoa(rec.status)).Inc()
	}
	traceID := ""
	if sc := span.SpanContext(); sc.HasTraceID() {
		traceID = sc.TraceID().String()
	}
	s.audit.write(auditRecord{
		Time:       auditTime(start),
		Event:      "admin_request",
		SourceIP:   ip.String(),
		Identity:   d.identity,
		Method:     r.Method,
		Path:       auditPath(r.URL.Path, pattern != ""),
		Endpoint:   endpoint,
		Status:     rec.status,
		Result:     result,
		Reason:     reason,
		DryRun:     dryRun(r),
		DurationMS: float64(time.Since(start).Microseconds()) / 1000,
		TraceID:    traceID,
	})
}

func writeDenied(w http.ResponseWriter, d decision) {
	switch d.status {
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer realm="gatekeeper-admin"`)
		writeError(w, d.status, d.code, "authentication required: send Authorization: Bearer <token>, or a client certificate the admin API accepts")
	case http.StatusForbidden:
		writeError(w, d.status, d.code, "source address is not in admin.allowed_cidrs")
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", strconv.Itoa(int(d.retryAfter.Seconds())+1))
		writeError(w, d.status, d.code, "too many failed authentication attempts from this address; try again later")
	}
}

// unmatched answers an authenticated request no endpoint matched: 405
// with an Allow header if the path exists under another method, 404
// otherwise.
func (s *Server) unmatched(w http.ResponseWriter, r *http.Request) {
	var allowed []string
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, p := s.mux.Handler(probe); p != "" {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeError(w, http.StatusMethodNotAllowed, codeMethod, r.Method+" is not supported here; use "+strings.Join(allowed, " or "))
		return
	}
	writeError(w, http.StatusNotFound, codeNotFound, "no admin endpoint at "+auditPath(r.URL.Path, false))
}

// statusRecorder captures the response status, and the error code of an
// error response, for metrics and the audit log.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	errCode     string
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}
