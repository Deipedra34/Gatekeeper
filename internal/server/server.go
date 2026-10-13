// Package server runs Gatekeeper's listeners: the main listener — plain
// HTTP, or HTTPS with optional client certificate verification (mTLS) —
// and, when configured, a plain-HTTP listener that redirects everything
// to HTTPS. It owns the TLS-specific pieces: the hot-reloadable server
// certificate, the client CA pool, HSTS, and the TLS handshake metrics.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
)

// Server is Gatekeeper's front door.
type Server struct {
	cfg    config.TLSConfig
	logger *log.Logger
	main   *http.Server
	redir  *http.Server  // nil unless tls.redirect_http_port is set
	certs  *CertReloader // nil when TLS is off
	stop   context.CancelFunc
	stopMu sync.Mutex
}

// New builds the server for cfg, serving handler. With TLS enabled it
// loads the certificate and client CA bundle up front and fails with a
// clear error if either is missing or invalid, so a broken TLS setup
// stops startup instead of surfacing on the first handshake. m may be
// nil.
func New(cfg *config.Config, handler http.Handler, m *metrics.Metrics, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{cfg: cfg.TLS, logger: logger}

	if cfg.TLS.Enabled && cfg.TLS.HSTS.Enabled {
		handler = hsts(cfg.TLS.HSTS.HeaderValue(), handler)
	}
	s.main = &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout.Duration,
		WriteTimeout: cfg.Server.WriteTimeout.Duration,
		IdleTimeout:  cfg.Server.IdleTimeout.Duration,
	}
	if !cfg.TLS.Enabled {
		return s, nil
	}

	certs, err := NewCertReloader(cfg.TLS.CertFile, cfg.TLS.KeyFile, m, logger)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := newTLSConfig(cfg.TLS, certs, m)
	if err != nil {
		return nil, err
	}
	s.certs = certs
	s.main.TLSConfig = tlsCfg
	// net/http reports failed handshakes only through ErrorLog; tap it to
	// count them by reason, then log them as before.
	s.main.ErrorLog = log.New(&handshakeErrorTap{metrics: m, out: logger}, "", 0)

	if cfg.TLS.RedirectHTTPPort != 0 {
		host, httpsPort, err := net.SplitHostPort(cfg.Server.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("server.listen_addr %q: %w", cfg.Server.ListenAddr, err)
		}
		s.redir = &http.Server{
			Addr:         net.JoinHostPort(host, strconv.Itoa(cfg.TLS.RedirectHTTPPort)),
			Handler:      redirectToHTTPS(httpsPort),
			ReadTimeout:  cfg.Server.ReadTimeout.Duration,
			WriteTimeout: cfg.Server.WriteTimeout.Duration,
			IdleTimeout:  cfg.Server.IdleTimeout.Duration,
		}
	}
	return s, nil
}

// newTLSConfig builds the listener's tls.Config. Certificates are served
// through GetCertificate so they can be swapped without a restart.
// Client certificates, when requested, are verified by crypto/tls itself
// against the client CA pool; the auth middleware only ever trusts a
// certificate that verification produced a chain for.
func newTLSConfig(cfg config.TLSConfig, certs *CertReloader, m *metrics.Metrics) (*tls.Config, error) {
	suites, err := cfg.CipherSuiteIDs()
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{
		MinVersion:     cfg.MinTLSVersion(),
		CipherSuites:   suites,
		GetCertificate: certs.GetCertificate,
		ClientAuth:     cfg.ClientAuthType(),
	}
	if cfg.ClientCAFile != "" {
		pool, err := LoadCertPool(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.client_ca_file: %w", err)
		}
		tc.ClientCAs = pool
	}
	if m != nil {
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			m.TLSHandshakes.WithLabelValues(tls.VersionName(cs.Version)).Inc()
			if len(cs.VerifiedChains) > 0 {
				m.MTLSVerifications.WithLabelValues("success", "verified").Inc()
			}
			return nil
		}
	}
	return tc, nil
}

// LoadCertPool reads a PEM bundle of CA certificates.
func LoadCertPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("CA bundle %s contains no valid PEM certificates", path)
	}
	return pool, nil
}

// ListenAndServe opens the configured listeners and serves until
// Shutdown. Listener errors (e.g. a port already in use) are returned
// before anything is served.
func (s *Server) ListenAndServe() error {
	mainLn, err := net.Listen("tcp", s.main.Addr)
	if err != nil {
		return err
	}
	var redirLn net.Listener
	if s.redir != nil {
		if redirLn, err = net.Listen("tcp", s.redir.Addr); err != nil {
			mainLn.Close()
			return err
		}
	}
	return s.Serve(mainLn, redirLn)
}

// Serve serves on already-open listeners: mainLn for the gateway itself
// and, if a redirect listener is configured, redirLn for it. It blocks
// until Shutdown, returning nil in that case.
func (s *Server) Serve(mainLn, redirLn net.Listener) error {
	ctx, cancel := context.WithCancel(context.Background())
	s.stopMu.Lock()
	s.stop = cancel
	s.stopMu.Unlock()
	defer cancel()

	if s.certs != nil && s.cfg.ReloadInterval.Duration > 0 {
		go s.certs.watch(ctx, s.cfg.ReloadInterval.Duration)
	}
	if s.redir != nil && redirLn != nil {
		go func() {
			if err := s.redir.Serve(redirLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Printf("server: HTTP redirect listener stopped: %v", err)
			}
		}()
	}

	var err error
	if s.main.TLSConfig != nil {
		err = s.main.ServeTLS(mainLn, "", "")
	} else {
		err = s.main.Serve(mainLn)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting connections on every listener and waits for
// in-flight requests, up to ctx's deadline. Hijacked (WebSocket)
// connections are not covered; see gateway.ShutdownWebSockets.
func (s *Server) Shutdown(ctx context.Context) error {
	s.stopMu.Lock()
	if s.stop != nil {
		s.stop()
	}
	s.stopMu.Unlock()

	var redirErr error
	if s.redir != nil {
		redirErr = s.redir.Shutdown(ctx)
	}
	return errors.Join(s.main.Shutdown(ctx), redirErr)
}

// TLSEnabled reports whether the main listener serves HTTPS.
func (s *Server) TLSEnabled() bool { return s.certs != nil }

// ReloadCertificates reloads the server certificate — from certFile and
// keyFile if they're non-empty and differ from the current paths,
// otherwise from the current paths. It's a no-op without TLS. On failure
// the previous certificate stays in use.
func (s *Server) ReloadCertificates(certFile, keyFile string) error {
	if s.certs == nil {
		return nil
	}
	if certFile == "" || keyFile == "" {
		return s.certs.Reload()
	}
	return s.certs.SetFiles(certFile, keyFile)
}

// Certificates returns the certificate reloader, or nil without TLS.
func (s *Server) Certificates() *CertReloader { return s.certs }

// hsts adds a Strict-Transport-Security header to responses served over
// TLS.
func hsts(value string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", value)
		}
		next.ServeHTTP(w, r)
	})
}

// redirectToHTTPS answers every request with a 308 to the same host,
// path, and query on HTTPS (on httpsPort, omitted when it's 443). 308
// keeps the method and body, so a POST stays a POST.
func redirectToHTTPS(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if host == "" {
			http.Error(w, "missing Host header", http.StatusBadRequest)
			return
		}
		authority := host
		if httpsPort != "443" {
			authority = net.JoinHostPort(host, httpsPort)
		} else if strings.Contains(host, ":") {
			authority = "[" + host + "]"
		}
		http.Redirect(w, r, "https://"+authority+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

// handshakeErrorTap receives net/http's error log. Lines reporting a
// failed TLS handshake are counted by reason; every line is then written
// to out unchanged.
type handshakeErrorTap struct {
	metrics *metrics.Metrics
	out     *log.Logger
}

const handshakeErrorPrefix = "http: TLS handshake error from "

func (t *handshakeErrorTap) Write(p []byte) (int, error) {
	line := string(p)
	if t.metrics != nil && strings.HasPrefix(line, handshakeErrorPrefix) {
		reason, mtlsReason := classifyHandshakeError(line)
		t.metrics.TLSHandshakeErrors.WithLabelValues(reason).Inc()
		if mtlsReason != "" {
			t.metrics.MTLSVerifications.WithLabelValues("failure", mtlsReason).Inc()
		}
	}
	t.out.Print(strings.TrimSuffix(line, "\n"))
	return len(p), nil
}

// classifyHandshakeError maps a crypto/tls handshake error message to a
// handshake error reason and, for client certificate failures, an mTLS
// failure reason. crypto/tls only exposes these errors as text through
// net/http, so this matches on its (long-stable) messages; anything
// unrecognised is "other".
func classifyHandshakeError(msg string) (reason, mtlsReason string) {
	switch {
	case strings.Contains(msg, "client didn't provide a certificate"):
		return "client_certificate", "no_certificate"
	case strings.Contains(msg, "failed to verify certificate"),
		strings.Contains(msg, "client certificate"):
		switch {
		case strings.Contains(msg, "unknown authority"):
			return "client_certificate", "unknown_authority"
		case strings.Contains(msg, "expired or is not yet valid"):
			return "client_certificate", "expired"
		default:
			return "client_certificate", "invalid"
		}
	case strings.Contains(msg, "unsupported versions"), strings.Contains(msg, "protocol version"):
		return "protocol_version", ""
	case strings.Contains(msg, "no cipher suite"):
		return "cipher_suite", ""
	default:
		return "other", ""
	}
}
