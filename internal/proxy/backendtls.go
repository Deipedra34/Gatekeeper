package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"gatekeeper/internal/config"
)

// newBackendTLSConfig builds the TLS client config for one backend
// (target, on the route labelled route), or returns nil if bt isn't
// enabled — in which case an https:// target keeps using Go's defaults
// (system trust store), exactly as before. Files are read here, so a
// missing or malformed one fails startup or the reload rather than the
// first request.
func newBackendTLSConfig(route, target string, bt config.BackendTLSConfig) (*tls.Config, error) {
	if !bt.Enabled {
		return nil, nil
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         bt.ServerName,
		InsecureSkipVerify: bt.InsecureSkipVerify, //nolint:gosec // opt-in, warned about below
	}
	if bt.CAFile != "" {
		pemBytes, err := os.ReadFile(bt.CAFile)
		if err != nil {
			return nil, fmt.Errorf("proxy: route %s: backend_tls.ca_file: %w", route, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("proxy: route %s: backend_tls.ca_file %s contains no valid PEM certificates", route, bt.CAFile)
		}
		tc.RootCAs = pool
	}
	if bt.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(bt.ClientCertFile, bt.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("proxy: route %s: backend_tls client certificate %s / key %s: %w",
				route, bt.ClientCertFile, bt.ClientKeyFile, err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	if bt.InsecureSkipVerify {
		log.Printf("proxy: WARNING: route %s: backend_tls.insecure_skip_verify is enabled — the backend's certificate is NOT verified "+
			"and traffic to %s can be intercepted. Use this for local development only.", route, target)
	}
	return tc, nil
}

// newBackendTransport returns an http.Transport with Go's default
// settings (connection pooling, timeouts, proxy-from-environment) but
// the route's backend TLS config.
func newBackendTransport(tc *tls.Config) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tc
	return t
}
