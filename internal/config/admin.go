package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Defaults for the admin section.
const (
	DefaultAdminListen          = "127.0.0.1:9090"
	DefaultAdminMaxBodyBytes    = 64 << 10
	DefaultAdminMaxAuthFailures = 5
	DefaultAdminAuthWindow      = time.Minute
)

// AdminConfig controls the optional admin API. It's served on its own
// listener — never on the public proxy port — and every endpoint needs
// authentication: a bearer token, a verified client certificate, or
// either. Like server.* and tls.*, the section is read at startup only;
// changing it (including the tokens) needs a restart.
type AdminConfig struct {
	// Enabled starts the admin listener. Defaults to false.
	Enabled bool `yaml:"enabled"`

	// Listen is the admin listener's address. Defaults to
	// 127.0.0.1:9090, reachable from the same host only.
	Listen string `yaml:"listen"`

	// Tokens are the accepted bearer tokens, each stored as the
	// hex-encoded SHA-256 of the token, never the token itself. ID names
	// the token in the audit log.
	Tokens []AdminToken `yaml:"tokens"`

	// MTLS accepts a verified client certificate as admin credentials.
	// It needs TLS on the admin listener with a verifying client_auth.
	MTLS AdminMTLSConfig `yaml:"mtls"`

	// AllowedCIDRs, when non-empty, restricts which source addresses may
	// reach the admin API at all (single addresses are allowed too, e.g.
	// "10.0.0.5"). Others get 403 before authentication is attempted.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`

	// TLS serves the admin API over HTTPS. Same fields as the top-level
	// tls section, except redirect_http_port, which isn't supported here.
	TLS TLSConfig `yaml:"tls"`

	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	IdleTimeout  Duration `yaml:"idle_timeout"`

	// MaxBodyBytes caps admin request bodies. Defaults to 64 KiB.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`

	// AuthFailures slows down credential guessing: a source IP with
	// MaxFailures failed authentications within Window is refused (429)
	// until that window ends, whatever credentials it sends.
	AuthFailures AdminAuthFailureConfig `yaml:"auth_failures"`

	// AuditLog is a file to append the JSON audit log to (created 0600
	// if missing). Empty means the process log, one line per request
	// prefixed "admin-audit: ".
	AuditLog string `yaml:"audit_log"`
}

// AdminToken is one accepted admin bearer token.
type AdminToken struct {
	// ID identifies the token in audit logs, e.g. "ops-laptop". Not
	// secret.
	ID string `yaml:"id"`
	// SHA256 is the lowercase hex SHA-256 of the token, e.g. the output
	// of `printf %s "$TOKEN" | sha256sum`.
	SHA256 string `yaml:"sha256"`
}

// AdminMTLSConfig controls client-certificate authentication on the
// admin listener.
type AdminMTLSConfig struct {
	Enabled bool `yaml:"enabled"`
	// AllowedCNs, when non-empty, limits admin access to certificates
	// with one of these subject common names. Empty accepts any
	// certificate that chains to admin.tls.client_ca_file.
	AllowedCNs []string `yaml:"allowed_cns"`
}

// AdminAuthFailureConfig is the failed-authentication limit per source
// IP.
type AdminAuthFailureConfig struct {
	MaxFailures int      `yaml:"max_failures"`
	Window      Duration `yaml:"window"`
}

func (a *AdminConfig) applyDefaults() {
	if a.Listen == "" {
		a.Listen = DefaultAdminListen
	}
	if a.ReadTimeout.Duration == 0 {
		a.ReadTimeout.Duration = 10 * time.Second
	}
	if a.WriteTimeout.Duration == 0 {
		a.WriteTimeout.Duration = 30 * time.Second
	}
	if a.IdleTimeout.Duration == 0 {
		a.IdleTimeout.Duration = 60 * time.Second
	}
	if a.MaxBodyBytes == 0 {
		a.MaxBodyBytes = DefaultAdminMaxBodyBytes
	}
	if a.AuthFailures.MaxFailures == 0 {
		a.AuthFailures.MaxFailures = DefaultAdminMaxAuthFailures
	}
	if a.AuthFailures.Window.Duration == 0 {
		a.AuthFailures.Window.Duration = DefaultAdminAuthWindow
	}
	a.TLS.applyDefaults()
	for i := range a.Tokens {
		a.Tokens[i].SHA256 = strings.ToLower(strings.TrimSpace(a.Tokens[i].SHA256))
	}
}

// validate checks the admin section. Nothing is checked while it's
// disabled, so configs without one behave exactly as before. Errors
// never include a token hash.
func (a AdminConfig) validate(server ServerConfig, mainTLS TLSConfig) error {
	if !a.Enabled {
		return nil
	}
	_, adminPort, err := net.SplitHostPort(a.Listen)
	if err != nil {
		return fmt.Errorf("admin.listen %q must be host:port: %w", a.Listen, err)
	}
	if _, port, err := net.SplitHostPort(server.ListenAddr); err == nil && port == adminPort {
		return fmt.Errorf("admin.listen must use a different port from server.listen_addr (%s), so the admin API is never served on the proxy port", port)
	}
	if mainTLS.Enabled && mainTLS.RedirectHTTPPort != 0 && fmt.Sprint(mainTLS.RedirectHTTPPort) == adminPort {
		return fmt.Errorf("admin.listen uses the same port as tls.redirect_http_port")
	}

	if len(a.Tokens) == 0 && !a.MTLS.Enabled {
		return fmt.Errorf("admin.enabled is true but no admin authentication is configured: add admin.tokens (SHA-256 hashes) and/or enable admin.mtls")
	}
	ids := map[string]bool{}
	for i, t := range a.Tokens {
		if t.ID == "" {
			return fmt.Errorf("admin.tokens[%d].id is required", i)
		}
		if ids[t.ID] {
			return fmt.Errorf("admin.tokens: id %q is listed twice", t.ID)
		}
		ids[t.ID] = true
		if b, err := hex.DecodeString(t.SHA256); err != nil || len(b) != 32 {
			return fmt.Errorf("admin.tokens[%d] (%s): sha256 must be the 64-character hex SHA-256 of the token, not the token itself", i, t.ID)
		}
	}

	if _, err := a.ParseAllowedCIDRs(); err != nil {
		return err
	}

	if err := a.TLS.validate(a.Listen); err != nil {
		return fmt.Errorf("admin.%w", err)
	}
	if a.TLS.RedirectHTTPPort != 0 {
		return fmt.Errorf("admin.tls.redirect_http_port is not supported on the admin listener")
	}
	if a.MTLS.Enabled && !a.TLS.VerifiesClientCerts() {
		return fmt.Errorf("admin.mtls.enabled needs admin.tls.enabled: true and admin.tls.client_auth verify_if_given or require_and_verify (with admin.tls.client_ca_file)")
	}
	if !a.MTLS.Enabled && len(a.MTLS.AllowedCNs) > 0 {
		return fmt.Errorf("admin.mtls.allowed_cns is set but admin.mtls.enabled is false")
	}

	switch {
	case a.ReadTimeout.Duration < 0, a.WriteTimeout.Duration < 0, a.IdleTimeout.Duration < 0:
		return fmt.Errorf("admin read_timeout, write_timeout and idle_timeout must be >= 0")
	case a.MaxBodyBytes < 0:
		return fmt.Errorf("admin.max_body_bytes must be >= 0")
	case a.AuthFailures.MaxFailures < 0:
		return fmt.Errorf("admin.auth_failures.max_failures must be >= 0")
	case a.AuthFailures.Window.Duration < 0:
		return fmt.Errorf("admin.auth_failures.window must be >= 0")
	}
	return nil
}

// ParseAllowedCIDRs parses AllowedCIDRs; a bare address is a single-host
// prefix.
func (a AdminConfig) ParseAllowedCIDRs() ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(a.AllowedCIDRs))
	for i, s := range a.AllowedCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("admin.allowed_cidrs[%d]: %q is not a CIDR or IP address", i, s)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
	}
	return prefixes, nil
}
