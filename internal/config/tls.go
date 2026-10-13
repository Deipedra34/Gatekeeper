package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// Client certificate modes for TLSConfig.ClientAuth.
const (
	ClientAuthNone             = "none"
	ClientAuthRequest          = "request"
	ClientAuthRequire          = "require"
	ClientAuthVerifyIfGiven    = "verify_if_given"
	ClientAuthRequireAndVerify = "require_and_verify"
)

// Certificate fields a client's identity can be taken from, for
// MTLSConfig.IdentityField.
const (
	IdentityFieldCN     = "cn"
	IdentityFieldSANDNS = "san_dns"
	IdentityFieldSerial = "serial"
)

// Defaults for the tls section.
const (
	DefaultTLSMinVersion      = "1.2"
	DefaultCertReloadInterval = 30 * time.Second
	DefaultHSTSMaxAge         = 31536000 // one year, in seconds
)

// TLSConfig controls HTTPS on Gatekeeper's own listener. Like server.*, it
// is read at startup only — except the certificate and key themselves,
// which are reloaded on SIGHUP and whenever their files change.
type TLSConfig struct {
	// Enabled switches the main listener from plain HTTP to HTTPS.
	// Defaults to false.
	Enabled bool `yaml:"enabled"`

	// CertFile and KeyFile are the PEM-encoded server certificate (with
	// any intermediates after it) and its private key. Both are required
	// when Enabled is true.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// MinVersion is the oldest TLS version accepted: "1.2" (the default)
	// or "1.3".
	MinVersion string `yaml:"min_version"`

	// CipherSuites optionally restricts the TLS 1.2 cipher suites offered,
	// by their standard names (e.g. "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256").
	// Empty means Go's secure defaults. Insecure suites are rejected, and
	// TLS 1.3 suites aren't configurable at all.
	CipherSuites []string `yaml:"cipher_suites"`

	// ClientAuth sets whether clients must present a certificate, and
	// whether it's verified against ClientCAFile: "none" (the default),
	// "request", "require", "verify_if_given", or "require_and_verify".
	// Only the two verifying modes make a client certificate usable for
	// authentication (auth_mode mtls).
	ClientAuth string `yaml:"client_auth"`

	// ClientCAFile is a PEM bundle of the CAs client certificates must
	// chain to. Required by the verifying ClientAuth modes.
	ClientCAFile string `yaml:"client_ca_file"`

	// ReloadInterval is how often the certificate and key files are
	// checked for changes. Defaults to 30s.
	ReloadInterval Duration `yaml:"reload_interval"`

	// RedirectHTTPPort, when non-zero, starts an extra plain-HTTP listener
	// on that port that redirects every request to HTTPS. Defaults to 0
	// (off).
	RedirectHTTPPort int `yaml:"redirect_http_port"`

	HSTS HSTSConfig `yaml:"hsts"`
}

// HSTSConfig controls the Strict-Transport-Security header added to
// HTTPS responses.
type HSTSConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxAge is in seconds. Defaults to one year.
	MaxAge            int  `yaml:"max_age"`
	IncludeSubdomains bool `yaml:"include_subdomains"`
	Preload           bool `yaml:"preload"`
}

// MinTLSVersion returns MinVersion as a crypto/tls constant.
func (t TLSConfig) MinTLSVersion() uint16 {
	if t.MinVersion == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// CipherSuiteIDs returns CipherSuites as crypto/tls IDs, or nil (Go's
// defaults) when none are configured.
func (t TLSConfig) CipherSuiteIDs() ([]uint16, error) {
	if len(t.CipherSuites) == 0 {
		return nil, nil
	}
	secure := map[string]*tls.CipherSuite{}
	for _, cs := range tls.CipherSuites() {
		secure[cs.Name] = cs
	}
	insecure := map[string]bool{}
	for _, cs := range tls.InsecureCipherSuites() {
		insecure[cs.Name] = true
	}

	ids := make([]uint16, 0, len(t.CipherSuites))
	for _, name := range t.CipherSuites {
		cs, ok := secure[name]
		switch {
		case insecure[name]:
			return nil, fmt.Errorf("tls.cipher_suites: %s is insecure and not allowed", name)
		case !ok:
			return nil, fmt.Errorf("tls.cipher_suites: unknown cipher suite %q", name)
		case len(cs.SupportedVersions) == 1 && cs.SupportedVersions[0] == tls.VersionTLS13:
			return nil, fmt.Errorf("tls.cipher_suites: %s is a TLS 1.3 suite; TLS 1.3 suites are not configurable", name)
		}
		ids = append(ids, cs.ID)
	}
	return ids, nil
}

// ClientAuthType returns ClientAuth as a crypto/tls constant.
func (t TLSConfig) ClientAuthType() tls.ClientAuthType {
	switch t.ClientAuth {
	case ClientAuthRequest:
		return tls.RequestClientCert
	case ClientAuthRequire:
		return tls.RequireAnyClientCert
	case ClientAuthVerifyIfGiven:
		return tls.VerifyClientCertIfGiven
	case ClientAuthRequireAndVerify:
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

// VerifiesClientCerts reports whether client certificates are verified
// against ClientCAFile, which is what makes them usable for auth.
func (t TLSConfig) VerifiesClientCerts() bool {
	return t.Enabled && (t.ClientAuth == ClientAuthVerifyIfGiven || t.ClientAuth == ClientAuthRequireAndVerify)
}

// HeaderValue renders the Strict-Transport-Security header value.
func (h HSTSConfig) HeaderValue() string {
	v := "max-age=" + strconv.Itoa(h.MaxAge)
	if h.IncludeSubdomains {
		v += "; includeSubDomains"
	}
	if h.Preload {
		v += "; preload"
	}
	return v
}

func (t *TLSConfig) applyDefaults() {
	if t.MinVersion == "" {
		t.MinVersion = DefaultTLSMinVersion
	}
	if t.ClientAuth == "" {
		t.ClientAuth = ClientAuthNone
	}
	if t.ReloadInterval.Duration == 0 {
		t.ReloadInterval.Duration = DefaultCertReloadInterval
	}
	if t.HSTS.MaxAge == 0 {
		t.HSTS.MaxAge = DefaultHSTSMaxAge
	}
}

// validate checks the tls section, including settings that contradict
// each other — e.g. client certificate or redirect settings while TLS is
// off — so a misconfiguration fails at startup instead of silently doing
// nothing.
func (t TLSConfig) validate(listenAddr string) error {
	switch t.ClientAuth {
	case ClientAuthNone, ClientAuthRequest, ClientAuthRequire, ClientAuthVerifyIfGiven, ClientAuthRequireAndVerify:
	default:
		return fmt.Errorf("tls.client_auth must be one of none, request, require, verify_if_given, require_and_verify, got %q", t.ClientAuth)
	}

	if !t.Enabled {
		switch {
		case t.ClientAuth != ClientAuthNone:
			return fmt.Errorf("tls.client_auth is %q but tls.enabled is false; client certificates need TLS", t.ClientAuth)
		case t.RedirectHTTPPort != 0:
			return fmt.Errorf("tls.redirect_http_port is set but tls.enabled is false; there is no HTTPS listener to redirect to")
		case t.HSTS.Enabled:
			return fmt.Errorf("tls.hsts.enabled is true but tls.enabled is false; HSTS is only sent over HTTPS")
		}
		return nil
	}

	if t.CertFile == "" || t.KeyFile == "" {
		return fmt.Errorf("tls.enabled is true but tls.cert_file and tls.key_file are not both set")
	}
	switch t.MinVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("tls.min_version must be \"1.2\" or \"1.3\", got %q", t.MinVersion)
	}
	if _, err := t.CipherSuiteIDs(); err != nil {
		return err
	}
	if len(t.CipherSuites) > 0 && !hasHTTP2Suite(t.CipherSuites) {
		return fmt.Errorf("tls.cipher_suites must include TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, which HTTP/2 requires")
	}
	if len(t.CipherSuites) > 0 && t.MinVersion == "1.3" {
		return fmt.Errorf("tls.cipher_suites has no effect when tls.min_version is 1.3 (TLS 1.3 suites are not configurable); remove it")
	}
	if (t.ClientAuth == ClientAuthVerifyIfGiven || t.ClientAuth == ClientAuthRequireAndVerify) && t.ClientCAFile == "" {
		return fmt.Errorf("tls.client_auth %q requires tls.client_ca_file", t.ClientAuth)
	}
	if t.ReloadInterval.Duration < 0 {
		return fmt.Errorf("tls.reload_interval must be >= 0")
	}
	if t.RedirectHTTPPort < 0 || t.RedirectHTTPPort > 65535 {
		return fmt.Errorf("tls.redirect_http_port must be between 1 and 65535")
	}
	if t.RedirectHTTPPort != 0 {
		if _, port, err := net.SplitHostPort(listenAddr); err == nil && port == strconv.Itoa(t.RedirectHTTPPort) {
			return fmt.Errorf("tls.redirect_http_port %d is the same port as server.listen_addr", t.RedirectHTTPPort)
		}
	}
	if t.HSTS.MaxAge < 0 {
		return fmt.Errorf("tls.hsts.max_age must be >= 0")
	}
	return nil
}

// hasHTTP2Suite reports whether names includes a cipher suite RFC 7540
// makes mandatory for HTTP/2; Go's HTTP/2 server refuses to start without
// one.
func hasHTTP2Suite(names []string) bool {
	for _, n := range names {
		if n == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" || n == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
			return true
		}
	}
	return false
}

// MTLSConfig controls how a verified client certificate is turned into a
// client identity on routes whose auth_mode is "mtls" or "either".
type MTLSConfig struct {
	// IdentityField picks the certificate field identifying the client
	// for rate limiting: "cn" (subject common name, the default),
	// "san_dns" (first DNS subject alternative name), or "serial"
	// (serial number, uppercase hex). A certificate without that field
	// is rejected.
	IdentityField string `yaml:"identity_field"`

	// Tiers maps a rate-limit tier to the certificates that belong to it,
	// by subject common name and/or organizational unit. A CN match wins
	// over an OU match; a certificate matching nothing gets "default".
	Tiers map[string]MTLSTierMatch `yaml:"tiers"`
}

// MTLSTierMatch lists the certificate attributes that put a client in a
// tier.
type MTLSTierMatch struct {
	CN []string `yaml:"cn"`
	OU []string `yaml:"ou"`
}

func (m *MTLSConfig) applyDefaults() {
	if m.IdentityField == "" {
		m.IdentityField = IdentityFieldCN
	}
}

// EffectiveIdentityField returns IdentityField, defaulting to "cn" for a
// config built without going through Load.
func (m MTLSConfig) EffectiveIdentityField() string {
	if m.IdentityField == "" {
		return IdentityFieldCN
	}
	return m.IdentityField
}

func (m MTLSConfig) validate(tiers map[string]TierLimit) error {
	switch m.EffectiveIdentityField() {
	case IdentityFieldCN, IdentityFieldSANDNS, IdentityFieldSerial:
	default:
		return fmt.Errorf("auth.mtls.identity_field must be one of cn, san_dns, serial, got %q", m.IdentityField)
	}
	seenCN, seenOU := map[string]string{}, map[string]string{}
	for tier, match := range m.Tiers {
		if _, ok := tiers[tier]; !ok {
			return fmt.Errorf("auth.mtls.tiers.%s: no such tier under rate_limit.tiers", tier)
		}
		for _, cn := range match.CN {
			if other, dup := seenCN[cn]; dup {
				return fmt.Errorf("auth.mtls.tiers: CN %q is listed under both %s and %s", cn, other, tier)
			}
			seenCN[cn] = tier
		}
		for _, ou := range match.OU {
			if other, dup := seenOU[ou]; dup {
				return fmt.Errorf("auth.mtls.tiers: OU %q is listed under both %s and %s", ou, other, tier)
			}
			seenOU[ou] = tier
		}
	}
	return nil
}

// BackendTLSConfig controls TLS for connections from Gatekeeper to one
// route's backend. A route with an https:// target and no backend_tls
// block keeps using the system's trusted CAs, as before.
type BackendTLSConfig struct {
	Enabled bool `yaml:"enabled"`

	// CAFile is a PEM bundle of the CAs the backend's certificate must
	// chain to. When set it replaces the system trust store for this
	// backend.
	CAFile string `yaml:"ca_file"`

	// ClientCertFile and ClientKeyFile, set together, are presented to
	// the backend for mutual TLS.
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`

	// ServerName overrides the name the backend's certificate is checked
	// against (and sent as SNI). Defaults to the target's hostname.
	ServerName string `yaml:"server_name"`

	// InsecureSkipVerify disables verification of the backend's
	// certificate. Development only — a loud warning is logged.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

func (b BackendTLSConfig) validate(target string) error {
	if !b.Enabled {
		if b.CAFile != "" || b.ClientCertFile != "" || b.ClientKeyFile != "" || b.ServerName != "" || b.InsecureSkipVerify {
			return fmt.Errorf("backend_tls settings are present but backend_tls.enabled is false")
		}
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("backend_tls.enabled requires an https:// target (WebSocket upgrades on it go out as wss), got %q", target)
	}
	if (b.ClientCertFile == "") != (b.ClientKeyFile == "") {
		return fmt.Errorf("backend_tls.client_cert_file and backend_tls.client_key_file must be set together")
	}
	return nil
}
