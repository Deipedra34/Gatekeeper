package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/config"
)

// Reasons an admin request is refused before reaching an endpoint; the
// "reason" label of gatekeeper_admin_auth_failures_total and the audit
// log's "reason" field.
const (
	reasonMissingCredentials = "missing_credentials"
	reasonInvalidToken       = "invalid_token"
	reasonCertNotAllowed     = "certificate_not_allowed"
	reasonIPNotAllowed       = "ip_not_allowed"
	reasonRateLimited        = "rate_limited"
)

// tokenHash is one accepted token, as configured: an ID and the SHA-256
// of the token. The token itself is never held.
type tokenHash struct {
	id   string
	hash []byte
}

// authenticator decides who an admin request comes from, if anyone.
type authenticator struct {
	tokens     []tokenHash
	mtls       bool
	allowedCNs map[string]bool // empty: any verified certificate
	cidrs      []netip.Prefix  // empty: any source address
	failures   *failureLimiter
}

func newAuthenticator(cfg config.AdminConfig) (*authenticator, error) {
	cidrs, err := cfg.ParseAllowedCIDRs()
	if err != nil {
		return nil, err
	}
	a := &authenticator{
		mtls:       cfg.MTLS.Enabled,
		allowedCNs: map[string]bool{},
		cidrs:      cidrs,
		failures:   newFailureLimiter(cfg.AuthFailures.MaxFailures, cfg.AuthFailures.Window.Duration),
	}
	for _, t := range cfg.Tokens {
		h, err := hex.DecodeString(t.SHA256)
		if err != nil {
			return nil, err // config validation already rules this out
		}
		a.tokens = append(a.tokens, tokenHash{id: t.ID, hash: h})
	}
	for _, cn := range cfg.MTLS.AllowedCNs {
		a.allowedCNs[cn] = true
	}
	return a, nil
}

// decision is the outcome of authenticate.
type decision struct {
	identity   string // "token:<id>" or "cert:<CN>" when allowed
	status     int    // 0 when allowed
	code       string
	reason     string
	retryAfter time.Duration
}

// authenticate checks, in order: the source address against the
// allowlist (403), whether that address is locked out after too many
// failed attempts (429 — checked before credentials, so a correct guess
// made while locked out is still refused), then the credentials (401).
// A verified client certificate is tried before a bearer token.
func (a *authenticator) authenticate(r *http.Request, ip netip.Addr) decision {
	if !a.ipAllowed(ip) {
		return decision{status: http.StatusForbidden, code: codeForbidden, reason: reasonIPNotAllowed}
	}
	if wait := a.failures.blocked(ip, time.Now()); wait > 0 {
		return decision{status: http.StatusTooManyRequests, code: codeTooManyFailures, reason: reasonRateLimited, retryAfter: wait}
	}

	reason := reasonMissingCredentials
	if a.mtls && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if len(a.allowedCNs) == 0 || a.allowedCNs[cn] {
			return decision{identity: "cert:" + cn}
		}
		reason = reasonCertNotAllowed
	}
	if token, ok := bearerToken(r); ok && len(a.tokens) > 0 {
		if id, ok := matchToken(a.tokens, token); ok {
			return decision{identity: "token:" + id}
		}
		reason = reasonInvalidToken
	}

	a.failures.fail(ip, time.Now())
	return decision{status: http.StatusUnauthorized, code: codeUnauthorized, reason: reason}
}

func (a *authenticator) ipAllowed(ip netip.Addr) bool {
	if len(a.cidrs) == 0 {
		return true
	}
	for _, p := range a.cidrs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// tokenCompare compares two hashes in constant time. It's a variable so
// a test can confirm every configured token is compared on every attempt.
var tokenCompare = subtle.ConstantTimeCompare

// matchToken hashes presented and compares it against every configured
// hash, without stopping at a match: how long it takes depends on
// neither which token matched nor how much of a wrong token was right.
// Comparing fixed-length hashes rather than the tokens themselves also
// keeps the token's length from leaking.
func matchToken(tokens []tokenHash, presented string) (id string, ok bool) {
	sum := sha256.Sum256([]byte(presented))
	for _, t := range tokens {
		if tokenCompare(sum[:], t.hash) == 1 {
			id, ok = t.id, true
		}
	}
	return id, ok
}

// sourceIP is the request's peer address. X-Forwarded-For is
// deliberately ignored: the admin listener isn't meant to sit behind a
// proxy, and a client-supplied header must never get past the
// allowlist or the failure limit.
func sourceIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// failureLimiter counts failed authentications per source IP in fixed
// windows. Once an address reaches max failures in a window it's locked
// out until the window ends.
type failureLimiter struct {
	max    int
	window time.Duration

	mu      sync.Mutex
	entries map[netip.Addr]*failureWindow
}

type failureWindow struct {
	start    time.Time
	failures int
}

// maxTrackedIPs bounds the limiter's memory under a flood of addresses;
// expired windows are swept once it's reached.
const maxTrackedIPs = 10000

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, entries: map[netip.Addr]*failureWindow{}}
}

func (l *failureLimiter) blocked(ip netip.Addr, now time.Time) time.Duration {
	if l.max <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok || now.Sub(e.start) >= l.window {
		return 0
	}
	if e.failures >= l.max {
		return l.window - now.Sub(e.start)
	}
	return 0
}

func (l *failureLimiter) fail(ip netip.Addr, now time.Time) {
	if l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= maxTrackedIPs {
		for k, e := range l.entries {
			if now.Sub(e.start) >= l.window {
				delete(l.entries, k)
			}
		}
	}
	e, ok := l.entries[ip]
	if !ok || now.Sub(e.start) >= l.window {
		e = &failureWindow{start: now}
		l.entries[ip] = e
	}
	e.failures++
}
