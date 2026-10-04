package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"gatekeeper/internal/config"
)

// minRSAKeyBits is the smallest RSA public key accepted for RS256.
const minRSAKeyBits = 2048

var (
	errUnexpectedSigningMethod = errors.New("unexpected signing method")
	errMissingClientClaim      = errors.New("client id claim missing or not a non-empty string")
)

// jwtVerifier validates bearer tokens against one configured algorithm
// and key. It's built once per config (load or reload), so the key file
// is read and parsed up front instead of on every request.
type jwtVerifier struct {
	parser      *jwt.Parser
	keyFunc     jwt.Keyfunc
	clientClaim string
	tierClaim   string
}

// newJWTVerifier builds a verifier from cfg. Errors may name the key file
// but never include the secret or key material.
func newJWTVerifier(cfg config.JWTConfig) (*jwtVerifier, error) {
	opts := []jwt.ParserOption{
		// Pinning the accepted algorithm to exactly the configured one is
		// what stops algorithm-confusion attacks: a token claiming "none",
		// or HS256 when we expect RS256 (signed with the public key as an
		// HMAC secret), is rejected before the key is ever consulted.
		jwt.WithValidMethods([]string{cfg.Algorithm}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(cfg.Leeway.Duration),
	}
	if cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}

	var keyFunc jwt.Keyfunc
	switch cfg.Algorithm {
	case "HS256":
		secret, err := cfg.HMACSecret()
		if err != nil {
			return nil, err
		}
		keyFunc = func(t *jwt.Token) (any, error) {
			// Redundant with WithValidMethods, kept as defence in depth so
			// the secret can only ever be handed to an HMAC verifier.
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errUnexpectedSigningMethod
			}
			return secret, nil
		}
	case "RS256":
		pemBytes, err := os.ReadFile(cfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt: reading public_key_file %s: %w", cfg.PublicKeyFile, err)
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt: public_key_file %s is not a PEM-encoded RSA public key: %w", cfg.PublicKeyFile, err)
		}
		if key.N.BitLen() < minRSAKeyBits {
			return nil, fmt.Errorf("auth.jwt: RSA public key must be at least %d bits", minRSAKeyBits)
		}
		keyFunc = func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errUnexpectedSigningMethod
			}
			return key, nil
		}
	default:
		return nil, fmt.Errorf("auth.jwt.algorithm must be HS256 or RS256, got %q", cfg.Algorithm)
	}

	return &jwtVerifier{
		parser:      jwt.NewParser(opts...),
		keyFunc:     keyFunc,
		clientClaim: cfg.ClientIDClaim,
		tierClaim:   cfg.TierClaim,
	}, nil
}

// verify checks raw's signature and standard claims, and extracts the
// client identity (and tier, if configured) used for rate limiting. The
// returned error is for tests and debugging only — it must never be
// written to the response or logged alongside the token.
func (v *jwtVerifier) verify(raw string) (Identity, error) {
	claims := jwt.MapClaims{}
	if _, err := v.parser.ParseWithClaims(raw, claims, v.keyFunc); err != nil {
		return Identity{}, err
	}

	client, ok := claims[v.clientClaim].(string)
	if !ok || client == "" {
		return Identity{}, errMissingClientClaim
	}

	var tier string
	if v.tierClaim != "" {
		tier, _ = claims[v.tierClaim].(string)
	}
	return Identity{Method: config.AuthModeJWT, Client: client, Tier: tier}, nil
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
// The scheme is matched case-insensitively, per RFC 7235. ok is false if
// the header is absent, uses another scheme, or carries an empty token.
func bearerToken(r *http.Request) (token string, ok bool) {
	h := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// writeBearerChallenge answers 401 with an RFC 6750 WWW-Authenticate
// challenge. invalidToken distinguishes "a token was sent but rejected"
// from "no token was sent"; deliberately, nothing about *why* a token was
// rejected (expired, bad signature, wrong audience...) is revealed.
func writeBearerChallenge(w http.ResponseWriter, invalidToken bool) {
	challenge := `Bearer realm="gatekeeper"`
	if invalidToken {
		challenge += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
