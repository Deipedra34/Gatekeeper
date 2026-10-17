package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket"
)

// APIKeyAuth rejects requests that don't present a valid API key in
// cfg.Header — unless auth is turned off in config, in which case it's a
// no-op. Keys are compared with constant-time equality so a timing
// side-channel can't leak anything about the key material.
//
// It enforces API keys on every request regardless of route; Auth is the
// per-route variant that also understands JWTs.
func APIKeyAuth(cfg config.AuthConfig) Middleware {
	valid := keySet(cfg.APIKeys)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			if !validAPIKey(valid, r.Header.Get(cfg.Header)) {
				http.Error(w, "invalid or missing API key", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Identity records how a request authenticated, for middleware further
// down the chain (the rate limiter) to read back via IdentityFrom.
type Identity struct {
	// Method is config.AuthModeAPIKey, config.AuthModeJWT, or
	// config.AuthModeMTLS.
	Method string
	// Client is the value of the configured client id claim (JWT) or
	// certificate field (mTLS). Unset for API keys.
	Client string
	// Tier is the value of the configured tier claim (JWT) or the tier
	// the certificate's CN/OU maps to (mTLS), or "" for none — the
	// default tier. Unset for API keys.
	Tier string
}

type identityKey struct{}

// IdentityFrom returns the Identity the auth middleware attached to ctx,
// if any. There's none when auth is disabled.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

func withIdentity(r *http.Request, id Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
}

// Auth enforces each route's auth mode — api_key, jwt, mtls, or either —
// as resolved by modeFor (normally the router's AuthModeFor; nil means
// every request is api_key). It's a no-op when auth is disabled.
//
// On an api_key route the behaviour, including the 401 response body, is
// identical to APIKeyAuth. Routes that accept JWTs answer failures with a
// generic body and a WWW-Authenticate: Bearer challenge.
//
// An mtls route requires a client certificate that crypto/tls verified
// against tls.client_ca_file during the handshake; an either route
// accepts, in order, a valid API key, a valid JWT, or such a certificate.
// Whatever the route's mode — and even with auth disabled — a verified
// client certificate's identity is attached to the request for later
// middleware (see ClientCertificateFrom).
//
// m, if non-nil, receives one success or failure count per request; see
// metrics.Metrics.AuthRequests for how failures are attributed. A
// rejected WebSocket handshake is additionally counted as a handshake
// rejection with reason "auth".
func Auth(cfg config.AuthConfig, modeFor func(*http.Request) string, m *metrics.Metrics) (Middleware, error) {
	valid := keySet(cfg.APIKeys)

	var verifier *jwtVerifier
	if cfg.Enabled && cfg.JWT.Algorithm != "" {
		v, err := newJWTVerifier(cfg.JWT)
		if err != nil {
			return nil, err
		}
		verifier = v
	}

	certs := newCertIdentifier(cfg.MTLS)

	record := func(method string, success bool) {
		if m == nil {
			return
		}
		result := "failure"
		if success {
			result = "success"
		}
		m.AuthRequests.WithLabelValues(method, result).Inc()
	}

	// tryJWT reports whether a bearer token was presented at all, and the
	// verified identity if it was valid.
	tryJWT := func(r *http.Request) (id Identity, presented, ok bool) {
		raw, presented := bearerToken(r)
		if !presented || verifier == nil {
			return Identity{}, presented, false
		}
		id, err := verifier.verify(raw)
		return id, true, err == nil
	}

	// tryMTLS reports whether a verified client certificate was presented,
	// and its identity if one could be derived from it.
	tryMTLS := func(r *http.Request) (id Identity, presented, ok bool) {
		cert := verifiedClientCert(r)
		if cert == nil {
			return Identity{}, false, false
		}
		id, err := certs.identify(cert)
		return id, true, err == nil
	}

	// decide authenticates r against mode. method is what the decision is
	// attributed to in metrics and traces: the credential that succeeded,
	// or — on failure — the one that was tried (see AuthRequests).
	decide := func(mode string, r *http.Request) authOutcome {
		switch mode {
		case config.AuthModeJWT:
			id, presented, ok := tryJWT(r)
			if !ok {
				return authOutcome{method: config.AuthModeJWT, reject: bearerChallenge(presented)}
			}
			return authOutcome{id: id, method: config.AuthModeJWT, ok: true}

		case config.AuthModeMTLS:
			id, _, ok := tryMTLS(r)
			if !ok {
				return authOutcome{method: config.AuthModeMTLS, reject: plainUnauthorized("valid client certificate required")}
			}
			return authOutcome{id: id, method: config.AuthModeMTLS, ok: true}

		case config.AuthModeEither:
			if validAPIKey(valid, r.Header.Get(cfg.Header)) {
				return authOutcome{id: Identity{Method: config.AuthModeAPIKey}, method: config.AuthModeAPIKey, ok: true}
			}
			id, presented, ok := tryJWT(r)
			if ok {
				return authOutcome{id: id, method: config.AuthModeJWT, ok: true}
			}
			certID, certPresented, certOK := tryMTLS(r)
			if certOK {
				return authOutcome{id: certID, method: config.AuthModeMTLS, ok: true}
			}
			method := config.AuthModeAPIKey
			switch {
			case presented:
				method = config.AuthModeJWT
			case certPresented:
				method = config.AuthModeMTLS
			}
			return authOutcome{method: method, reject: bearerChallenge(presented)}

		default: // config.AuthModeAPIKey
			if !validAPIKey(valid, r.Header.Get(cfg.Header)) {
				return authOutcome{method: config.AuthModeAPIKey, reject: plainUnauthorized("invalid or missing API key")}
			}
			return authOutcome{id: Identity{Method: config.AuthModeAPIKey}, method: config.AuthModeAPIKey, ok: true}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id, _, ok := tryMTLS(r); ok {
				r = withClientCertificate(r, id)
			}
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			mode := config.AuthModeAPIKey
			if modeFor != nil {
				mode = modeFor(r)
			}

			// The span covers the authentication decision only; it ends
			// before the request moves on, so later stages are its
			// siblings rather than its children.
			_, span := tracing.Start(r.Context(), tracing.SpanAuth,
				trace.WithAttributes(tracing.AttrAuthMode.String(mode)))
			out := decide(mode, r)
			record(out.method, out.ok)
			span.SetAttributes(tracing.AttrAuthMethod.String(out.method), tracing.AttrAuthResult.String(result(out.ok)))
			if !out.ok {
				tracing.Fail(span, "unauthorized")
				span.End()
				websocket.RecordRejectionFor(r, m, websocket.RejectAuth)
				out.reject(w)
				return
			}
			span.End()
			next.ServeHTTP(w, withIdentity(r, out.id))
		})
	}, nil
}

// authOutcome is the result of one authentication decision.
type authOutcome struct {
	id     Identity
	method string
	ok     bool
	reject func(http.ResponseWriter) // writes the 401; set when !ok
}

func bearerChallenge(invalidToken bool) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { writeBearerChallenge(w, invalidToken) }
}

func plainUnauthorized(msg string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { http.Error(w, msg, http.StatusUnauthorized) }
}

func result(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}

func keySet(keys []string) map[string]struct{} {
	valid := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		valid[k] = struct{}{}
	}
	return valid
}

func validAPIKey(valid map[string]struct{}, key string) bool {
	return key != "" && containsKey(valid, key)
}

func containsKey(valid map[string]struct{}, key string) bool {
	for candidate := range valid {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1 {
			return true
		}
	}
	return false
}
