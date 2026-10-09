package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
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
	// Method is config.AuthModeAPIKey or config.AuthModeJWT.
	Method string
	// Client is the value of the configured client id claim. JWT only.
	Client string
	// Tier is the value of the configured tier claim, or "" if there's no
	// tier claim configured or the token doesn't carry it. JWT only.
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

// Auth enforces each route's auth mode — api_key, jwt, or either — as
// resolved by modeFor (normally the router's AuthModeFor; nil means
// every request is api_key). It's a no-op when auth is disabled.
//
// On an api_key route the behaviour, including the 401 response body, is
// identical to APIKeyAuth. Routes that accept JWTs answer failures with a
// generic body and a WWW-Authenticate: Bearer challenge.
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			mode := config.AuthModeAPIKey
			if modeFor != nil {
				mode = modeFor(r)
			}

			switch mode {
			case config.AuthModeJWT:
				id, presented, ok := tryJWT(r)
				if !ok {
					record(config.AuthModeJWT, false)
					websocket.RecordRejectionFor(r, m, websocket.RejectAuth)
					writeBearerChallenge(w, presented)
					return
				}
				record(config.AuthModeJWT, true)
				next.ServeHTTP(w, withIdentity(r, id))

			case config.AuthModeEither:
				if validAPIKey(valid, r.Header.Get(cfg.Header)) {
					record(config.AuthModeAPIKey, true)
					next.ServeHTTP(w, withIdentity(r, Identity{Method: config.AuthModeAPIKey}))
					return
				}
				id, presented, ok := tryJWT(r)
				if ok {
					record(config.AuthModeJWT, true)
					next.ServeHTTP(w, withIdentity(r, id))
					return
				}
				if presented {
					record(config.AuthModeJWT, false)
				} else {
					record(config.AuthModeAPIKey, false)
				}
				websocket.RecordRejectionFor(r, m, websocket.RejectAuth)
				writeBearerChallenge(w, presented)

			default: // config.AuthModeAPIKey
				if !validAPIKey(valid, r.Header.Get(cfg.Header)) {
					record(config.AuthModeAPIKey, false)
					websocket.RecordRejectionFor(r, m, websocket.RejectAuth)
					http.Error(w, "invalid or missing API key", http.StatusUnauthorized)
					return
				}
				record(config.AuthModeAPIKey, true)
				next.ServeHTTP(w, withIdentity(r, Identity{Method: config.AuthModeAPIKey}))
			}
		})
	}, nil
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
