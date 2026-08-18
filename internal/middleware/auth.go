package middleware

import (
	"crypto/subtle"
	"net/http"

	"gatekeeper/internal/config"
)

// APIKeyAuth rejects requests that don't present a valid API key in
// cfg.Header — unless auth is turned off in config, in which case it's a
// no-op. Keys are compared with constant-time equality so a timing
// side-channel can't leak anything about the key material.
func APIKeyAuth(cfg config.AuthConfig) Middleware {
	valid := make(map[string]struct{}, len(cfg.APIKeys))
	for _, k := range cfg.APIKeys {
		valid[k] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			key := r.Header.Get(cfg.Header)
			if key == "" || !containsKey(valid, key) {
				http.Error(w, "invalid or missing API key", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func containsKey(valid map[string]struct{}, key string) bool {
	for candidate := range valid {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1 {
			return true
		}
	}
	return false
}
