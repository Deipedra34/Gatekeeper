package middleware

import (
	"log"
	"math"
	"net"
	"net/http"
	"strconv"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter"
)

// apiKeyHeader is the header checked when RateLimitConfig.Scope is
// "api_key". It matches AuthConfig's default Header value on purpose —
// a deployment using both API key auth and API-key-scoped limits only
// has to think about one header name, not two.
const apiKeyHeader = "X-API-Key"

// RateLimit enforces per-client limits, one Limiter per configured tier.
// It works out a client identifier from the request based on cfg.Scope
// (API key, source IP, or a custom header), maps that to a tier via
// cfg.Clients — unknown clients land in the "default" tier — and asks
// that tier's Limiter whether the request should go through.
//
// If the limiter itself errors, say because the store is briefly
// unreachable, the request is let through anyway and a warning gets
// logged. A storage hiccup should degrade to "unlimited," not "gateway
// down."
func RateLimit(cfg config.RateLimitConfig, limiters map[string]ratelimiter.Limiter, m *metrics.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := clientKey(cfg, r)
			tier := clientTier(cfg, client)

			limiter, ok := limiters[tier]
			if !ok {
				limiter = limiters["default"]
			}

			result, err := limiter.Allow(r.Context(), client)
			if err != nil {
				log.Printf("ratelimiter: allow check failed for client %q, allowing request through: %v", client, err)
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
			m.LimiterRemaining.WithLabelValues(client, tier).Set(float64(result.Remaining))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(result.RetryAfter.Seconds()))))
				m.RequestsRejected.WithLabelValues(client, tier).Inc()
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			m.RequestsAllowed.WithLabelValues(client, tier).Inc()
			next.ServeHTTP(w, r)
		})
	}
}

func clientKey(cfg config.RateLimitConfig, r *http.Request) string {
	switch cfg.Scope {
	case "api_key":
		return r.Header.Get(apiKeyHeader)
	case "header":
		return r.Header.Get(cfg.HeaderName)
	default: // "ip"
		return clientIP(r)
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clientTier(cfg config.RateLimitConfig, client string) string {
	if tier, ok := cfg.Clients[client]; ok {
		return tier
	}
	return "default"
}
