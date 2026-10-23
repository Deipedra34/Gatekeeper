package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"go.opentelemetry.io/otel/trace"

	"gatekeeper/internal/ratelimiter"
	"gatekeeper/internal/tracing"
	"gatekeeper/internal/websocket"
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
// A request that authenticated with a JWT is identified differently: by
// the client id claim the auth middleware extracted (prefixed "jwt:" so
// it can never share a bucket with an API key, IP, or header value that
// happens to be the same string), with its tier taken from the tier
// claim — or "default" if there's no tier claim or it names a tier that
// isn't configured. Scope and cfg.Clients don't apply to JWT clients.
// A request authenticated by client certificate works the same way,
// keyed "mtls:<identity>" with the tier its CN/OU maps to.
//
// If the limiter itself errors, say because the store is briefly
// unreachable, the request is let through anyway and a warning gets
// logged. A storage hiccup should degrade to "unlimited," not "gateway
// down."
//
// A WebSocket upgrade request costs exactly one token, like any other
// request; frames exchanged once the connection is established never
// pass through here. The client identity resolved for a handshake is
// recorded on it (see websocket.Handshake) so per-client connection
// limits key on the same identity.
//
// When tracing is on, each check gets a rate_limit span recording the
// decision, algorithm, store, tier, and a keyed hash of the client
// identity — never the identity itself, which may be an API key.
func RateLimit(cfg config.RateLimitConfig, limiters map[string]ratelimiter.Limiter, m *metrics.Metrics, opts ...RateLimitOption) Middleware {
	var o rateLimitOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := clientKey(cfg, r)
			tier := clientTier(cfg, client)
			// label is how the client appears in metrics and logs: never
			// a raw API key.
			label := client
			if cfg.Scope == "api_key" {
				label = APIKeyFingerprint(client)
			}
			if id, ok := IdentityFrom(r.Context()); ok && (id.Method == config.AuthModeJWT || id.Method == config.AuthModeMTLS) {
				client = id.Method + ":" + id.Client
				label = client
				tier = claimedTier(id.Tier, limiters)
			}

			limiter, ok := limiters[tier]
			if !ok {
				limiter = limiters["default"]
			}
			if hs, ok := websocket.HandshakeFrom(r.Context()); ok {
				hs.SetClient(client)
			}

			ctx, span := tracing.Start(r.Context(), tracing.SpanRateLimit, trace.WithAttributes(
				tracing.AttrRateLimitAlgorithm.String(cfg.Algorithm),
				tracing.AttrRateLimitStore.String(o.store),
				tracing.AttrClientTier.String(tier),
				tracing.AttrClientIDHash.String(tracing.HashClientID(client)),
			))
			result, err := limiter.Allow(ctx, client)
			if err != nil {
				// Fail open, as before; the span says so.
				span.SetAttributes(tracing.AttrRateLimitAllowed.Bool(true), tracing.AttrRateLimitError.Bool(true))
				span.End()
				log.Printf("ratelimiter: allow check failed for client %q, allowing request through: %v", label, err)
				next.ServeHTTP(w, r)
				return
			}
			span.SetAttributes(
				tracing.AttrRateLimitAllowed.Bool(result.Allowed),
				tracing.AttrRateLimitLimit.Int64(result.Limit),
				tracing.AttrRateLimitRemaining.Int64(result.Remaining),
			)
			if !result.Allowed {
				tracing.Fail(span, "rate limit exceeded")
			}
			span.End()

			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
			m.LimiterRemaining.WithLabelValues(label, tier).Set(float64(result.Remaining))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(result.RetryAfter.Seconds()))))
				m.RequestsRejected.WithLabelValues(label, tier).Inc()
				websocket.RecordRejectionFor(r, m, websocket.RejectRateLimit)
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			m.RequestsAllowed.WithLabelValues(label, tier).Inc()
			next.ServeHTTP(w, r)
		})
	}
}

// APIKeyFingerprint is how an API key is identified in metrics and logs:
// "key:" followed by the first 12 hex characters of its SHA-256. It's
// stable across restarts and replicas (so Prometheus series continue), and
// an operator can work out which key it is with
//
//	printf %s "$KEY" | sha256sum | cut -c1-12
//
// but the key itself never appears. An empty key (no key sent) stays "".
func APIKeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return "key:" + hex.EncodeToString(sum[:])[:12]
}

// RateLimitOption customises RateLimit.
type RateLimitOption func(*rateLimitOptions)

type rateLimitOptions struct {
	store string
}

// WithStoreType names the storage backend ("memory" or "redis") in
// rate_limit spans.
func WithStoreType(store string) RateLimitOption {
	return func(o *rateLimitOptions) { o.store = store }
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

// claimedTier maps a tier from a JWT claim or a certificate mapping onto
// a configured tier, falling back to "default" when it's absent or names
// a tier that doesn't exist — a credential can't invent its own tier.
func claimedTier(claimed string, limiters map[string]ratelimiter.Limiter) string {
	if _, ok := limiters[claimed]; ok {
		return claimed
	}
	return "default"
}
