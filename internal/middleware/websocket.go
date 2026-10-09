package middleware

import (
	"net/http"

	"gatekeeper/internal/websocket"
)

// WebSocketHandshake tags each WebSocket upgrade request with the route
// it's headed for (as resolved by routeFor, normally the router's
// RouteLabelFor), so the middleware after it can attribute handshake
// rejections to that route and the rate limiter can hand its client
// identity on to the router's per-client connection limit. Ordinary HTTP
// requests, and upgrades that match no route, pass through untouched.
func WebSocketHandshake(routeFor func(*http.Request) (string, bool)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if websocket.IsUpgrade(r) {
				if route, ok := routeFor(r); ok {
					r = websocket.Annotate(r, route)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
