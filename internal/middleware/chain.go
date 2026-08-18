// Package middleware provides the HTTP middleware chain Gatekeeper
// wraps around the reverse proxy: request logging, API key
// authentication, CORS handling, and per-client rate limiting.
package middleware

import "net/http"

// Middleware wraps an http.Handler to produce another http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies mws to h in order, so the first middleware in the list
// is the outermost (it sees the request first and the response last).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
