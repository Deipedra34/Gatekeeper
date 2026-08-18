// Package dashboard serves a small self-contained HTML page for poking at
// a running Gatekeeper instance interactively. It sends real requests to
// the gateway's own routes — same-origin, so there's no CORS config to
// worry about — and polls /metrics to show live results. It's a
// developer/demo aid, nothing more; it isn't part of the gateway's
// request path.
package dashboard

import (
	_ "embed"
	"net/http"
)

//go:embed static/index.html
var page []byte

// Handler serves the dashboard page.
func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page)
}
