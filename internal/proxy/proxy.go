// Package proxy implements Gatekeeper's reverse-proxy core: routing
// incoming requests to configured backend services by path prefix or
// hostname and forwarding them with net/http/httputil.ReverseProxy.
package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"gatekeeper/internal/config"
)

// route is a config.Route compiled into a ready-to-use reverse proxy.
type route struct {
	pathPrefix string
	host       string
	target     *url.URL
	proxy      *httputil.ReverseProxy
}

// Router dispatches requests to the backend whose route matches, based
// on hostname first and then longest-matching path prefix.
type Router struct {
	routes []route
}

// NewRouter compiles cfg's routes into a Router. It fails fast on a
// malformed target URL, so a typo in config shows up at startup instead
// of on whatever request happens to hit it first.
func NewRouter(routes []config.Route) (*Router, error) {
	r := &Router{}
	for _, rt := range routes {
		target, err := url.Parse(rt.Target)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid target %q: %w", rt.Target, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorHandler = errorHandler(rt.Target)

		r.routes = append(r.routes, route{
			pathPrefix: rt.PathPrefix,
			host:       rt.Host,
			target:     target,
			proxy:      proxy,
		})
	}
	return r, nil
}

// ServeHTTP implements http.Handler, dispatching to the first matching
// route's reverse proxy.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rt := r.match(req)
	if rt == nil {
		http.Error(w, "no backend route configured for this request", http.StatusNotFound)
		return
	}
	rt.proxy.ServeHTTP(w, req)
}

// match picks the route to use for req. Hostname routes take priority
// over path-prefix routes; among path-prefix routes, the longest
// matching prefix wins so a more specific route (e.g. "/api/users/vip")
// beats a more general one (e.g. "/api/users").
func (r *Router) match(req *http.Request) *route {
	for i := range r.routes {
		if r.routes[i].host != "" && r.routes[i].host == req.Host {
			return &r.routes[i]
		}
	}

	var best *route
	for i := range r.routes {
		rt := &r.routes[i]
		if rt.pathPrefix == "" {
			continue
		}
		if !pathHasPrefix(req.URL.Path, rt.pathPrefix) {
			continue
		}
		if best == nil || len(rt.pathPrefix) > len(best.pathPrefix) {
			best = rt
		}
	}
	return best
}

func pathHasPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	return path[:len(prefix)] == prefix
}

// errorHandler returns a ReverseProxy.ErrorHandler that logs the
// backend failure and answers with 502 instead of ReverseProxy's default
// bare "connection refused" text — callers get a stable, documented
// response for a backend outage instead of whatever the transport error
// happened to say.
func errorHandler(target string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("proxy: backend %s unreachable for %s %s: %v", target, req.Method, req.URL.Path, err)
		http.Error(w, "backend service unavailable", http.StatusBadGateway)
	}
}
