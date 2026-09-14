// Package proxy implements Gatekeeper's reverse-proxy core: routing
// incoming requests to configured backend services by path prefix or
// hostname and forwarding them with net/http/httputil.ReverseProxy.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
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
//
// proxyCfg controls the per-attempt timeout and retry/backoff policy
// applied to every backend call. m, if non-nil, receives retry-attempt
// and outcome metrics; it may be nil in tests that don't care about
// metrics.
func NewRouter(routes []config.Route, proxyCfg config.ProxyConfig, m *metrics.Metrics) (*Router, error) {
	r := &Router{}
	for _, rt := range routes {
		target, err := url.Parse(rt.Target)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid target %q: %w", rt.Target, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorHandler = errorHandler(rt.Target)
		proxy.Transport = newRetryTransport(proxyCfg, m, routeLabel(rt))

		r.routes = append(r.routes, route{
			pathPrefix: rt.PathPrefix,
			host:       rt.Host,
			target:     target,
			proxy:      proxy,
		})
	}
	return r, nil
}

// routeLabel identifies a route for metrics purposes: its path prefix,
// or its host if it has no path prefix.
func routeLabel(rt config.Route) string {
	if rt.PathPrefix != "" {
		return rt.PathPrefix
	}
	return rt.Host
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

// retryTransport wraps an http.RoundTripper with a per-attempt timeout
// and retries with exponential backoff and jitter. It retries on
// transport-level failures (timeouts, connection errors) and 5xx
// responses; a 4xx response is returned to the caller immediately since
// no amount of retrying fixes a client error.
//
// A single incoming request may cause several backend attempts, but
// this transport sits below the rate limiter middleware — it is only
// ever invoked once per admitted request — so retries never cost the
// client extra rate-limit budget. See ProxyRetries / ProxyOutcomes for
// how retries and their final result are reflected in /metrics
// separately from the raw allowed/rejected request counts.
type retryTransport struct {
	base    http.RoundTripper
	timeout time.Duration
	retry   config.RetryConfig
	metrics *metrics.Metrics
	route   string
}

func newRetryTransport(cfg config.ProxyConfig, m *metrics.Metrics, routeLabel string) *retryTransport {
	return &retryTransport{
		base:    http.DefaultTransport,
		timeout: cfg.Timeout.Duration,
		retry:   cfg.Retry,
		metrics: m,
		route:   routeLabel,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	bodyBytes, err := drainBody(req)
	if err != nil {
		return nil, err
	}

	maxAttempts := t.retry.MaxRetries + 1
	var resp *http.Response
	var rtErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			t.incRetries()
			if werr := waitBackoff(req.Context(), t.retry, attempt-1); werr != nil {
				t.recordOutcome(false)
				return nil, werr
			}
		}

		attemptReq := cloneRequestWithBody(req, bodyBytes)
		ctx, cancel := context.WithTimeout(req.Context(), t.timeout)
		attemptReq = attemptReq.WithContext(ctx)

		resp, rtErr = t.base.RoundTrip(attemptReq)
		last := attempt == maxAttempts

		if rtErr != nil {
			cancel()
			if last || req.Context().Err() != nil {
				t.recordOutcome(false)
				return nil, rtErr
			}
			continue
		}

		if isRetryableStatus(resp.StatusCode) && !last {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			cancel()
			continue
		}

		// This is the response we're returning to the caller (success,
		// a 4xx we never retry, or a 5xx after exhausting retries).
		// ReverseProxy reads and closes resp.Body after RoundTrip
		// returns, so the attempt's context must stay alive until then.
		resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
		t.recordOutcome(resp.StatusCode < 500)
		return resp, nil
	}

	return resp, rtErr
}

func (t *retryTransport) incRetries() {
	if t.metrics == nil {
		return
	}
	t.metrics.ProxyRetries.WithLabelValues(t.route).Inc()
}

func (t *retryTransport) recordOutcome(success bool) {
	if t.metrics == nil {
		return
	}
	outcome := "failure"
	if success {
		outcome = "success"
	}
	t.metrics.ProxyOutcomes.WithLabelValues(t.route, outcome).Inc()
}

// isRetryableStatus reports whether status is a server error worth
// retrying. 4xx client errors are deliberately excluded.
func isRetryableStatus(status int) bool {
	return status >= 500 && status <= 599
}

// drainBody reads req's body fully into memory and closes the original,
// so it can be replayed unchanged on every retry attempt. Incoming
// request bodies generally can't be re-read from the network directly,
// so buffering is the price of being able to retry a request with a
// body at all.
func drainBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	defer req.Body.Close()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("proxy: reading request body for retry buffering: %w", err)
	}
	return b, nil
}

// cloneRequestWithBody clones req and attaches a fresh, independent
// reader over body so each retry attempt gets its own unconsumed copy.
func cloneRequestWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	if body == nil {
		clone.Body = http.NoBody
		clone.ContentLength = 0
		return clone
	}
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	clone.ContentLength = int64(len(body))
	return clone
}

// waitBackoff sleeps for the backoff delay before retry number
// retryNum (1 for the first retry, 2 for the second, ...), returning
// early with an error if ctx is cancelled first.
func waitBackoff(ctx context.Context, cfg config.RetryConfig, retryNum int) error {
	delay := backoffDelay(cfg, retryNum)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// backoffDelay computes the exponential backoff delay before retry
// number retryNum, doubling each time up to cfg.MaxBackoff, then
// applies full jitter (a random value between 0 and that cap) so many
// clients retrying at once don't hammer the backend in lockstep.
func backoffDelay(cfg config.RetryConfig, retryNum int) time.Duration {
	base := cfg.BaseBackoff.Duration
	max := cfg.MaxBackoff.Duration
	if base <= 0 {
		return 0
	}

	d := base
	for i := 1; i < retryNum && d < max; i++ {
		d *= 2
		if d <= 0 { // overflowed
			d = max
			break
		}
	}
	if d > max {
		d = max
	}
	if d <= 0 {
		return 0
	}

	return time.Duration(rand.Int63n(int64(d) + 1))
}

// cancelOnCloseBody wraps a response body so the per-attempt timeout
// context is cancelled when (and only when) the body is closed, once
// the caller has finished reading the response.
type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
