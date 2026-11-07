// Package transform applies a route's request and response
// transformations: path prefix stripping and regex rewrites, query
// parameter and header changes on the forwarded request, and header
// changes (including default security headers) on the response.
//
// Values may reference a fixed set of variables (see
// config.TransformVariables), chosen so a transform can never copy a
// credential to a backend: there is no "copy this request header"
// variable, and ${client_id} is the rate-limit label, never a raw API
// key. Everything is compiled and validated at config load.
package transform

import (
	"bufio"
	"net"
	"net/http"
	"net/textproto"
	"path"
	"regexp"
	"sort"
	"strings"

	"gatekeeper/internal/config"
)

// Vars are the values ${...} variables expand to for one request.
type Vars struct {
	ClientIP, RequestID, ClientID, ClientTier, Route, TraceID string
}

func (v Vars) lookup(name string) string {
	var s string
	switch name {
	case config.VarClientIP:
		s = v.ClientIP
	case config.VarRequestID:
		s = v.RequestID
	case config.VarClientID:
		s = v.ClientID
	case config.VarClientTier:
		s = v.ClientTier
	case config.VarRoute:
		s = v.Route
	case config.VarTraceID:
		s = v.TraceID
	}
	return sanitize(s)
}

// stable looks variables up like lookup, except the per-request
// identifiers, which expand to "". Used for cache keys: a header that
// only differs by request ID must not make every request a miss.
func (v Vars) stable(name string) string {
	if name == config.VarRequestID || name == config.VarTraceID {
		return ""
	}
	return v.lookup(name)
}

// sanitize drops control characters from a variable's value. Values
// that come from the client (a header-scoped client ID, a trusted
// X-Forwarded-For) already passed through a header, but nothing a
// transform writes may ever split a header.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

type headerValue struct {
	name  string // canonical
	value config.Template
}

// Request is a route's compiled request transformation.
type Request struct {
	stripPrefix string // the route's path prefix, or "" for no stripping
	rewrite     *regexp.Regexp
	replacement string

	add, set    []headerValue
	remove      []string
	addQuery    []queryValue
	removeQuery []string
}

type queryValue struct {
	name  string
	value config.Template
}

// Response is a route's compiled response transformation.
type Response struct {
	add, set []headerValue
	remove   []string
	security []headerValue // default security headers, set if absent
}

// Result says what ApplyRequest changed.
type Result struct {
	// PathChanged is true when strip_prefix or rewrite changed the path.
	PathChanged bool
	Headers     bool
	Query       bool
}

// Compile builds rt's transformations; global supplies the default
// security headers. A nil Request or Response means there's nothing to
// do in that direction. cfg has already been validated.
func Compile(rt config.Route, global config.TransformConfig) (*Request, *Response, error) {
	reqCfg, respCfg := rt.Transform.Request, rt.Transform.Response

	var req *Request
	if reqCfg.StripPrefix || reqCfg.Rewrite != nil || len(reqCfg.AddHeaders) > 0 || len(reqCfg.SetHeaders) > 0 ||
		len(reqCfg.RemoveHeaders) > 0 || len(reqCfg.AddQueryParams) > 0 || len(reqCfg.RemoveQueryParams) > 0 {
		req = &Request{}
		if reqCfg.StripPrefix {
			req.stripPrefix = rt.PathPrefix
		}
		if rw := reqCfg.Rewrite; rw != nil {
			re, err := regexp.Compile(rw.Pattern)
			if err != nil {
				return nil, nil, err
			}
			req.rewrite, req.replacement = re, rw.Replacement
		}
		var err error
		if req.add, err = compileHeaders(reqCfg.AddHeaders); err != nil {
			return nil, nil, err
		}
		if req.set, err = compileHeaders(reqCfg.SetHeaders); err != nil {
			return nil, nil, err
		}
		req.remove = canonical(reqCfg.RemoveHeaders)
		for _, name := range sortedKeys(reqCfg.AddQueryParams) {
			t, err := config.ParseTemplate(reqCfg.AddQueryParams[name])
			if err != nil {
				return nil, nil, err
			}
			req.addQuery = append(req.addQuery, queryValue{name: name, value: t})
		}
		req.removeQuery = append([]string(nil), reqCfg.RemoveQueryParams...)
	}

	sec := global.SecurityHeaders
	if respCfg.SecurityHeaders.Enabled != nil {
		sec = respCfg.SecurityHeaders
	}
	securityOn := sec.Enabled != nil && *sec.Enabled

	var resp *Response
	if securityOn || len(respCfg.AddHeaders) > 0 || len(respCfg.SetHeaders) > 0 || len(respCfg.RemoveHeaders) > 0 {
		resp = &Response{remove: canonical(respCfg.RemoveHeaders)}
		var err error
		if resp.add, err = compileHeaders(respCfg.AddHeaders); err != nil {
			return nil, nil, err
		}
		if resp.set, err = compileHeaders(respCfg.SetHeaders); err != nil {
			return nil, nil, err
		}
		if securityOn {
			for _, h := range [][2]string{
				{"X-Content-Type-Options", sec.ContentTypeOptions},
				{"X-Frame-Options", sec.FrameOptions},
				{"Referrer-Policy", sec.ReferrerPolicy},
			} {
				t, _ := config.ParseTemplate(h[1])
				resp.security = append(resp.security, headerValue{name: h[0], value: t})
			}
		}
	}
	return req, resp, nil
}

func compileHeaders(m map[string]string) ([]headerValue, error) {
	var out []headerValue
	for _, name := range sortedKeys(m) {
		t, err := config.ParseTemplate(m[name])
		if err != nil {
			return nil, err
		}
		out = append(out, headerValue{name: http.CanonicalHeaderKey(name), value: t})
	}
	return out, nil
}

func canonical(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = http.CanonicalHeaderKey(n)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Apply rewrites req in place — it must be the gateway's own copy of
// the request, not one still shared with earlier middleware — and
// reports what changed.
func (t *Request) Apply(req *http.Request, vars Vars) Result {
	var res Result
	if t == nil {
		return res
	}
	oldPath := req.URL.Path

	if t.stripPrefix != "" && pathHasPrefix(req.URL.Path, t.stripPrefix) {
		stripped := "/" + strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, t.stripPrefix), "/")
		if req.URL.RawPath != "" && strings.HasPrefix(req.URL.RawPath, t.stripPrefix) {
			req.URL.RawPath = "/" + strings.TrimPrefix(strings.TrimPrefix(req.URL.RawPath, t.stripPrefix), "/")
		} else {
			req.URL.RawPath = ""
		}
		req.URL.Path = stripped
	}
	if t.rewrite != nil {
		if m := t.rewrite.FindStringSubmatchIndex(req.URL.Path); m != nil {
			rewritten := string(t.rewrite.ExpandString(nil, t.replacement, req.URL.Path, m))
			req.URL.Path = cleanPath(rewritten)
			req.URL.RawPath = ""
		}
	}
	res.PathChanged = req.URL.Path != oldPath

	if len(t.addQuery) > 0 || len(t.removeQuery) > 0 {
		q := req.URL.Query()
		for _, name := range t.removeQuery {
			q.Del(name)
		}
		for _, p := range t.addQuery {
			q.Set(p.name, p.value.Expand(vars.lookup))
		}
		req.URL.RawQuery = q.Encode()
		res.Query = true
	}

	if len(t.add) > 0 || len(t.set) > 0 || len(t.remove) > 0 {
		h := req.Header
		for _, name := range t.remove {
			h.Del(name)
		}
		for _, hv := range t.set {
			h.Set(hv.name, hv.value.Expand(vars.lookup))
		}
		for _, hv := range t.add {
			if _, ok := h[hv.name]; !ok {
				h.Set(hv.name, hv.value.Expand(vars.lookup))
			}
		}
		// A client could name one of these in its Connection header to
		// have the proxy strip it as hop-by-hop after it was set.
		UnlistFromConnection(h, t.setNames()...)
		res.Headers = true
	}
	return res
}

func (t *Request) setNames() []string {
	names := make([]string, 0, len(t.add)+len(t.set))
	for _, hv := range t.set {
		names = append(names, hv.name)
	}
	for _, hv := range t.add {
		names = append(names, hv.name)
	}
	return names
}

// CacheVary returns "Name=value" for every header the transform adds or
// sets, for the response cache key: the backend's response may depend
// on them (e.g. a header carrying ${client_id}), so requests that
// differ only there must not share a cache entry. Per-request IDs
// (${request_id}, ${trace_id}) are left out of the values, so they
// don't turn every request into a miss. It reads the transformed
// request, so a header the client already had (add_headers keeps it)
// is keyed by the value actually forwarded.
func (t *Request) CacheVary(req *http.Request, vars Vars) []string {
	if t == nil || (len(t.add) == 0 && len(t.set) == 0) {
		return nil
	}
	var out []string
	for _, hv := range t.set {
		out = append(out, hv.name+"="+hv.value.Expand(vars.stable))
	}
	for _, hv := range t.add {
		v := req.Header.Get(hv.name)
		if v == hv.value.Expand(vars.lookup) {
			v = hv.value.Expand(vars.stable) // ours: key it without per-request IDs
		}
		out = append(out, hv.name+"="+v)
	}
	return out
}

// UnlistFromConnection removes names from the request's Connection
// header, so a hop-by-hop strip further down can't remove headers the
// gateway just set.
func UnlistFromConnection(h http.Header, names ...string) {
	values := h.Values("Connection")
	if len(values) == 0 || len(names) == 0 {
		return
	}
	drop := map[string]bool{}
	for _, n := range names {
		drop[http.CanonicalHeaderKey(n)] = true
	}
	var kept []string
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			if tok = textproto.TrimString(tok); tok != "" && !drop[http.CanonicalHeaderKey(tok)] {
				kept = append(kept, tok)
			}
		}
	}
	if len(kept) == 0 {
		h.Del("Connection")
		return
	}
	h.Set("Connection", strings.Join(kept, ", "))
}

func pathHasPrefix(p, prefix string) bool {
	return len(p) >= len(prefix) && p[:len(prefix)] == prefix
}

// cleanPath makes a rewritten path absolute and removes dot segments,
// keeping a trailing slash.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// ApplyHeaders applies the response transformation to h: remove, set,
// add (when absent), then security headers (when absent).
func (t *Response) ApplyHeaders(h http.Header, vars Vars) {
	if t == nil {
		return
	}
	for _, name := range t.remove {
		h.Del(name)
	}
	for _, hv := range t.set {
		h.Set(hv.name, hv.value.Expand(vars.lookup))
	}
	for _, hv := range t.add {
		if _, ok := h[hv.name]; !ok {
			h.Set(hv.name, hv.value.Expand(vars.lookup))
		}
	}
	for _, hv := range t.security {
		if _, ok := h[hv.name]; !ok {
			h.Set(hv.name, hv.value.Expand(vars.lookup))
		}
	}
}

// Wrap returns a ResponseWriter that applies the transformation to the
// response headers just before they're written; applied is called once
// when that happens. Informational (1xx) responses pass through
// unchanged.
func (t *Response) Wrap(w http.ResponseWriter, vars Vars, applied func()) http.ResponseWriter {
	if t == nil {
		return w
	}
	return &responseWriter{ResponseWriter: w, t: t, vars: vars, applied: applied}
}

type responseWriter struct {
	http.ResponseWriter
	t           *Response
	vars        Vars
	applied     func()
	wroteHeader bool
}

func (w *responseWriter) WriteHeader(status int) {
	if !w.wroteHeader && status >= http.StatusOK {
		w.wroteHeader = true
		w.t.ApplyHeaders(w.Header(), w.vars)
		if w.applied != nil {
			w.applied()
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ForwardedHeaders replaces client-supplied forwarding headers with
// ones derived from the connection (trust_forwarded_headers: false):
// X-Real-IP is the peer address, X-Forwarded-Proto http or https,
// X-Forwarded-Host the request's Host. X-Forwarded-For is removed; the
// proxy sets it to the peer address when forwarding.
func ForwardedHeaders(req *http.Request) {
	h := req.Header
	for _, name := range config.ForwardingHeaders() {
		h.Del(name)
	}
	if ip := PeerIP(req); ip != "" {
		h.Set("X-Real-IP", ip)
	}
	proto := "http"
	if req.TLS != nil {
		proto = "https"
	}
	h.Set("X-Forwarded-Proto", proto)
	if req.Host != "" {
		h.Set("X-Forwarded-Host", req.Host)
	}
	UnlistFromConnection(h, config.ForwardingHeaders()...)
}

// PeerIP is the address of the connection's peer.
func PeerIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// ClientIP is ${client_ip}: the first X-Forwarded-For address when
// forwarding headers are trusted and it parses as an IP, the peer
// address otherwise.
func ClientIP(req *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if first, _, _ := strings.Cut(req.Header.Get("X-Forwarded-For"), ","); first != "" {
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip.String()
			}
		}
	}
	return PeerIP(req)
}
