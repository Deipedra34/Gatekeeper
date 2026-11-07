package config

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// TransformConfig is the top-level transform section: settings that
// apply to every route. Per-route rewrites and header changes live
// under each route's transform section (RouteTransform).
type TransformConfig struct {
	// TrustForwardedHeaders keeps client-supplied X-Forwarded-For,
	// X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-Port,
	// X-Forwarded-Prefix, Forwarded, and X-Real-IP and forwards them
	// (X-Forwarded-For with the client's address appended), as earlier
	// versions did. Set it only behind a proxy you trust to set them.
	//
	// When false (the default) those headers are dropped and set from
	// the connection itself: X-Forwarded-For and X-Real-IP to the peer
	// address, X-Forwarded-Proto to http or https, X-Forwarded-Host to
	// the request's Host. ${client_ip} follows the same rule.
	TrustForwardedHeaders bool `yaml:"trust_forwarded_headers"`

	RequestID RequestIDConfig `yaml:"request_id"`

	// SecurityHeaders are default security response headers for every
	// route; a route's own transform.response.security_headers
	// overrides them. Off by default.
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers"`
}

// RequestIDConfig controls request IDs.
type RequestIDConfig struct {
	// Enabled gives every request an ID: the client's, if it sent a
	// valid one in Header, otherwise a new random one. The ID is
	// forwarded to the backend and returned to the client in Header,
	// and available as ${request_id}. Off by default.
	Enabled bool `yaml:"enabled"`
	// Header is the header carrying the ID. Defaults to X-Request-ID.
	Header string `yaml:"header"`
}

// DefaultRequestIDHeader is RequestIDConfig.Header's default.
const DefaultRequestIDHeader = "X-Request-ID"

// SecurityHeadersConfig adds common security headers to responses that
// don't already carry them (a backend's own value always wins).
type SecurityHeadersConfig struct {
	// Enabled turns the headers on. At route level, unset inherits the
	// global setting and false turns them off for that route.
	Enabled *bool `yaml:"enabled"`
	// ContentTypeOptions is X-Content-Type-Options. Default "nosniff".
	ContentTypeOptions string `yaml:"content_type_options"`
	// FrameOptions is X-Frame-Options: "DENY" (the default) or
	// "SAMEORIGIN".
	FrameOptions string `yaml:"frame_options"`
	// ReferrerPolicy is Referrer-Policy. Default "no-referrer".
	ReferrerPolicy string `yaml:"referrer_policy"`
}

// RouteTransform rewrites requests on their way to a route's backends
// and responses on their way back. A route without one is proxied
// exactly as before.
type RouteTransform struct {
	Request  RequestTransform  `yaml:"request"`
	Response ResponseTransform `yaml:"response"`
}

// RequestTransform changes the request forwarded to the backend. It's
// applied after auth and rate limiting (which see the request as the
// client sent it) and before the response cache, so cache keys use the
// forwarded path, query, and headers. Steps run in this order:
// strip_prefix, rewrite, query parameters, then headers (remove, set,
// add).
type RequestTransform struct {
	// StripPrefix removes the route's path_prefix before forwarding:
	// /api/users on route /api goes to the backend as /users.
	StripPrefix bool `yaml:"strip_prefix"`
	// Rewrite rewrites the path (after StripPrefix) with a regular
	// expression.
	Rewrite *PathRewrite `yaml:"rewrite"`

	// AddHeaders adds headers the request doesn't already have.
	AddHeaders map[string]string `yaml:"add_headers"`
	// SetHeaders sets headers, replacing any value the client sent.
	SetHeaders map[string]string `yaml:"set_headers"`
	// RemoveHeaders removes headers.
	RemoveHeaders []string `yaml:"remove_headers"`

	// AddQueryParams sets query parameters, replacing any value the
	// client sent for the same name, so a client can't pre-empt them.
	AddQueryParams map[string]string `yaml:"add_query_params"`
	// RemoveQueryParams removes query parameters.
	RemoveQueryParams []string `yaml:"remove_query_params"`
}

// PathRewrite is a regular expression path rewrite. Pattern is matched
// against the path (without the query); Replacement may use capture
// groups as $1 or ${name}. A path the pattern doesn't match is left
// alone. Patterns are Go RE2 expressions, which run in time linear in
// the input: there is no backtracking to blow up.
type PathRewrite struct {
	Pattern     string `yaml:"pattern"`
	Replacement string `yaml:"replacement"`
}

// ResponseTransform changes the response returned to the client. It
// applies to every response on the route — from the backend, the
// cache, or the gateway itself (e.g. 502) — and to WebSocket 101
// responses. Steps run in order: remove, set, add, security headers.
type ResponseTransform struct {
	AddHeaders      map[string]string     `yaml:"add_headers"`
	SetHeaders      map[string]string     `yaml:"set_headers"`
	RemoveHeaders   []string              `yaml:"remove_headers"`
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers"`
}

// IsZero reports whether the route has no transformation at all.
func (t RouteTransform) IsZero() bool {
	r, s := t.Request, t.Response
	return !r.StripPrefix && r.Rewrite == nil && len(r.AddHeaders) == 0 && len(r.SetHeaders) == 0 &&
		len(r.RemoveHeaders) == 0 && len(r.AddQueryParams) == 0 && len(r.RemoveQueryParams) == 0 &&
		len(s.AddHeaders) == 0 && len(s.SetHeaders) == 0 && len(s.RemoveHeaders) == 0 && s.SecurityHeaders.Enabled == nil
}

// Transform variables: the only names ${...} may use in header and
// query parameter values. Each is either chosen by the gateway or
// already public to the backend; none can carry a credential.
const (
	VarClientIP   = "client_ip"   // the client's address (see trust_forwarded_headers)
	VarRequestID  = "request_id"  // the request ID; needs transform.request_id.enabled
	VarClientID   = "client_id"   // the rate-limit identity: key:<fingerprint>, jwt:<id>, mtls:<id>, IP, or header value; never a raw API key
	VarClientTier = "client_tier" // the client's rate-limit tier
	VarRoute      = "route"       // the route label
	VarTraceID    = "trace_id"    // the trace ID, or "" when tracing is off
)

// TransformVariables lists every allowed variable name.
var TransformVariables = []string{VarClientIP, VarRequestID, VarClientID, VarClientTier, VarRoute, VarTraceID}

// Template is a header or query value with ${variable} references,
// parsed and checked at config load.
type Template struct {
	parts []templatePart
}

type templatePart struct {
	literal string
	varName string // "" for a literal
}

// ParseTemplate parses s, rejecting unknown variables, an unterminated
// "${", and control characters (a CR or LF would let a value inject
// headers). A "$" not followed by "{" is literal.
func ParseTemplate(s string) (Template, error) {
	for _, c := range s {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return Template{}, fmt.Errorf("value contains a control character")
		}
	}
	var t Template
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			if s != "" {
				t.parts = append(t.parts, templatePart{literal: s})
			}
			return t, nil
		}
		if i > 0 {
			t.parts = append(t.parts, templatePart{literal: s[:i]})
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return Template{}, fmt.Errorf("unterminated \"${\" in %q", s)
		}
		name := s[i+2 : i+end]
		if !isTransformVariable(name) {
			return Template{}, fmt.Errorf("unknown variable ${%s}; allowed: %s", name, allowedVariables())
		}
		t.parts = append(t.parts, templatePart{varName: name})
		s = s[i+end+1:]
	}
}

func isTransformVariable(name string) bool {
	for _, v := range TransformVariables {
		if v == name {
			return true
		}
	}
	return false
}

func allowedVariables() string {
	names := make([]string, len(TransformVariables))
	for i, v := range TransformVariables {
		names[i] = "${" + v + "}"
	}
	return strings.Join(names, ", ")
}

// Uses reports whether the template references variable name.
func (t Template) Uses(name string) bool {
	for _, p := range t.parts {
		if p.varName == name {
			return true
		}
	}
	return false
}

// Expand renders the template, looking each variable up with value.
func (t Template) Expand(value func(name string) string) string {
	if len(t.parts) == 1 && t.parts[0].varName == "" {
		return t.parts[0].literal
	}
	var b strings.Builder
	for _, p := range t.parts {
		if p.varName == "" {
			b.WriteString(p.literal)
		} else {
			b.WriteString(value(p.varName))
		}
	}
	return b.String()
}

// maxRewritePatternLen bounds rewrite patterns. RE2 already guarantees
// linear-time matching; this just keeps compiled programs small.
const maxRewritePatternLen = 1024

// forwardingHeaders are set by the gateway itself according to
// trust_forwarded_headers, so transforms can't touch them.
var forwardingHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
	"X-Forwarded-Prefix", "X-Forwarded-Server", "X-Real-Ip", "Forwarded",
}

// ForwardingHeaders returns the client-supplied forwarding headers that
// are dropped when trust_forwarded_headers is false.
func ForwardingHeaders() []string { return append([]string(nil), forwardingHeaders...) }

// hopByHopHeaders are connection-level headers (RFC 9110 §7.6.1) that
// the proxy manages; a transform touching them could break framing or
// WebSocket upgrades.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// protectedHeader reports why name may not be transformed in direction
// ("request" or "response"), or "" if it may.
func (c *Config) protectedHeader(direction, name string) string {
	canon := http.CanonicalHeaderKey(name)
	for _, h := range hopByHopHeaders {
		if canon == h {
			return "it is a hop-by-hop header the proxy manages"
		}
	}
	if strings.HasPrefix(canon, "Sec-Websocket-") {
		return "it is part of the WebSocket handshake"
	}
	if canon == "Content-Length" {
		return "it frames the message body"
	}
	if c.Transform.RequestID.Enabled && canon == http.CanonicalHeaderKey(c.Transform.RequestID.Header) {
		return "it carries the request ID (see transform.request_id)"
	}
	switch direction {
	case "request":
		if canon == "Host" {
			return "the backend's Host comes from the client request"
		}
		for _, h := range forwardingHeaders {
			if canon == h {
				return "forwarding headers are controlled by transform.trust_forwarded_headers"
			}
		}
	case "response":
		switch canon {
		case "Content-Encoding":
			return "it describes how the body is encoded"
		case "X-Ratelimit-Limit", "X-Ratelimit-Remaining", "Retry-After":
			return "the rate limiter sets it"
		case "X-Cache":
			return "the response cache sets it"
		case "Strict-Transport-Security":
			return "it is controlled by tls.hsts"
		}
		if c.Tracing.ResponseHeader != "" && canon == http.CanonicalHeaderKey(c.Tracing.ResponseHeader) {
			return "it is controlled by tracing.response_header"
		}
	}
	return ""
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c > 0x7e || c <= 0x20 || strings.ContainsRune("\"(),/:;<=>?@[\\]{}", c) {
			return false
		}
	}
	return true
}

func (c *Config) applyTransformDefaults() {
	if c.Transform.RequestID.Header == "" {
		c.Transform.RequestID.Header = DefaultRequestIDHeader
	}
	c.Transform.SecurityHeaders.applyDefaults()
	for i := range c.Routes {
		c.Routes[i].Transform.Response.SecurityHeaders.applyDefaults()
	}
}

func (s *SecurityHeadersConfig) applyDefaults() {
	if s.ContentTypeOptions == "" {
		s.ContentTypeOptions = "nosniff"
	}
	if s.FrameOptions == "" {
		s.FrameOptions = "DENY"
	}
	if s.ReferrerPolicy == "" {
		s.ReferrerPolicy = "no-referrer"
	}
}

var referrerPolicies = map[string]bool{
	"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true, "origin-when-cross-origin": true,
	"same-origin": true, "strict-origin": true, "strict-origin-when-cross-origin": true, "unsafe-url": true,
}

func (s SecurityHeadersConfig) validate(where string) error {
	if s.ContentTypeOptions != "nosniff" {
		return fmt.Errorf("%s.content_type_options must be \"nosniff\"", where)
	}
	if s.FrameOptions != "DENY" && s.FrameOptions != "SAMEORIGIN" {
		return fmt.Errorf("%s.frame_options must be \"DENY\" or \"SAMEORIGIN\", got %q", where, s.FrameOptions)
	}
	if !referrerPolicies[s.ReferrerPolicy] {
		return fmt.Errorf("%s.referrer_policy %q is not a valid Referrer-Policy", where, s.ReferrerPolicy)
	}
	return nil
}

func (c *Config) validateTransform() error {
	if !validHeaderName(c.Transform.RequestID.Header) {
		return fmt.Errorf("transform.request_id.header %q is not a valid header name", c.Transform.RequestID.Header)
	}
	if err := c.Transform.SecurityHeaders.validate("transform.security_headers"); err != nil {
		return err
	}
	for i, rt := range c.Routes {
		if err := c.validateRouteTransform(rt); err != nil {
			return fmt.Errorf("routes[%d].transform.%w", i, err)
		}
	}
	return nil
}

func (c *Config) validateRouteTransform(rt Route) error {
	req, resp := rt.Transform.Request, rt.Transform.Response
	if req.StripPrefix && rt.PathPrefix == "" {
		return fmt.Errorf("request.strip_prefix needs the route to have a path_prefix")
	}
	if rw := req.Rewrite; rw != nil {
		if err := validateRewrite(*rw); err != nil {
			return fmt.Errorf("request.rewrite: %w", err)
		}
	}

	// A per-request value in the query would make every request on a
	// cached route a cache miss (the query is part of the cache key).
	perRequestQueryOK := !rt.Cache.IsEnabled()
	if err := c.validateTemplates("request.add_query_params", req.AddQueryParams, func(t Template) error {
		if !perRequestQueryOK && (t.Uses(VarRequestID) || t.Uses(VarTraceID)) {
			return fmt.Errorf("${request_id} and ${trace_id} would make every request a cache miss on a cached route; disable cache for the route or drop the variable")
		}
		return nil
	}); err != nil {
		return err
	}
	for i, name := range req.RemoveQueryParams {
		if name == "" {
			return fmt.Errorf("request.remove_query_params[%d] is empty", i)
		}
	}
	for name := range req.AddQueryParams {
		if name == "" {
			return fmt.Errorf("request.add_query_params has an empty name")
		}
	}

	if err := c.validateHeaderOps("request", req.AddHeaders, req.SetHeaders, req.RemoveHeaders); err != nil {
		return err
	}
	if err := c.validateHeaderOps("response", resp.AddHeaders, resp.SetHeaders, resp.RemoveHeaders); err != nil {
		return err
	}
	return resp.SecurityHeaders.validate("response.security_headers")
}

func validateRewrite(rw PathRewrite) error {
	if rw.Pattern == "" {
		return fmt.Errorf("pattern is required")
	}
	if len(rw.Pattern) > maxRewritePatternLen {
		return fmt.Errorf("pattern is longer than %d characters", maxRewritePatternLen)
	}
	re, err := regexp.Compile(rw.Pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}
	if rw.Replacement == "" {
		return fmt.Errorf("replacement is required")
	}
	if strings.ContainsAny(rw.Replacement, "?#") {
		return fmt.Errorf("replacement must be a path only; use add_query_params for query parameters")
	}
	return checkReplacementGroups(re, rw.Replacement)
}

// replacementRef matches the group references regexp.Expand understands.
var replacementRef = regexp.MustCompile(`\$(\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))`)

// checkReplacementGroups rejects references to capture groups the
// pattern doesn't have, which regexp.Expand would silently expand to "".
func checkReplacementGroups(re *regexp.Regexp, replacement string) error {
	names := map[string]bool{}
	for _, n := range re.SubexpNames() {
		if n != "" {
			names[n] = true
		}
	}
	for _, m := range replacementRef.FindAllStringSubmatch(strings.ReplaceAll(replacement, "$$", ""), -1) {
		ref := m[2] + m[3]
		if n, err := strconv.Atoi(ref); err == nil {
			if n > re.NumSubexp() {
				return fmt.Errorf("replacement uses $%d but the pattern has only %d capture group(s)", n, re.NumSubexp())
			}
			continue
		}
		if !names[ref] {
			return fmt.Errorf("replacement uses ${%s} but the pattern has no capture group named %q (wrap a name in braces, e.g. ${1}x, when text follows)", ref, ref)
		}
	}
	return nil
}

func (c *Config) validateTemplates(where string, values map[string]string, extra func(Template) error) error {
	for _, k := range sortedKeys(values) {
		t, err := ParseTemplate(values[k])
		if err != nil {
			return fmt.Errorf("%s.%s: %w", where, k, err)
		}
		if t.Uses(VarRequestID) && !c.Transform.RequestID.Enabled {
			return fmt.Errorf("%s.%s: ${request_id} needs transform.request_id.enabled: true", where, k)
		}
		if extra != nil {
			if err := extra(t); err != nil {
				return fmt.Errorf("%s.%s: %w", where, k, err)
			}
		}
	}
	return nil
}

func (c *Config) validateHeaderOps(direction string, add, set map[string]string, remove []string) error {
	seen := map[string]string{}
	check := func(op, name string) error {
		if !validHeaderName(name) {
			return fmt.Errorf("%s.%s: %q is not a valid header name", direction, op, name)
		}
		if why := c.protectedHeader(direction, name); why != "" {
			return fmt.Errorf("%s.%s: %s can't be changed by a transform: %s", direction, op, http.CanonicalHeaderKey(name), why)
		}
		canon := http.CanonicalHeaderKey(name)
		if prev, dup := seen[canon]; dup {
			return fmt.Errorf("%s: %s is listed under both %s and %s", direction, canon, prev, op)
		}
		seen[canon] = op
		return nil
	}
	for _, name := range sortedKeys(add) {
		if err := check("add_headers", name); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(set) {
		if err := check("set_headers", name); err != nil {
			return err
		}
	}
	for _, name := range remove {
		if err := check("remove_headers", name); err != nil {
			return err
		}
	}
	if err := c.validateTemplates(direction+".add_headers", add, nil); err != nil {
		return err
	}
	return c.validateTemplates(direction+".set_headers", set, nil)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
