package fault

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/config"
	"gatekeeper/internal/lb"
)

// Client is what a rule's client allowlist is checked against.
type Client struct {
	IP     netip.Addr
	APIKey string
	Tier   string
}

// Request is one request as rules see it: the HTTP request, the traffic
// split variant serving it ("" on an unsplit route), and its client,
// resolved only if a rule has a client allowlist to check.
type Request struct {
	HTTP    *http.Request
	Variant string
	Client  func() Client
}

// matcher is a rule's compiled targeting.
type matcher struct {
	header       *config.ValueMatch
	pathPrefixes []string
	methods      map[string]bool
	variants     map[string]bool
	backends     map[string]bool // by lb.Label; nil: every backend
	clients      *clientMatcher
}

type clientMatcher struct {
	tiers   map[string]bool
	apiKeys map[string]bool
	cidrs   *accesscontrol.PrefixSet
}

// newMatcher compiles m, already validated.
func newMatcher(m config.FaultMatch) *matcher {
	out := &matcher{header: m.Header, pathPrefixes: m.PathPrefixes}
	out.methods = set(m.Methods)
	out.variants = set(m.Variants)
	if len(m.Backends) > 0 {
		out.backends = make(map[string]bool, len(m.Backends))
		for _, b := range m.Backends {
			out.backends[backendLabel(b)] = true
		}
	}
	if c := m.Clients; c != nil {
		cidrs, _ := accesscontrol.NewPrefixSet(c.CIDRs) // validated at load
		out.clients = &clientMatcher{tiers: set(c.Tiers), apiKeys: set(c.APIKeys), cidrs: cidrs}
	}
	return out
}

// backendLabel normalizes a configured target the way the load balancer
// labels its backend, so the two compare equal.
func backendLabel(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	return lb.Label(u)
}

func set(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// matches reports whether req meets every request-level condition. The
// backend condition can only be checked per attempt; see
// Decision.AppliesTo.
func (m *matcher) matches(req Request) bool {
	r := req.HTTP
	if h := m.header; h != nil {
		v, ok := r.Header[http.CanonicalHeaderKey(h.Name)]
		if !ok || (h.Value != "" && !containsValue(v, h.Value)) {
			return false
		}
	}
	if len(m.pathPrefixes) > 0 && !hasAnyPrefix(r.URL.Path, m.pathPrefixes) {
		return false
	}
	if m.methods != nil && !m.methods[r.Method] {
		return false
	}
	if m.variants != nil && !m.variants[req.Variant] {
		return false
	}
	if m.clients != nil && (req.Client == nil || !m.clients.matches(req.Client())) {
		return false
	}
	return true
}

func (c *clientMatcher) matches(cl Client) bool {
	return (cl.Tier != "" && c.tiers[cl.Tier]) ||
		(cl.APIKey != "" && c.apiKeys[cl.APIKey]) ||
		c.cidrs.Contains(cl.IP)
}

func containsValue(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
