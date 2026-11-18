package split

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"gatekeeper/internal/config"
)

// How a request's variant was chosen, reported in Decision.Source.
const (
	// SourceWeight: the client's bucket, by the current weights.
	SourceWeight = "weight"
)

// Client is what the gateway knows about a request's client, for sticky
// assignment and override checks. Empty fields are unknown.
type Client struct {
	// IP is the client's address as access control (or, without it, the
	// connection) resolved it.
	IP string
	// APIKey is the raw API key the request carried.
	APIKey string
	// JWTSubject is the client id claim of a verified JWT.
	JWTSubject string
	// CertID is the identity of a verified client certificate.
	CertID string
	// Tier is the client's rate limit tier.
	Tier string
}

// Decision is the variant chosen for one request.
type Decision struct {
	// Index is the variant's position in the config, Name its name.
	Index int
	Name  string
	// Source says how it was chosen: SourceWeight, SourceOverride, or
	// SourceRule.
	Source string
}

// Route is a split route's compiled traffic split and its live state:
// the current weights. It outlives config reloads that leave the split
// unchanged (see Registry), so its state does too.
type Route struct {
	label    string
	cfg      config.TrafficSplitConfig
	names    []string
	baseline int
	salt     string
	now      func() time.Time

	mu      sync.Mutex
	weights Weights
}

// Option customises a Route.
type Option func(*Route)

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Route) { r.now = now }
}

// NewRoute compiles cfg, a validated traffic split, for the route
// labelled label.
func NewRoute(label string, cfg config.TrafficSplitConfig, opts ...Option) (*Route, error) {
	if len(cfg.Variants) == 0 {
		return nil, fmt.Errorf("split: route %s has no variants", label)
	}
	r := &Route{label: label, cfg: cfg, now: time.Now, baseline: -1}
	for _, opt := range opts {
		opt(r)
	}
	w := make(Weights, len(cfg.Variants))
	for i, v := range cfg.Variants {
		r.names = append(r.names, v.Name)
		w[i] = v.Weight
		if v.Name == cfg.Baseline {
			r.baseline = i
		}
	}
	if r.baseline < 0 {
		r.baseline = 0
	}
	r.weights = w
	r.salt = cfg.Sticky.Salt
	if r.salt == "" {
		r.salt = label
	}
	return r, nil
}

// Label returns the route's label.
func (r *Route) Label() string { return r.label }

// Names returns the variant names in config order.
func (r *Route) Names() []string { return append([]string(nil), r.names...) }

// Index returns the position of the variant called name.
func (r *Route) Index(name string) (int, bool) {
	for i, n := range r.names {
		if n == name {
			return i, true
		}
	}
	return 0, false
}

// Baseline returns the baseline variant's index.
func (r *Route) Baseline() int { return r.baseline }

// Weights returns the current weights.
func (r *Route) Weights() Weights {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.weights.Clone()
}

// Select chooses req's variant.
func (r *Route) Select(req *http.Request, c Client) Decision {
	return r.decide(r.Weights().Pick(r.bucket(c)), SourceWeight)
}

func (r *Route) decide(i int, source string) Decision {
	if i < 0 {
		i = r.baseline
	}
	return Decision{Index: i, Name: r.names[i], Source: source}
}

// identity returns what the client is known by for sticky assignment:
// the configured identity, or its address when the request doesn't
// carry that identity. Prefixes keep an API key from ever hashing like
// an IP that happens to be the same string.
func (r *Route) identity(c Client) string {
	switch r.cfg.Sticky.By {
	case config.StickyAPIKey:
		if c.APIKey != "" {
			return "key:" + c.APIKey
		}
	case config.StickyJWTSubject:
		if c.JWTSubject != "" {
			return "jwt:" + c.JWTSubject
		}
	case config.StickyClientCert:
		if c.CertID != "" {
			return "cert:" + c.CertID
		}
	}
	if c.IP != "" {
		return "ip:" + c.IP
	}
	return ""
}

// bucket returns the client's bucket: its identity's hash, or a random
// bucket for a client with no identity at all (it can't be kept sticky).
func (r *Route) bucket(c Client) int {
	id := r.identity(c)
	if id == "" {
		return RandomBucket()
	}
	return Bucket(r.salt, id)
}
