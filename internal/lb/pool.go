package lb

import (
	"errors"
	"hash/fnv"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/circuitbreaker"
	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
)

var (
	// ErrNoHealthyBackend means every backend of the route is unhealthy
	// (failing probes or passively ejected) or draining.
	ErrNoHealthyBackend = errors.New("lb: no healthy backend available")
	// ErrAllCircuitsOpen means healthy backends exist, but every one of
	// them has an open circuit breaker.
	ErrAllCircuitsOpen = errors.New("lb: circuit breaker open on every healthy backend")
)

// PoolConfig configures a Pool.
type PoolConfig struct {
	Route      string
	Strategy   string // a config.LB* constant; "" = round_robin
	HashHeader string // consistent_hash key header; "" = client IP

	PassiveEnabled bool
	Passive        config.PassiveHealthConfig // with defaults applied

	HealthCheck config.HealthCheckConfig // Enabled false = no probes
}

// Pool is one route's set of backends and the policy for choosing
// between them.
type Pool struct {
	cfg      PoolConfig
	backends []*Backend
	metrics  *metrics.Metrics
	logger   *log.Logger

	rr   atomic.Uint64 // round_robin / tie-break counter
	ring *hashRing     // ip_hash / consistent_hash

	wrrMu      sync.Mutex
	wrrCurrent map[*Backend]int

	checker *healthChecker
}

// NewPool builds a pool over backends. It doesn't start health checks;
// see Start.
func NewPool(cfg PoolConfig, backends []*Backend, m *metrics.Metrics, logger *log.Logger) *Pool {
	if logger == nil {
		logger = log.Default()
	}
	if cfg.Strategy == "" {
		cfg.Strategy = config.LBRoundRobin
	}
	p := &Pool{cfg: cfg, backends: backends, metrics: m, logger: logger, wrrCurrent: map[*Backend]int{}}
	if cfg.Strategy == config.LBIPHash || cfg.Strategy == config.LBConsistentHash {
		p.ring = newHashRing(backends)
	}
	return p
}

// Backends returns the pool's backends.
func (p *Pool) Backends() []*Backend { return p.backends }

// Route returns the pool's route label.
func (p *Pool) Route() string { return p.cfg.Route }

// Single reports whether the pool has exactly one backend.
func (p *Pool) Single() bool { return len(p.backends) == 1 }

// Pick chooses a backend for r among those that are healthy, not
// draining, and whose circuit breaker isn't open. exclude removes
// backends whose breaker just refused this request (a full Half-Open
// trial). Backends for which avoid returns true — ones a retry already
// tried — are used only if nothing else qualifies, so a single-backend
// route still retries against its one backend, as it always has.
//
// It returns ErrAllCircuitsOpen when healthy backends exist but every
// one's breaker is refusing traffic, and ErrNoHealthyBackend when no
// backend is healthy at all.
func (p *Pool) Pick(r *http.Request, avoid, exclude func(*Backend) bool) (*Backend, error) {
	var candidates, preferred []*Backend
	healthy := 0
	for _, b := range p.backends {
		if !b.Available() {
			continue
		}
		healthy++
		if exclude != nil && exclude(b) {
			continue
		}
		if cb := b.Breaker(); cb != nil && cb.State() == circuitbreaker.Open {
			continue
		}
		candidates = append(candidates, b)
		if avoid == nil || !avoid(b) {
			preferred = append(preferred, b)
		}
	}
	switch {
	case len(candidates) == 0 && healthy > 0:
		return nil, ErrAllCircuitsOpen
	case len(candidates) == 0:
		return nil, ErrNoHealthyBackend
	case len(preferred) > 0:
		candidates = preferred
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return p.choose(candidates, r), nil
}

func (p *Pool) choose(c []*Backend, r *http.Request) *Backend {
	switch p.cfg.Strategy {
	case config.LBLeastConnections:
		return p.leastConnections(c)
	case config.LBWeightedRoundRobin:
		return p.smoothWeighted(c)
	case config.LBRandom:
		return weightedRandom(c)
	case config.LBIPHash:
		return p.ring.lookup(ClientIP(r), c)
	case config.LBConsistentHash:
		key := ""
		if p.cfg.HashHeader != "" {
			key = r.Header.Get(p.cfg.HashHeader)
		}
		if key == "" {
			key = ClientIP(r)
		}
		return p.ring.lookup(key, c)
	default: // round_robin
		return c[(p.rr.Add(1)-1)%uint64(len(c))]
	}
}

// leastConnections picks the backend with the fewest in-flight requests
// relative to its weight; ties rotate so equal backends share load.
func (p *Pool) leastConnections(c []*Backend) *Backend {
	start := int((p.rr.Add(1) - 1) % uint64(len(c)))
	best := c[start]
	bestLoad, bestWeight := best.InFlight(), int64(best.Settings().Weight)
	for i := 1; i < len(c); i++ {
		b := c[(start+i)%len(c)]
		load, weight := b.InFlight(), int64(b.Settings().Weight)
		// load/weight < bestLoad/bestWeight, without division.
		if load*bestWeight < bestLoad*weight {
			best, bestLoad, bestWeight = b, load, weight
		}
	}
	return best
}

// smoothWeighted is nginx's smooth weighted round robin: over any window
// of sum(weights) picks each backend is chosen weight times, interleaved
// rather than in bursts.
func (p *Pool) smoothWeighted(c []*Backend) *Backend {
	p.wrrMu.Lock()
	defer p.wrrMu.Unlock()
	total := 0
	var best *Backend
	for _, b := range c {
		w := b.Settings().Weight
		total += w
		p.wrrCurrent[b] += w
		if best == nil || p.wrrCurrent[b] > p.wrrCurrent[best] {
			best = b
		}
	}
	p.wrrCurrent[best] -= total
	return best
}

func weightedRandom(c []*Backend) *Backend {
	total := 0
	for _, b := range c {
		total += b.Settings().Weight
	}
	n := rand.IntN(total)
	for _, b := range c {
		n -= b.Settings().Weight
		if n < 0 {
			return b
		}
	}
	return c[len(c)-1]
}

// ClientIP is the address hash strategies key on: the first
// X-Forwarded-For entry when present (the original client behind any
// proxies in front of Gatekeeper), otherwise the connection's address.
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// hashRing is a consistent hash ring with virtual nodes. It's built over
// all of the pool's backends, so when one becomes unavailable only the
// keys that mapped to it move — everyone else stays where they were.
type hashRing struct {
	points []uint64
	owner  map[uint64]*Backend
}

const virtualNodesPerWeight = 160

func newHashRing(backends []*Backend) *hashRing {
	r := &hashRing{owner: map[uint64]*Backend{}}
	for _, b := range backends {
		for i := 0; i < virtualNodesPerWeight*b.Settings().Weight; i++ {
			h := hash64(b.Label() + "#" + strconv.Itoa(i))
			if _, taken := r.owner[h]; taken {
				continue
			}
			r.owner[h] = b
			r.points = append(r.points, h)
		}
	}
	sort.Slice(r.points, func(i, j int) bool { return r.points[i] < r.points[j] })
	return r
}

// lookup returns the first backend clockwise from key's position that is
// among candidates.
func (r *hashRing) lookup(key string, candidates []*Backend) *Backend {
	allowed := make(map[*Backend]bool, len(candidates))
	for _, b := range candidates {
		allowed[b] = true
	}
	h := hash64(key)
	start := sort.Search(len(r.points), func(i int) bool { return r.points[i] >= h })
	for i := 0; i < len(r.points); i++ {
		if b := r.owner[r.points[(start+i)%len(r.points)]]; allowed[b] {
			return b
		}
	}
	return candidates[0]
}

func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	// FNV's low bits are weak for short keys; mix them (splitmix64).
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// Report records the outcome of a real request to b for passive health
// checking: consecutive failures (timeouts, connection errors, 5xx) eject
// it for the configured period.
func (p *Pool) Report(b *Backend, success bool) {
	outcome := "failure"
	if success {
		outcome = "success"
	}
	if p.metrics != nil {
		p.metrics.BackendRequests.WithLabelValues(p.cfg.Route, b.Label(), outcome).Inc()
	}
	if !p.cfg.PassiveEnabled {
		return
	}
	if success {
		b.passiveFailures.Store(0)
		return
	}
	if b.passiveFailures.Add(1) < int64(p.cfg.Passive.ConsecutiveFailures) {
		return
	}
	b.passiveFailures.Store(0)
	until := time.Now().Add(p.cfg.Passive.EjectionDuration.Duration)
	b.ejectedUntil.Store(until.UnixNano())
	if p.metrics != nil {
		p.metrics.BackendEjections.WithLabelValues(p.cfg.Route, b.Label()).Inc()
	}
	p.logger.Printf("lb: route %s: backend %s ejected for %s after %d consecutive failures",
		p.cfg.Route, b.Label(), p.cfg.Passive.EjectionDuration.Duration, p.cfg.Passive.ConsecutiveFailures)
}

// Start begins active health checking, if configured.
func (p *Pool) Start() {
	if p.cfg.HealthCheck.Enabled && p.checker == nil {
		p.checker = startHealthChecker(p)
	}
}

// Stop ends active health checking.
func (p *Pool) Stop() {
	if p.checker != nil {
		p.checker.stop()
		p.checker = nil
	}
}
