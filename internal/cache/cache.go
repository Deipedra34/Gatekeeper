// Package cache implements Gatekeeper's response cache for GET requests.
// Backend responses are stored in a store.Store — the same abstraction
// the rate limiter uses, memory or Redis — keyed by route, backend
// target, method, URL, and a few headers that can legitimately change
// the response body without changing the URL. A cache hit is served
// directly, without the request ever reaching the proxy's retry
// transport or the backend.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/ratelimiter/store"
)

// BypassHeader lets a client skip the cache entirely for one request —
// no read, no write — so a route can be debugged without waiting out
// its configured TTL.
const BypassHeader = "X-Bypass-Cache"

// varyHeaders lists the request headers folded into the cache key
// alongside the method and URL. A response can legitimately differ
// across these without the URL changing: Authorization/X-API-Key scope
// a response to a specific caller, and Accept affects content
// negotiation.
var varyHeaders = []string{"Authorization", "X-API-Key", "Accept"}

// keyPrefix namespaces cache entries in the shared Store so they never
// collide with the rate limiter's own keys (client identifiers, which
// carry no prefix of their own) in the same backend.
const keyPrefix = "gatekeeper:cache:"

// Entry is a cached backend response, capturing everything needed to
// replay it byte-for-byte on a later cache hit.
type Entry struct {
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"body"`
}

// Cache stores GET responses in a store.Store. It never returns a raw
// store error to a caller that can't sensibly handle one — Get and Set
// both report failure so the caller can fail open (treat it as a miss,
// go to the backend) instead of crashing when Redis is unreachable.
//
// Cache also keeps an index of the entries this process wrote — route,
// request URI, and expiry, never the response — since keys are hashes
// and can't be matched against a route or URL prefix after the fact.
// That index is what admin purges and stats work from.
type Cache struct {
	store store.Store

	mu    sync.Mutex
	index map[string]Meta
	sets  int // Set calls since the index was last pruned

	hits, misses, writes, purged atomic.Int64
}

// Meta describes a cached entry for the admin API: the route that cached
// it and the request URI (path and query) it answers.
type Meta struct {
	Route string
	URI   string

	expiresAt time.Time
}

// pruneEvery is how many writes go by between sweeps of expired entries
// out of the index, so it stays bounded by what's live in the store.
const pruneEvery = 1024

// New creates a Cache backed by st. st is typically the same store the
// rate limiter uses (including a FallbackStore, if storage.backend is
// "redis"), so a Redis outage degrades caching the same way it degrades
// rate limiting.
func New(st store.Store) *Cache {
	return &Cache{store: st, index: map[string]Meta{}}
}

// Key builds the cache key for a request served by the route identified
// by routeLabel and target. Including target means a config reload that
// repoints a route at a different backend can never serve a stale entry
// cached under the old backend.
func Key(routeLabel, target string, r *http.Request) string {
	h := sha256.New()
	writePart := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	writePart(routeLabel)
	writePart(target)
	writePart(r.Method)
	writePart(r.URL.RequestURI())
	for _, name := range varyHeaders {
		writePart(name + "=" + r.Header.Get(name))
	}
	return keyPrefix + hex.EncodeToString(h.Sum(nil))
}

// Bypass reports whether r asks to skip the cache entirely.
func Bypass(r *http.Request) bool {
	return r.Header.Get(BypassHeader) != ""
}

// Storable reports whether a response carrying header is allowed to be
// cached at all: it must not have set Cache-Control: no-store.
func Storable(header http.Header) bool {
	for _, v := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return false
			}
		}
	}
	return true
}

// Get returns the cached entry for key, if present and unexpired. A
// store error comes back as (nil, false, err); callers should treat
// that the same as a miss and log the failure rather than fail the
// request.
func (c *Cache) Get(ctx context.Context, key string) (*Entry, bool, error) {
	raw, err := c.store.Load(ctx, key)
	if err == store.ErrNotFound {
		c.misses.Add(1)
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false, err
	}
	c.hits.Add(1)
	return &e, true, nil
}

// Set stores entry under key with the given ttl. It's best-effort: if
// another request races to populate the same key first, Set leaves that
// write in place rather than retrying, since both requests are caching
// the same backend response anyway.
func (c *Cache) Set(ctx context.Context, key string, entry *Entry, ttl time.Duration) error {
	return c.SetFor(ctx, key, Meta{}, entry, ttl)
}

// SetFor is Set, also recording meta in the index so the entry can later
// be purged by route or URL prefix.
func (c *Cache) SetFor(ctx context.Context, key string, meta Meta, entry *Entry, ttl time.Duration) error {
	newVal, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	old, err := c.store.Load(ctx, key)
	if err != nil && err != store.ErrNotFound {
		return err
	}
	if err == store.ErrNotFound {
		old = nil
	}

	ok, err := c.store.CompareAndSwap(ctx, key, old, newVal, ttl)
	if err != nil || !ok {
		return err
	}
	c.writes.Add(1)
	meta.expiresAt = time.Now().Add(ttl)
	c.mu.Lock()
	c.index[key] = meta
	if c.sets++; c.sets >= pruneEvery {
		c.pruneLocked(time.Now())
	}
	c.mu.Unlock()
	return nil
}

func (c *Cache) pruneLocked(now time.Time) {
	c.sets = 0
	for k, m := range c.index {
		if now.After(m.expiresAt) {
			delete(c.index, k)
		}
	}
}

// PurgeFilter selects the entries Purge removes. Both fields empty means
// every entry; when both are set an entry must match both.
type PurgeFilter struct {
	// Route matches the route label exactly (its path prefix, or its
	// host for a host route).
	Route string
	// URLPrefix matches the start of the cached request URI.
	URLPrefix string
}

func (f PurgeFilter) matches(m Meta) bool {
	if f.Route != "" && m.Route != f.Route {
		return false
	}
	return f.URLPrefix == "" || strings.HasPrefix(m.URI, f.URLPrefix)
}

// Purge deletes the indexed entries matching f and returns how many it
// removed — or, with dryRun, how many it would remove, touching nothing.
//
// It only knows about entries this process cached. With a Redis store
// shared by several gateways, run it against each one; entries another
// instance cached expire on their own TTL.
func (c *Cache) Purge(ctx context.Context, f PurgeFilter, dryRun bool) (int, error) {
	c.mu.Lock()
	c.pruneLocked(time.Now())
	var keys []string
	for k, m := range c.index {
		if f.matches(m) {
			keys = append(keys, k)
		}
	}
	c.mu.Unlock()
	if dryRun {
		return len(keys), nil
	}

	n := 0
	for _, k := range keys {
		if err := c.store.Delete(ctx, k); err != nil {
			return n, err
		}
		c.mu.Lock()
		delete(c.index, k)
		c.mu.Unlock()
		n++
	}
	c.purged.Add(int64(n))
	return n, nil
}

// Stats is a point-in-time summary of the cache, for the admin API.
type Stats struct {
	// Entries counts the unexpired entries this process cached, in total
	// and per route.
	Entries        int            `json:"entries"`
	EntriesByRoute map[string]int `json:"entries_by_route"`
	// Hits, Misses, Writes, and Purged count since startup. Hits and
	// Misses are lookups that found or didn't find an entry; a store
	// error counts as neither.
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
	Writes int64 `json:"writes"`
	Purged int64 `json:"purged"`
}

// Stats returns the cache's current Stats.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	c.pruneLocked(time.Now())
	byRoute := map[string]int{}
	for _, m := range c.index {
		byRoute[m.Route]++
	}
	entries := len(c.index)
	c.mu.Unlock()
	return Stats{
		Entries: entries, EntriesByRoute: byRoute,
		Hits: c.hits.Load(), Misses: c.misses.Load(), Writes: c.writes.Load(), Purged: c.purged.Load(),
	}
}
