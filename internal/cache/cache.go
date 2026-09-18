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
type Cache struct {
	store store.Store
}

// New creates a Cache backed by st. st is typically the same store the
// rate limiter uses (including a FallbackStore, if storage.backend is
// "redis"), so a Redis outage degrades caching the same way it degrades
// rate limiting.
func New(st store.Store) *Cache {
	return &Cache{store: st}
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
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false, err
	}
	return &e, true, nil
}

// Set stores entry under key with the given ttl. It's best-effort: if
// another request races to populate the same key first, Set leaves that
// write in place rather than retrying, since both requests are caching
// the same backend response anyway.
func (c *Cache) Set(ctx context.Context, key string, entry *Entry, ttl time.Duration) error {
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

	_, err = c.store.CompareAndSwap(ctx, key, old, newVal, ttl)
	return err
}
