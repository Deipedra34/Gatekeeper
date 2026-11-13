# 9. IP access control: sorted range tables and right-most-untrusted client addresses

## Status

Accepted

## Context

Gatekeeper needed IP allow and deny lists, global and per route, plus
temporary bans for addresses that keep misbehaving. Two decisions shape
everything else:

1. **How to match an address against a list.** Lists are often long:
   deny lists built from threat feeds or cloud provider ranges easily
   reach thousands or tens of thousands of entries, and the check runs on
   every request. A linear scan over `netip.Prefix.Contains` costs ~44µs
   per request at 10,000 entries. That's more than the rest of the
   in-memory pipeline put together, and it grows with the list.
2. **Which address is the client's.** Behind a load balancer, the TCP
   peer is the load balancer, and the client is somewhere in
   `X-Forwarded-For`. But anyone can send that header. The existing
   rate limiter keyed `ip` scope on the raw header, and
   `transform.trust_forwarded_headers` trusted it from every peer. Both
   are fine for limiting and forwarding. For access control they would
   make every deny list trivially bypassable and every allowlist
   trivially satisfiable.

## Decision

### Matching: a sorted table of disjoint ranges

Each list is compiled once, at load and on every reload, into two
sorted slices of non-overlapping closed ranges: `[lo, hi]` as `uint32`
for IPv4 and as a 128-bit pair for IPv6. Every prefix becomes the range
of addresses it covers. The ranges are sorted by start, and
overlapping or adjacent ones are merged. A lookup is one binary search
for the first range ending at or after the address, then one
comparison with its start.

- O(log n) per lookup with no allocation. ~10–65ns from 10 to 100,000
  entries in the benchmarks.
- Duplicated, nested, and adjacent entries collapse at compile time, so
  they cost nothing at lookup time and a messy feed doesn't slow
  requests.
- It's ~150 lines with no dependencies, and it's easy to test against
  a linear scan (the tests do, over thousands of generated entries).
- IPv4-mapped IPv6 addresses are unmapped on both sides, so
  `::ffff:192.0.2.1` matches `192.0.2.0/24`.

A binary (radix) trie was the obvious alternative. It gives
O(prefix length) lookups, but it chases one pointer per bit level,
allocates many small nodes, and only matters if we need *which* entry
matched (longest-prefix match for routing). Access lists only need
"is it in the set", which the range table answers with better cache
behaviour and a fraction of the memory. If per-entry metadata (for
example, per-range deny statuses) is ever needed, the table can carry a
value per range, or be swapped for a trie behind the same `PrefixSet`
API.

Every entry is parsed by `config.Load`, so an invalid address or CIDR
fails startup, or rejects a reload, with its exact location
(`access_control.deny[3]`). A list that can't do anything (entries with
`mode: off`, or `allowlist_only` with an empty allow list) is refused
for the same reason.

### Client address: the peer, unless a trusted proxy says otherwise

- The client address is the **TCP peer address** by default.
  Forwarding headers are ignored.
- Only when the peer is in `access_control.trusted_proxies` are
  `X-Forwarded-For` and `X-Real-IP` read. The client is the
  **right-most `X-Forwarded-For` address that isn't a trusted proxy**.
  Each proxy appends the address it got the request from, so walking
  right to left past the proxies we trust reaches the first hop that
  nobody we trust vouches for. Everything left of it may have been
  written by the client. The left-most entry, which many
  implementations use, is exactly the one a client controls. If a hop
  isn't a valid address, the walk stops at the last trusted hop rather
  than trusting anything beyond it.
- `trusted_proxies` is a separate setting from
  `transform.trust_forwarded_headers` on purpose. That setting is about
  what gets *forwarded to backends* and keeps its existing,
  all-or-nothing meaning, so no existing config changes behaviour. If
  it's on without `trusted_proxies`, a startup log line says that access
  control uses the peer address. (The address parsing lives in the
  `accesscontrol` package rather than reusing `transform`'s, because
  `config` validates lists through `accesscontrol`, and `transform`
  imports `config`.)
- With access control on, the rate limiter's `ip` scope uses the same
  resolved address, so auto-ban, the lists, and rate limiting agree on
  who the client is. Without access control nothing changes.
- Trusted proxies can never be banned, since that would ban every
  client behind them.

### Bans: per-address keys in the existing store

A ban is a key in the store the rate limiter already uses, with a TTL
equal to the ban. It expires on its own, and with Redis it's shared by
every instance. Offenses are counted with the store's `Increment`, a
fixed window per address. Only the increment that lands exactly on the
threshold issues a ban, which makes the decision race-free across
instances without a new store primitive. A small index key (address
to expiry, updated with compare-and-swap) exists only for listing bans
and the active-bans gauge. Requests never read it.

### Placement

Access control runs first in the middleware chain, before request IDs,
the per-request logger, CORS, auth, and the rate limiter. A blocked
request costs one lookup (plus one ban lookup if it passes the lists),
consumes no rate limit tokens, and never reaches the cache, the circuit
breaker, or a backend. The middleware isn't installed at all without an
`access_control` section.

## Consequences

- Lookups stay cheap however long the lists get. Compiling is the
  expensive part (~28ms for 100,000 entries), and it happens once per
  load or reload, off the request path. The compiled tables are
  swapped in atomically with the rest of the pipeline, so in-flight
  requests finish on the lists they started with.
- Operators behind a proxy must list it in `trusted_proxies`.
  Otherwise every request appears to come from the proxy. That's the
  safe failure: a missing entry makes allowlists stricter, it never
  lets a spoofed address through.
- With Redis, every request that passes the lists costs one extra
  `GET` for the ban check, about the same as the rate limiter's own
  round trip. If the store is down, the ban check fails open, matching
  the rate limiter's policy.
- An address is banned at most once per offense window, and a
  still-banned address isn't re-banned. Bans therefore can't be
  extended or escalated by the traffic they're already blocking.
- The ban index is a single key. Under a huge number of simultaneous
  bans its compare-and-swap updates contend, but only listing and the
  gauge depend on it. Enforcement uses the per-address keys.
