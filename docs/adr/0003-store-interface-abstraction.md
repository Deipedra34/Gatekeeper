# 3. A Store interface to decouple algorithms from storage backends

## Status

Accepted

## Context

Gatekeeper needs to support both a zero-dependency in-memory backend
(for single-instance deployments) and Redis (for fleet-wide limits), and
it needs all three rate-limiting algorithms to work identically against
either one. Without a shared abstraction, either every algorithm gets
written twice (once per backend), or the algorithms end up calling
Redis-specific or map-specific operations directly, making it impossible
to add a third backend later without touching every algorithm.

## Decision

All algorithms are written against one `Store` interface
(`internal/ratelimiter/store/store.go`), exposing exactly three
operations: `Increment` (a TTL'd counter, used by Fixed Window Counter),
and `Load`/`CompareAndSwap` (optimistic-concurrency key/value access,
used by Token Bucket and Sliding Window Log for read-modify-write state).
`MemoryStore` and `RedisStore` each implement this interface once, and
every algorithm is written once against the interface, not against
either backend.

A single conformance test suite
(`internal/ratelimiter/store/conformance_test.go`) runs the same
behavioral assertions against both implementations, so `MemoryStore` and
`RedisStore` are held to identical guarantees instead of drifting apart.

## Consequences

- Switching `storage.backend` in config between `memory` and `redis` is
  the only thing that changes — no algorithm code, and no middleware
  code, cares which one is in use.
- The interface is deliberately narrow (three methods plus `Ping`/
  `Close`), which is what makes `FallbackStore`
  (`internal/ratelimiter/store/fallback.go`) possible: it can wrap any
  `Store` around any other `Store` without knowing what either one is,
  because both just implement the same three operations.
- The trade-off is that every backend has to express its state in terms
  of these three primitives even when a richer, backend-specific API
  would be more efficient for a given operation. So far this hasn't been
  a real constraint — Redis's Lua scripts and the in-memory mutex both
  map onto `Increment`/`Load`/`CompareAndSwap` cleanly.
