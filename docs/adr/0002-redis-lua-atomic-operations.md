# 2. Redis + Lua scripts for atomic distributed rate limiting

## Status

Accepted

## Context

When Gatekeeper runs behind a load balancer with multiple instances, rate
limits need to be enforced fleet-wide, not per-instance — a client
shouldn't get `burst` requests through each instance it happens to land
on. That means the `Store.Increment` and `Store.CompareAndSwap` operations
(`internal/ratelimiter/store/store.go`) have to be atomic across
instances, not just within one process.

The obvious naive approach — a separate `GET`, then compute, then `SET` —
is not atomic: two instances can both read the same value, both decide a
request is allowed, and both write, letting more requests through than
the configured limit. Redis transactions (`MULTI`/`EXEC`) don't fully
solve this either, since they can't make a decision that depends on the
value they just read without an extra round trip (`WATCH`), which
reintroduces a race window under contention.

## Decision

`RedisStore` (`internal/ratelimiter/store/redis.go`) implements both
`Increment` and `CompareAndSwap` as single Lua scripts, run server-side
via `EVAL`. Redis executes a Lua script as one atomic unit — no other
command interleaves in the middle of it — so the read-modify-write that
Token Bucket and Sliding Window Log need happens as one round trip, with
no race window between reading state and writing the updated value.

## Consequences

- Multiple Gatekeeper instances pointed at the same Redis share one
  correct view of every client's rate-limit state, with no double-counted
  bursts from a check-then-act race.
- Each `Allow` call costs one Redis round trip per attempt (occasionally
  more than one, if `CompareAndSwap` loses a race against a concurrent
  writer and retries — see `maxCASRetries` in
  `internal/ratelimiter/tokenbucket.go`), which is slower than the
  in-memory store's mutex, and shows up directly in the benchmark numbers
  in the README.
- The scripts are middleware-agnostic Lua with no external dependencies,
  so they run on stock Redis (and on `miniredis` in tests — see
  `internal/ratelimiter/store/redis_test.go` — without needing a real
  Redis instance in CI).
