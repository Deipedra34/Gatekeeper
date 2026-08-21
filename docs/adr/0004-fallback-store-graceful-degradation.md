# 4. FallbackStore for graceful degradation when Redis is unreachable

## Status

Accepted

## Context

When `storage.backend: redis` is configured, Redis becomes a dependency
the gateway needs on every request. If Gatekeeper's own uptime is tied
directly to Redis's uptime, a Redis outage takes the whole gateway down
with it — every request either blocks or errors out, even though a
degraded-but-functional gateway (per-instance limits instead of
fleet-wide ones) is clearly better than no gateway at all.

## Decision

`FallbackStore` (`internal/ratelimiter/store/fallback.go`) wraps a
primary `Store` (Redis in practice) with a secondary `Store` (always
in-memory), and switches between them automatically:

- **At startup**, `cmd/gatekeeper` pings Redis. If that fails, it logs a
  warning and starts in fallback mode instead of refusing to boot.
- **At runtime**, every operation tries the primary first. Any error
  flips an atomic `healthy` flag to false and routes that call — and
  every call after it — to the secondary, until the flag flips back.
  A `CompareAndSwap(true, false)` on that flag means the warning is
  logged once per outage, not once per failed request.
- **In the background**, a health-check loop pings the primary every
  `checkInterval` (5 seconds in `cmd/gatekeeper`'s wiring). The first
  successful ping after an outage flips `healthy` back to true and logs
  the recovery.

Because `FallbackStore` itself implements `Store`
([ADR 3](0003-store-interface-abstraction.md)), none of the algorithms or
middleware need to know failover is happening at all.

## Consequences

- A Redis outage degrades Gatekeeper to per-instance limiting — the same
  behavior as if `storage.backend: memory` had been configured all
  along — instead of crashing or hanging. This is exactly the trade-off
  documented in the README's "Graceful degradation" section.
- The health check is a poll, not a push, so recovery detection lags by
  up to `checkInterval`. That's a deliberate trade: a tighter interval
  detects recovery faster but pings Redis more often for no benefit once
  it's healthy.
- The atomic flag means the health-check goroutine and every request
  goroutine touch shared state without a mutex, which keeps the hot path
  (`healthy.Load()`) cheap — a single atomic read per request instead of
  a lock.
