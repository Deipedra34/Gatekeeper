# 6. Load balancing: per-backend state, per-attempt selection, and drain-on-reload

## Status

Accepted

## Context

Until now each route proxied to exactly one `target`. Running more than
one instance of a backend meant putting another load balancer behind
Gatekeeper, which then hid from the gateway the very failures its retries
and circuit breaker exist to handle. Routes needed to spread traffic over
several backends, notice when one of them is down, and route around it.
None of that could change anything for the many existing single-target
configs.

## Decision

- **A route has a pool of backends; a single `target` is a pool of one.**
  There's one code path, not two, and a single-target route goes through
  it unchanged. Retries still hit its one backend. Its cache keys,
  route-level circuit breaker gauge, and responses are the same as before.
  Passive ejection is off by default for it, because with nowhere else to
  send traffic, ejecting the only backend would just turn errors into
  503s.
- **The backend is chosen per attempt, inside the retry transport.** It
  isn't chosen once per request. A retry therefore *prefers* a healthy
  backend it hasn't tried, and falls back to tried ones only when nothing
  else is left. Retries become failover, and the single-backend case
  falls out naturally.
- **Health, the circuit breaker, and the in-flight count live on the
  backend, not the route.**
  - One bad backend trips only its own breaker.
  - A backend whose breaker is open is skipped at selection time, so
    requests go to its siblings rather than failing fast.
  - The route fails fast with `503` only when *every* healthy backend's
    circuit is open, or when no backend is healthy at all.
- **Two independent health signals.**
  - Active probes catch a backend that's down before users do, and bring
    it back once it recovers.
  - Passive ejection reacts to real traffic within a few requests, without
    waiting for the next probe, and expires on its own, so a backend that
    only had a bad moment returns automatically.
  - Both feed one `Healthy()` predicate.
- **Selection strategies are small functions over the current candidate
  list.**
  - Weighted round robin uses nginx's smooth algorithm, so weights
    interleave rather than arriving in bursts.
  - Least-connections is weight-aware and breaks ties by rotation.
  - `ip_hash` and `consistent_hash` use a consistent hash ring with
    virtual nodes built over *all* backends. When one leaves rotation,
    only its clients move, and they move back when it returns.
  - Counters are atomics; the only lock is around the weighted round
    robin state.
- **Reloads reuse backends.**
  - A reload builds a new router whose backends are matched to the old
    one's by route and target. An unchanged backend is the *same object*,
    so its health, breaker, and in-flight count carry over. Its new
    settings (weight, TLS transport) are staged, and only take effect once
    the whole reload has succeeded.
  - A backend that's gone drains. It gets no new requests, keeps serving
    the ones in flight, and after `drain_timeout` whatever remains is
    cancelled. That includes its WebSocket tunnels, which are closed with
    `1001`, and cancelled HTTP attempts can be retried on a backend that's
    still in rotation.
  - A reload that fails part-way leaves the live backends exactly as they
    were.
- **Backend state metrics are computed at scrape time** from a registry
  of live backends, so a removed backend's gauges disappear on their own
  instead of going stale.

## Consequences

- Existing single-target configs keep their behaviour, and the test
  suite written for them passes unchanged.
- A route can fail over between backends without an external load
  balancer, and that's visible per backend in metrics and traces
  (`gatekeeper.backend` on every attempt span).
- Health is per gateway instance. Several Gatekeeper replicas each probe
  and eject on their own observations, and don't share health state.
  That's simpler and fails independently, at the cost of N× probe
  traffic and briefly different views of a flapping backend.
- `consistent_hash` keys on the client IP or a header the client sends.
  It provides stickiness, not affinity guarantees: a client can choose its
  key, so it must never be used for anything security-sensitive.
- Reusing backend objects across reloads means backend identity is
  "route label + target URL". Changing either, even only the route's path
  prefix, creates a fresh backend with fresh state, and the old one
  drains.
