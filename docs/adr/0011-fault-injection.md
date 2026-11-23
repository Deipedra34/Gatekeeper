# 11. Fault injection: decided in the router, injected per backend attempt, off by default

## Status

Accepted

## Context

Gatekeeper's retries, circuit breakers, health checks, load balancing,
cache, and traffic splits are only trustworthy if they've been seen to
handle failure. Waiting for a real outage to find out is too late, and
breaking a backend on purpose is slow and coarse. Fault injection lets
an operator delay, abort, or reset a chosen share of a route's requests
instead. Four decisions shape it:

1. **Where in the pipeline a fault takes effect**, which decides what it
   exercises and what it skips.
2. **What an injected fault counts as**: a backend failure, or something
   the gateway's resilience features should ignore.
3. **How to keep it from hurting production by accident**, since the
   feature exists to make requests fail.
4. **How rules are managed at runtime** while the config they started
   from can be reloaded.

## Decision

### Decided once in the router, injected per attempt in the retry transport

The router asks the fault registry once per request, after access
control, auth, and rate limiting have run and after the traffic split
picked a variant, but before request transforms rewrite the path. Rules
can therefore target the path and headers the client sent, the variant,
and the client's tier, API key, or address. The decision (delay, abort
status, reset) goes into the request context.

The retry transport applies it to each backend attempt, after the load
balancer picked the backend and its circuit breaker admitted the attempt,
in place of the call to the backend. An injected 503 is retried, counted
by the breaker and passive health check, and reported in metrics exactly
like a real backend's. A rule can target one backend, and a retry then
moves to another one as it would in a real outage. A request served from
the cache never reaches the fault, and a cached response is never a
faulted one: a reset leaves nothing to store.

The other option was a middleware in front of the router. It's simpler,
but faults injected there never reach retries, breakers, health checks,
or the load balancer, which are the things worth testing.

A delay respects the attempt's context, so `proxy.timeout` fails a long
delay the way it fails a slow backend, and a client that goes away ends
the delay at once. The delay is a timer in a `select`, with no goroutine
of its own. A connection reset fails the attempt with a connection error,
and once retries are spent the router hijacks the client connection and
closes it with `SO_LINGER 0`, so the client sees a TCP RST. On HTTP/2,
where hijacking isn't possible, the stream is aborted.

Reset takes precedence over abort, and a delay can go with either.

### Counted as backend failures by default

`count_as_backend_failure` defaults to true, because exercising the
resilience features is the point. Set to false, the fault is applied
before the attempt starts and answered at once: it's never retried, never
reported to the breaker or health check, and its delay runs outside the
per-attempt timeout. That's for testing clients' handling of slow or
failing responses without tripping the gateway's own protections.

### Safe by default

- Every rule is off unless it's `enabled`, and nothing is injected unless
  the global kill switch `fault_injection.global_enabled` is on. Turning
  the kill switch off with a reload stops everything at once.
- With nothing in force, the per-request cost is one atomic load of a nil
  snapshot, with no allocation.
- The admin listener, `/metrics`, the common health check paths, and
  known health check probes (by User-Agent, Gatekeeper's own included)
  are never faulted, whatever a rule says.
- `max_duration` makes a config rule expire on its own, and runtime rules
  always have a TTL (at most 24h). A reload that leaves a rule unchanged
  keeps its countdown going, so a reload can't extend an experiment.
- In a production-like `environment` (production or staging), a 100%
  abort or reset is rejected unless the rule sets `allow_full_abort`.
- A warning naming every rule in force, with its remaining time, is
  logged at startup and on every reload. `gatekeeper_fault_injection_active`
  is 1 while anything is in force, so a dashboard can show it.

### Runtime rules beside config rules

The admin API adds runtime rules with a TTL. They live in a registry that
outlives reloads, like the traffic split registry, and are tried before
the route's config rule, newest first; the first matching rule decides.
Runtime rules aren't persisted or shared between instances: an experiment
is meant to be short and local, and a restart ending it is a feature.
Deleting a config rule through the API lasts until the next reload, which
reads it from the file again.

## Consequences

- Injected failures behave like real ones all the way through the
  gateway, so retries, breakers, health checks, and split guardrails can
  be tested without touching a backend. The flip side is that a counted
  fault can open a breaker or eject a backend for everyone on that route.
  That is the intended effect, and the docs say so.
- Faults are injected per attempt, so a retried request shows up in the
  counters once per attempt, and a 5xx abort with retries costs that many
  attempts' worth of backoff.
- Rules are per instance. In a fleet, each instance needs the same config
  or the same API calls.
- The reset relies on hijacking. Behind a proxy that terminates the
  client connection, the client sees whatever that proxy does with a
  reset upstream connection.
