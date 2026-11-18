# 10. Traffic splitting: bucket hashing in config order and one-way, per-instance rollback

## Status

Accepted

## Context

Gatekeeper needed to split a route's traffic between variants for
canary releases and A/B tests: a share of clients goes to a new
version, a rollout raises that share over time, and a version that
misbehaves loses its traffic again without anyone being paged first.
Three decisions shape the design:

1. **How a client is assigned to a variant.** Assignments must be
   sticky (a user shouldn't flip between versions from one click to the
   next), match the weights over many clients, survive reloads and
   restarts, agree across instances, and move as few clients as
   possible when weights change. They must also not let the public pick
   the canary.
2. **How a rollback is decided and applied.** Rolling back too eagerly
   (on five unlucky requests) or flapping a canary on and off are both
   worse than not having the feature.
3. **Where the live state lives.** Weights change at runtime (rollout
   steps, admin actions, rollbacks), while the config they started from
   can be reloaded underneath them.

## Decision

### Assignment: a stable hash into buckets owned in config order

The client's identity (its address by default, or its API key, JWT
subject, or certificate identity) is hashed with FNV-1a and a 64-bit
finalizer, salted with the route's label, into one of 10,000 buckets.
Each variant owns a contiguous range of buckets in the order the config
lists the variants, sized by its weight: with `[90, 10]`, stable owns
0-8999 and canary 9000-9999.

- The hash depends on nothing but the salt and the identity. FNV is
  fixed by its specification, unlike Go's map hash, so assignments
  don't change between processes, instances, Go versions, or reloads,
  and an unrelated config change moves nobody. Tests pin a few bucket
  values so an accidental change to the hash fails loudly.
- Because ranges follow config order, raising the last variant's weight
  only moves the clients at the boundary, from the variants before it
  to it. Listing stable first makes a growing canary strictly
  monotonic: no client is ever moved off the canary by its own rollout.
- Plain consistent hashing (a ring) was the alternative. It also
  minimises movement, but its shares are only approximately the
  weights unless many virtual nodes are used, and it doesn't give
  "grow the canary, never shrink it for anyone" for free. With
  percentages as the unit, contiguous ranges are exact and simpler.
- A client with no usable identity falls back to its address. With
  `sticky.by: cookie`, the bucket itself is stored in a cookie signed
  with HMAC-SHA256: storing the bucket rather than the variant means
  cookie clients move with weight changes and rollbacks exactly like
  hashed clients, and the signature means a client can't write its own
  bucket to choose a variant.

Overrides and rules sit in front of the hash: an override header from
an allowlisted client (by tier, API key, or CIDR) first, then match
rules in order, then the bucket. An override with an empty allowlist is
refused at load unless `anyone: true` says so explicitly.

### Rollback: guardrails with a minimum sample, one-way, then a cooldown

Each guarded variant has its own rolling window (ten slices of the
configured length), recording requests, 5xx responses, and a
logarithmic latency histogram for the p95, alongside a window of the
baseline's requests of the same length. At most once a second, inline
as requests finish, a variant with traffic is compared with the
baseline:

- The variant isn't judged before it has served `min_requests` in the
  window. The latency check also needs `min_requests` on the baseline.
  The error check compares with whatever the baseline has, counting no
  baseline traffic as 0% errors, which errs towards rolling back.
- A rollback is one-way: the variant's share goes to the baseline, a
  running rollout stops, and nothing raises the variant again on its
  own. Only an operator (`resume`, `set`, `promote`) can.
- For a cooldown after an automatic rollback, the admin API refuses to
  give the variant traffic again unless the request says `force`. The
  windows are reset at each rollback, so the requests that caused one
  can't cause a second.
- Evaluation recovers from panics: a bug in the guardrails can't break
  the request whose completion triggered the check.

Doing this inline rather than on a ticker means no goroutine per route
to start, stop, and keep in step with reloads, and an idle route costs
nothing. The rollout schedule is evaluated lazily in the same way: the
current step is derived from the time whenever weights are read.

### State: per instance, shared across a reload when the split is unchanged

A route's live state (weights an operator set, the rollout's progress,
the last rollback, cooldowns, guardrail windows) is held in memory, in
a registry that outlives reloads. When a reload rebuilds a route whose
weights, baseline, rollout, and guardrails are configured as before,
the new route shares the old one's state object, so a reload that only
touches backends, stickiness, overrides, rules, or headers changes none
of it, and requests still in flight on the old router see the same
state as new ones. A change to those settings is a deliberate change to
the split, so the route starts again from the new config.

The state isn't shared through the store across instances. Every
request reads the weights, so a store round trip per request was not an
option, and a shared view would also need a single place that decides
rollbacks from fleet-wide windows. Instead each instance judges the
traffic it serves and keeps its own weights, while stickiness, which
depends only on the client and the route, is consistent everywhere.

## Consequences

- Routes without `traffic_split` run no split code, keep their cache
  keys, log lines, and metrics, and behave exactly as before.
- Each variant is a backend pool of its own with its own retry
  transport, so retries, circuit breakers, health checks, and draining
  stay inside the variant without any special casing. Cache keys
  include the variant, so variants never share entries.
- Admin changes and automatic rollbacks are per instance. In a fleet,
  run admin actions against every instance; with guardrails, each
  instance rolls back on the evidence it sees, which may happen a few
  seconds apart across instances.
- The order of variants in the config matters for how clients move when
  weights change. That's documented: list the stable variant first.
- Without a configured secret, cookie signing uses a secret generated
  at startup, so cookies are reassigned after a restart. A startup log
  line says so.
