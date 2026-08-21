# 1. Token Bucket as the default rate-limiting algorithm

## Status

Accepted

## Context

Gatekeeper ships three interchangeable algorithms — Token Bucket, Sliding
Window Log, Fixed Window Counter — behind the same `ratelimiter.Limiter`
interface (see `internal/ratelimiter/ratelimiter.go`). Something has to be
the default in `configs/config.yaml` for anyone who hasn't thought about
the trade-offs yet, and that default shapes most users' first impression
of the gateway.

Fixed Window Counter is the cheapest of the three, but it can let up to 2x
the configured limit through in a short burst that straddles a window
boundary (see `TestFixedWindow_BoundaryCanDoubleAllowedRequests`). Sliding
Window Log is exact, but its per-client storage and per-request work both
scale with `burst`, which gets expensive at high-limit tiers.

## Decision

Token Bucket is the default algorithm. It allows short bursts up to
`burst` immediately, then converges to the configured `requests_per_second`
sustained rate via continuous refill — no boundary doubling, and no
per-request cost that scales with the configured limit. Per-client state
is a fixed size regardless of burst: one float64 token count and one
timestamp.

## Consequences

- New users who don't touch `rate_limit.algorithm` get smooth, predictable
  limiting without the Fixed Window boundary artifact.
- Token Bucket's Allow path costs more than Fixed Window's single atomic
  increment — it's a Load-then-CompareAndSwap loop with float math (see
  `internal/ratelimiter/tokenbucket.go`) — but that cost stays flat as
  `burst` grows, unlike Sliding Window Log.
- Anyone who genuinely needs exact enforcement (Sliding Window Log) or
  needs to shave off every last bit of per-request cost at the price of
  boundary bursts (Fixed Window) can still opt in via config; Token Bucket
  is a default, not a mandate.
