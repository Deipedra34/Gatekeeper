# 8. Request and response transformation with a fixed variable whitelist

## Status

Accepted

## Context

Backends rarely want the request exactly as the client sent it. A route
mounted at `/api` often needs the prefix removed; a renamed backend API
needs `/api/v1/...` mapped to `/v2/...`; backends want a client identity
or request ID in a header; and backend responses leak `Server` and
`X-Powered-By` details or lack basic security headers.

A transformation feature is also an easy way to create problems:

- A rewrite applied *before* the cache key is computed, or forgotten when
  computing it, serves one request's response to another.
- A header value template that can read arbitrary request headers can
  copy a client's API key or JWT to a backend that was never meant to see
  it.
- A transform that can remove or set `Connection`, `Host`,
  `X-Forwarded-For`, or the rate limit headers can break framing, spoof a
  client address, or hide what the gateway did.
- Regex engines with backtracking turn a rewrite rule into a denial of
  service.

## Decision

- **Per route, opt in, and compiled at load.** Each route can have a
  `transform` section; a route without one is forwarded byte for byte as
  before. Everything — regexes, header names, value templates — is
  parsed and validated when the config loads (and on every SIGHUP
  reload), never on the request path.
- **One place, one order.** The router applies the transform after auth
  and rate limiting, which see the request as the client sent it, and
  before everything else: the response cache, retries, backend
  selection, and WebSocket upgrades all use the transformed request. The
  request steps run in a fixed order — `strip_prefix`, `rewrite`, query
  parameters, then headers (remove, set, add) — so a config reads the
  same way it behaves.
- **The cache key follows the forwarded request.** The key already uses
  the request's path and query, which are now the transformed ones. It
  also includes the final value of every header the transform sets,
  because the backend's response may depend on it (a `X-Tenant:
  ${client_id}` header must split the cache by tenant). Per-request IDs
  (`${request_id}`, `${trace_id}`) are left out of the key, so a
  correlation header doesn't turn every request into a miss; putting one
  in a query parameter on a cached route is rejected at load instead.
- **A fixed variable whitelist.** Values may use exactly six variables:
  `${client_ip}`, `${request_id}`, `${client_id}`, `${client_tier}`,
  `${route}`, and `${trace_id}`. Each is either chosen by the gateway or
  already known to the backend; `${client_id}` is the same label
  `/metrics` uses, so an API key appears only as its fingerprint. There
  is deliberately no "copy request header X" or "environment variable"
  form. Unknown variables, unterminated `${`, and control characters
  (which could inject headers) fail validation; variable values are
  stripped of control characters at runtime too.
- **Protected headers.** Transforms can't touch hop-by-hop headers,
  `Content-Length`, `Sec-WebSocket-*`, `Host`, the forwarding headers,
  the request ID header, and, in responses, `Content-Encoding`, the rate
  limit headers, `X-Cache`, `Strict-Transport-Security`, and the
  configured trace header. Each of these has an owner elsewhere in the
  gateway. A header the gateway sets is also taken off the client's
  `Connection` list, so a client can't ask the proxy to strip it as
  hop-by-hop.
- **Forwarding headers are not trusted by default.** With
  `transform.trust_forwarded_headers: false` (the default), client
  `X-Forwarded-*`, `Forwarded`, and `X-Real-IP` are dropped and set from
  the connection. `true` restores the earlier pass-through behaviour for
  deployments behind a trusted proxy. `${client_ip}` follows the same
  setting.
- **RE2 only.** Rewrites use Go's `regexp` (RE2), which matches in time
  linear in the input with no backtracking, so there is no catastrophic
  backtracking to guard against. Patterns are additionally capped at
  1024 characters, Go caps repetition counts at 1000, and a replacement
  that references a capture group the pattern doesn't have is rejected
  rather than silently expanding to nothing.
- **Response headers at write time.** Response transforms and security
  headers are applied when the response headers are written, so they
  cover backend responses, cached responses, the gateway's own errors on
  the route, and WebSocket 101s alike, and a reload takes effect
  immediately even for responses already in the cache. Security headers
  are only added when the response doesn't already set them.

## Consequences

- Existing configs keep proxying exactly as before, with one deliberate
  exception: forwarding headers. Deployments behind another proxy that
  relied on Gatekeeper passing `X-Forwarded-For` through unchanged need
  `trust_forwarded_headers: true`.
- The rate limiter still identifies `ip`-scoped clients as before
  (including `X-Forwarded-For`); `trust_forwarded_headers` governs what
  is forwarded and what `${client_ip}` means, not rate limit identity.
- A route that sets a header from the client identity caches per
  client. That is the correct trade-off, but it lowers the hit rate.
- Anything beyond the whitelist (copying arbitrary headers, request
  bodies, scripting) needs a new, reviewed variable rather than a
  config-only change.
