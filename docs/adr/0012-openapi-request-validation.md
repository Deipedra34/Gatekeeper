# 12. OpenAPI request validation: kin-openapi, in the router, on a bounded copy of the body

## Status

Accepted

## Context

Routes can now check requests against an OpenAPI 3.x spec, rejecting
invalid ones (`enforce`) or logging and counting them (`report_only`).
Four decisions shape it:

1. **Which validator to use.** OpenAPI request validation covers a lot:
   operation matching with path templates and server URLs, parameter
   styles and explode rules, content types, and JSON Schema with its
   formats, combinators, and `$ref`s.
2. **Where in the pipeline it runs**, which decides what an invalid
   request still costs and what it can reach.
3. **How the body is read**, since validation needs the body before the
   backend does, and a gateway that truncates, double-reads, or buffers
   unbounded bodies is worse than one that doesn't validate.
4. **What may appear in errors, logs, and spans**, since what fails
   validation is often exactly what a client shouldn't have sent:
   credentials and personal data in the wrong field.

## Decision

### kin-openapi rather than a validator of our own

We use `github.com/getkin/kin-openapi`: its loader to parse and check the
spec, its gorilla/mux-based router to resolve a request to an operation,
and `openapi3filter.ValidateRequest` to check parameters and bodies. It's
widely used and actively maintained, supports OpenAPI 3.0 and 3.1, and
has years of fixes for the edge cases (parameter serialisation styles,
path template matching, format and regex handling) that a validator
written for this would have to rediscover one bug report at a time.

What we take from it, and what we don't:

- **Specs load from local files only.** The loader's `$ref` reader reads
  local files and refuses URLs, so loading a spec never touches the
  network.
- **Hosts are ignored.** Server URLs are reduced to their paths before
  the router is built. The gateway knows which host a request arrived
  on; the spec's idea of its public hostname is irrelevant here.
- **No defaults, no auth.** `SkipSettingDefaults` keeps kin-openapi from
  writing spec defaults into the request; the backend gets what the
  client sent. Security requirements are dropped at load, and
  `NoopAuthenticationFunc` stands in, because authentication already
  happened in the gateway.
- **Our own messages.** kin-openapi's error text can include the failing
  value (always, for OpenAPI 3.1 specs, whose schemas go through a JSON
  Schema 2020-12 validator). We never use it. Messages are rebuilt from
  each schema error's keyword and schema ("must be at most 100", "must
  match the pattern ..."), with the field named by its JSON pointer.
- **Compiled once.** The spec and its router are compiled when the
  router is built, once per file, and shared read-only by every request.
  A reload that finds the file and everything it `$ref`s unchanged (by
  SHA-256) reuses the compiled spec.

The cost is a dependency with a few of its own (gorilla/mux, a JSON
Schema validator, a YAML library), and per-request work measured in
microseconds to tens of microseconds rather than nanoseconds. Both are
acceptable for a feature that's off unless a route turns it on.

### In the router, after rate limiting, before everything with effects

Validation runs inside the router, once the route is matched: after
access control, auth, CORS, and rate limiting, and before the traffic
split, fault injection, request transforms, the cache, retries, circuit
breakers, and the backend.

- **After auth**, so an unauthenticated client can't probe the spec
  through validation errors, and so credentials can be left to auth
  entirely (below).
- **After rate limiting.** Validation is the most expensive step before
  the backend. Behind the rate limiter, its cost per client is bounded by
  that client's limit, and an invalid request spends budget like any
  other, so invalid payloads aren't a free way to load the gateway. The
  alternative, validating first so invalid requests cost no tokens, would
  hand an attacker unmetered CPU.
- **Before the split, faults, cache, breaker, and backend**, so a
  rejected request picks no variant (and doesn't skew guardrails), is
  never faulted, never reads or fills the cache, never counts toward a
  circuit breaker, and never reaches a backend.
- **In the router rather than in a middleware**, because that's where
  the route, its transforms, and its settings are known after the one
  route match the router already does. A route without validation pays a
  single nil check.

The spec describes the backend, so the request is validated as the
backend will receive it: on a copy with the route's request transform
applied (`strip_prefix`, `rewrite`, query and header changes). The real
request is transformed later, as before. A header the gateway sets
satisfies a spec that requires it, and paths in the spec are the
backend's paths.

WebSocket upgrades, the metrics path, and the common health check paths
(matched exactly) are never validated. Unlike fault injection, health
check probes aren't recognised by `User-Agent`: for a feature that
rejects requests, anything a client can claim is a way around it.

### The body: read once, bounded, restored, and checked in a copy

- **Bounded.** At most `max_body_bytes` (1 MiB by default) are read. A
  `Content-Length` over the limit means the body isn't read at all; a
  chunked body is read until it passes the limit. Either way the request
  is invalid (`body_too_large`, 413 in enforce mode).
- **Restored, never truncated.** The bytes read go back on the request
  for the backend. If the body was over the limit, what was read is put
  back in front of the unread rest (`io.MultiReader`), so in
  `report_only` mode the backend still gets the whole body, and the
  retry transport buffers it as it always has.
- **No double reads.** kin-openapi reads the body itself, so it gets its
  own reader over the same bytes, on its own copy of the request (its
  own URL and header map, without credential headers). It never touches
  the request that goes on to the backend.
- **Only what can be checked.** Bodies are read only when they'll be
  checked: JSON of a declared media type by default, other declared
  types with `validate_non_json_bodies`. Anything else is forwarded
  unread. A JSON body without a Content-Type is checked as JSON, so
  dropping the header doesn't skip validation.
- **Depth before decoding.** One allocation-free pass over the bytes
  checks the JSON nesting depth against `max_json_depth` before the body
  is decoded, since both the decoder and the schema walk recurse once per
  level.
- **A deadline.** The schema checks run on a goroutine with a timeout
  (100ms by default). A check that runs over is given up on and the
  request is invalid (`timeout`); the abandoned check finishes on its own
  copy, and a buffered channel means it never blocks. A panic in the
  library is recovered and reported as `internal`. The timeout starts
  after the body is read: slow clients are the server's read timeout's
  business.

### Nothing the client sent goes back out

Credential headers (`Authorization`, `Proxy-Authorization`, `Cookie`,
and the API key header) are removed from the validated copy, and the
spec's cookie parameters and credential header parameters are dropped
at load, so a secret never reaches the validator at all. Error bodies,
log lines, and span attributes name fields and rules, never values.
Field names that come from the client (JSON property names) are cut to
64 bytes and stripped of control characters, an error lists at most 20
faults, and log lines quote the path and leave out the query string.
Metric labels are the route and a reason from a fixed list of seven.

## Consequences

- Validation is opt-in per route, costs nothing where it's off, and can
  be rolled out in `report_only` mode, watching
  `gatekeeper_validation_report_only_violations_total` and the
  rate-limited logs, before switching to `enforce`.
- A request is validated against the backend's view of it, so specs can
  be the backend's own, unchanged.
- A missing or invalid spec fails startup, and fails a reload as a
  whole, keeping the previous config and specs. That's consistent with
  every other config error, though it means a broken spec also holds
  back unrelated config changes until it's fixed.
- Validated requests with bodies are buffered up to `max_body_bytes`
  before the backend sees a byte, which adds latency for large uploads.
  Routes that stream large bodies should validate parameters only (use
  a spec without a request body schema) or leave validation off.
- Counts in `GET /admin/v1/validation` are per instance and kept in
  memory; Prometheus is the place for fleet-wide numbers.
- Responses aren't validated. That would need buffering every response
  and has a different audience (backend developers, not clients); it can
  be added later on the same spec.
