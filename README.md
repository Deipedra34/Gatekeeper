<p align="center">
  <img src="docs/banner.svg" alt="Gatekeeper — rate limiter and API gateway, built with Go" width="100%" />
</p>

# Gatekeeper

[![CI](https://github.com/Deipedra34/Gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/Deipedra34/Gatekeeper/actions/workflows/ci.yml)

Gatekeeper is a rate limiter and API gateway written in Go. It sits in front of your backend services, decides which requests get through based on per-client limits, and proxies the rest to wherever they're supposed to go. Metrics and graceful degradation come standard, not bolted on afterward.

I built it as a reference implementation more than a one-off tool. All three rate-limiting algorithms you'd actually reach for in production — Token Bucket, Sliding Window Log, Fixed Window Counter — run against the same storage abstraction, so switching one for another (or memory for Redis) is a config change, not a rewrite.

## Features

- **Three pluggable rate-limiting algorithms.** Token Bucket, Sliding Window Log, Fixed Window Counter, selectable via config, all built on one `Store` interface.
- **Two storage backends.** An in-memory map for single-instance deployments, or Redis when you need limits coordinated across a fleet.
- **Reverse proxy core.** Routes requests to backend services by path prefix or hostname, using `net/http/httputil.ReverseProxy` under the hood.
- **Configurable backend timeout and retry.** Every backend attempt is bounded by a per-attempt timeout; a timeout, connection failure, or 5xx response is retried with exponential backoff and jitter, up to a configurable limit. 4xx responses are never retried.
- **A normal middleware chain.** Rate limiting, request logging, API key / JWT auth, and CORS, composed the same way you'd compose any `net/http` middleware.
- **API keys and JWTs, per route.** Each route requires an API key, a JWT (HS256 or RS256), or either one. Existing configs keep plain API key auth without any changes.
- **Per-client tiers.** Limits scoped by API key, source IP, a custom header, or a JWT claim, with independent free/premium/whatever tiers defined in config (or picked by a JWT claim).
- **A Prometheus-compatible `/metrics` endpoint.** Requests allowed/rejected per client and tier, current limiter state, request latency histograms, cache hits/misses per route, circuit breaker state and rejections per route, auth successes/failures by method.
- **Response caching for GET requests.** Backend responses are cached per route in the same storage backend the rate limiter uses (memory or Redis), with a configurable TTL, an opt-out per route, and a header to bypass the cache for debugging.
- **A circuit breaker around every backend call.** Closed / Open / Half-Open, configurable per route, so a struggling backend gets a break from traffic instead of every request queuing up behind retries and timeouts.
- **WebSocket proxying.** `Upgrade: websocket` requests are routed like any other request and pass through CORS, auth, and the rate limiter (one token per connection attempt). After that, frames are relayed transparently in both directions. Per-route idle timeouts, connection caps per route and per client, `Origin` allow-lists, metrics, and graceful close on shutdown are all included.
- **TLS and mTLS.** An optional HTTPS listener with TLS 1.2+ by default, hot-reloaded certificates (on `SIGHUP` or file change), client certificate verification, an `mtls` route auth mode with certificate-based client identity and tiers, HSTS, an HTTP→HTTPS redirect, and TLS / mTLS to backends.
- **Distributed tracing.** Optional OpenTelemetry traces with a span per pipeline stage and per backend attempt (retries are visible), W3C `traceparent` / `baggage` propagation in and out, OTLP gRPC/HTTP export, parent-based sampling, trace IDs in log lines and an optional response header. Secrets never reach spans, and a dead collector never slows a request.
- **Dynamic config reload.** `SIGHUP` re-reads the config file and swaps routes, rate-limit rules, tiers, and algorithm into the running gateway atomically — no restart, no dropped requests. An invalid config is logged and ignored, leaving the old one in place.
- **Graceful degradation.** If Redis goes down — at startup or mid-run — Gatekeeper falls back to in-memory limiting and logs a warning instead of taking the gateway down with it.

## Architecture

```mermaid
flowchart LR
    Client([Client])

    subgraph GW["Gatekeeper"]
        direction TB
        CORS["CORS middleware"]
        Auth["Auth\n(API key / JWT, per route)"]
        RL["Rate limiter middleware"]
        Proxy["Reverse proxy router\n(path prefix / host match)"]
        Metrics["/metrics endpoint"]

        CORS --> Auth --> RL --> Proxy
    end

    Store[("Store interface")]
    Mem[("MemoryStore\n(sync-protected map)")]
    Redis[("RedisStore\n(go-redis + Lua scripts)")]
    CB{{"Circuit breaker\n(per route)"}}

    Client -->|HTTP request| CORS
    RL <-->|Increment / Load / CAS| Store
    Proxy <-->|GET cache Get / Set| Store
    Store -.->|primary| Redis
    Store -.->|fallback on outage| Mem

    Proxy <-->|Allow / Report| CB
    CB -.->|Open: fail fast, no backend call| Proxy
    Proxy --> BackendA["Backend service A"]
    Proxy --> BackendB["Backend service B"]

    Client -.->|GET /metrics| Metrics
```

Every request runs through the same chain: CORS, then auth (API key or JWT, depending on the route), then the rate limiter, then the proxy. The limiter and the proxy don't know about each other — the limiter just needs a client key and a `Store`, the proxy just needs a routing table — so you can test, swap, or reason about either one on its own.

### Package layout

```
cmd/gatekeeper/        entrypoint: wires storage + metrics, runs the server, handles signals
internal/gateway/      assembles the request pipeline from config; rebuilds and swaps it on SIGHUP
internal/config/       YAML config loading, defaults, and validation
internal/ratelimiter/  the three algorithms + the Store abstraction they share
  └─ store/            MemoryStore, RedisStore, and FallbackStore (Redis → memory failover)
internal/proxy/        the reverse-proxy router (path prefix / hostname matching), backend timeout + retry/backoff, GET response caching, circuit breaker integration
internal/cache/        the response cache: key derivation, Cache-Control handling, Store-backed get/set
internal/circuitbreaker/ the Closed/Open/Half-Open state machine wrapped around each route's backend calls
internal/server/       the listeners: plain HTTP or HTTPS (mTLS, certificate hot reload, HSTS), plus the HTTP→HTTPS redirect
internal/tracing/      OpenTelemetry setup (exporters, sampling, OTEL_* overrides), the server span, and span/propagation helpers
internal/certgen/      throwaway CA / server / client certificate generation for tests and scripts/gencerts
internal/websocket/    WebSocket upgrade detection, the frame relay, and the hub tracking open connections (limits, idle timeout, shutdown)
  └─ wstest/           a minimal WebSocket client/server used by tests and scripts/wsclient
internal/middleware/   logging, CORS, API key + JWT auth, rate-limit middleware
internal/metrics/      Prometheus collectors + /metrics handler
configs/                example config.yaml
scripts/loadtest/      goroutine-based load generator (see "Load testing" below)
scripts/wsclient/      tiny WebSocket client for trying out WebSocket proxying
observability/         OpenTelemetry Collector config for docker-compose.tracing.yml
scripts/gencerts/      writes a development CA plus server and client certificates (see "TLS and mTLS")
```

## Rate-limiting algorithms: trade-offs

`ratelimiter.Limiter` has three implementations. All of them read the same two config knobs per tier — `requests_per_second` and `burst` — but they don't interpret those knobs the same way (see the doc comment on `ratelimiter.Rule` if you want the exact mapping).

| Algorithm | How it works | Accuracy | Cost | Trade-off |
|---|---|---|---|---|
| **Token Bucket** | Each client has a bucket of `burst` tokens that refills continuously at `requests_per_second`. Each request costs one token. | Smooth, no boundary weirdness. Bursts up to `burst` go through immediately; the sustained rate converges to whatever you configured. | O(1) storage per client (a float token count plus a timestamp), one optimistic CAS retry loop per request. | The default I'd reach for most of the time. Costs a bit more CPU and storage than Fixed Window because of the CAS loop and float math, but it's rarely the bottleneck. |
| **Sliding Window Log** | Every allowed request's timestamp gets logged. A request is allowed only if fewer than `burst` timestamps are still inside the trailing 1-second window. | Exact. There's no "more correct" than this one — no boundary doubling, ever. | O(`burst`) storage per client (one timestamp per request in the window) and O(`burst`) work per check just to prune the log. | The most precise option, but also the priciest. For high-limit tiers you're storing hundreds of timestamps per client and shipping that blob to Redis on every request. Works best when `burst` stays modest. |
| **Fixed Window Counter** | Time gets sliced into aligned 1-second windows; each client has one counter per window that resets on rollover. | The weakest guarantee of the three: a client can send `burst` requests at the very end of one window and another `burst` right at the start of the next — up to 2x the configured limit in a short span (`TestFixedWindow_BoundaryCanDoubleAllowedRequests` shows exactly this). | By far the cheapest: one atomic `INCR`-style op per request, O(1) storage. | Reach for this when throughput matters more than fairness at the margins — a coarse global ceiling rather than a strict per-client promise. |

All three share the same `Store` interface (`Increment`, `Load`, `CompareAndSwap`), so switching `rate_limit.algorithm` in config is the only thing you need to change to try a different trade-off against the same storage backend.

## Storage backends

- **`memory`** (default) — a `sync.Mutex`-protected map, local to the process. Fastest option, no external dependencies, but each instance enforces its own limit. Fine if you're running one instance, wrong if you're behind a load balancer.
- **`redis`** — counters live in Redis via [go-redis](https://github.com/redis/go-redis), so every instance behind that load balancer enforces one shared limit per client. `Increment` and `CompareAndSwap` are each a single Lua script, so the read-modify-write is atomic as far as Redis is concerned.

### Graceful degradation

When `storage.backend: redis` is set, Gatekeeper wraps the Redis store in a `FallbackStore`:

- At startup it pings Redis. If that fails, it logs a warning and just starts in fallback mode instead of refusing to boot.
- At runtime, any Redis error on a request sends that request (and everything after it) to the in-memory store, with a warning logged once per outage rather than once per request.
- A background check pings Redis every 5 seconds. Once it's back, Gatekeeper logs the recovery and starts using it again.

The trade-off while Redis is down: limits become per-instance instead of fleet-wide, same as if you'd configured `memory` in the first place — until Redis comes back. What doesn't happen is a crash or a gateway that stops responding.

## Backend request timeout and retry

Every request the proxy forwards to a backend is bounded by `proxy.timeout` and, if it fails, retried according to `proxy.retry` — both configurable in `configs/config.yaml`:

```yaml
proxy:
  timeout: 5s          # per-attempt timeout (default: 5s)
  retry:
    max_retries: 3     # additional attempts after the first (default: 3)
    base_backoff: 100ms # delay before the first retry (default: 100ms)
    max_backoff: 2s      # cap on the backoff delay (default: 2s)
```

All four fields are optional; any left unset get the defaults shown above.

- **Timeout** applies per attempt, not to the whole request — a request that ends up retrying 3 times can take up to roughly `4 × timeout` plus backoff delays in the worst case, not just `timeout`.
- **Retries** kick in only for failures a retry can plausibly fix: a timed-out attempt, a connection error (backend down/unreachable), or a `5xx` response. A **`4xx` response is never retried** — it means the backend understood the request and rejected it, and sending the same request again wouldn't change that.
- **Backoff** is exponential with jitter: the delay before retry *n* is `min(base_backoff × 2^(n-1), max_backoff)`, then a random value between 0 and that number is actually used, so many clients retrying at once don't all hit the backend in the same instant.
- The request body is buffered so it can be replayed identically on every retry attempt.
- If every attempt fails, the proxy returns whatever the last attempt produced: the backend's own `5xx` if that's what kept coming back, or a `502 Bad Gateway` if the backend was unreachable.

**Interaction with rate limiting and metrics:** the rate limiter middleware sits in front of the proxy and only ever sees the original incoming request once, so retries against the backend never cost a client extra rate-limit budget — a request that retries twice before succeeding still counts as exactly one allowed request against that client's limit. Retry attempts and final outcomes are tracked as their own metrics, separate from the raw allow/reject counters (see [Metrics](#metrics) below).

## Circuit breaker

Every route's backend calls go through a circuit breaker with three states:

- **Closed** — normal operation. Requests go to the backend as usual; failures are counted.
- **Open** — the backend has failed too many times in a row. Every request is **failed fast** with `503 Service Unavailable` — the backend is never contacted at all — until the configured cooldown elapses.
- **Half-Open** — after the cooldown, a limited number of trial requests are let through to check whether the backend has recovered. Everything else still fails fast while a trial is in flight.

```mermaid
stateDiagram-v2
    [*] --> Closed
    Closed --> Open: failure_threshold consecutive failures
    Open --> HalfOpen: open_duration cooldown elapses
    HalfOpen --> Closed: half_open_successes_to_close trial successes
    HalfOpen --> Open: half_open_failures_to_reopen trial failures
```

**What counts as a failure** is the same definition the retry logic uses: a timed-out attempt, a connection error, or a `5xx` response. A `4xx` response counts as a *success* for the breaker's purposes — the backend answered the request correctly, it just didn't like what the client sent, which says nothing about the backend's health. Any success (including a `4xx`) resets the consecutive-failure count while Closed.

**Configuration** — per route, in `configs/config.yaml`:

```yaml
routes:
  - path_prefix: "/api/users"
    target: "http://localhost:9001"
    circuit_breaker:
      enabled: true                        # default: true
      failure_threshold: 5                 # default: 5 consecutive failures
      open_duration: 30s                   # default: 30s cooldown
      half_open_max_requests: 1            # default: 1 concurrent trial
      half_open_successes_to_close: 1      # default: 1 trial success closes it
      half_open_failures_to_reopen: 1       # default: 1 trial failure reopens it
```

All fields are optional; omitting `circuit_breaker` entirely gives you the defaults shown above. Set `enabled: false` to exempt a route from circuit breaking altogether — for a backend where you'd always rather wait/retry than ever get a fast-fail 503, for instance.

**Interaction with retries.** The breaker is checked before every attempt a request makes, not just once per incoming request — so if a request's first attempt fails and pushes the breaker from Closed to Open, its *own* second attempt (and any further retries) sees the Open circuit and fails fast immediately: **no retry is made into an already-open circuit**. That fail-fast check happens before the retry's backoff delay too, so a circuit that's already open doesn't even pay the backoff wait before giving up. A circuit-open rejection isn't counted as a retry attempt in `gatekeeper_proxy_retries_total`, and it doesn't consume any of `proxy.retry.max_retries` — it's a distinct outcome from a retried-and-failed backend call, tracked in its own metric (see below). Like retries, this all happens below the rate limiter middleware, so a fast-failed request still counts as exactly one allowed request against the client's rate limit, same as any other outcome.

## Response caching

Gatekeeper caches `GET` responses per route, so repeated requests for the same resource are answered directly without touching the backend at all.

**How it's keyed.** A cache entry is keyed on the route, the backend target, the request method, the full URL (path + query string), and a few request headers that can legitimately change the response body for the same URL: `Authorization`, `X-API-Key`, and `Accept`. Two requests only share a cache entry if all of those match — different API keys, different query strings, or a different `Accept` value each get their own entry. Keying on the backend target as well as the route means a `SIGHUP` reload that repoints a route at a different backend can never serve a stale entry cached under the old one.

**What gets cached.** Only `GET` responses with a `200` status. A backend response carrying `Cache-Control: no-store` is never cached, no matter the route's configuration — every request for it reaches the backend. Anything other than `GET` (`POST`, `PUT`, `DELETE`, ...) always goes straight to the backend; caching never applies to it.

**Configuration** — per route, in `configs/config.yaml`:

```yaml
routes:
  - path_prefix: "/api/users"
    target: "http://localhost:9001"
    cache:
      enabled: true   # default: true — set false to opt this route out entirely
      ttl: 30s        # default: 60s
```

Both fields are optional. Omitting `cache` entirely gives you caching enabled with the default 60s TTL; set `enabled: false` for routes that must never be cached (anything with side effects on `GET`, or responses that are personalized in a way the cache key doesn't account for).

**Bypassing the cache.** Send `X-Bypass-Cache` (any non-empty value) on a request to skip the cache entirely for that one request — no read, no write — useful for confirming what the backend itself currently returns without waiting out the TTL or disabling caching for everyone else. Every cacheable response also carries an `X-Cache: HIT` or `X-Cache: MISS` header, so you can tell which path served a given response.

**Storage and graceful degradation.** Cached entries live in the same storage backend configured under `storage:` — the in-memory map, or Redis via the same `FallbackStore` the rate limiter uses. That means a Redis outage degrades caching exactly the way it degrades rate limiting: reads and writes fail open (skip the cache, go to the backend) rather than erroring or crashing the gateway, with a warning logged. A cache hit is served before the request ever reaches the proxy's retry transport, so it never triggers a backend retry and never costs an extra backend call.

**Interaction with rate limiting:** caching sits behind the rate limiter in the middleware chain, so a cached response still consumes the client's rate-limit budget exactly like an uncached one — caching saves the backend a request, not the client their quota.

## WebSocket proxying

Every route proxies WebSocket connections as well as plain HTTP. A request carrying `Connection: Upgrade` and `Upgrade: websocket` is matched to a route with the same hostname / path-prefix rules as any other request, runs through the same middleware chain, and, once the backend accepts the upgrade, gets a two-way tunnel to that backend. Existing configs pick this up with no changes, because `websocket` defaults to `true`.

**Request flow.**

1. **The middleware chain runs first.** CORS, API key / JWT auth (per the route's `auth_mode`), and the rate limiter all see the upgrade request before anything is upgraded. A failed check answers with the usual `401` / `429`, and the backend is never contacted.
2. **Route policy.** The router then checks `websocket`, `ws_allowed_origins`, `ws_max_connections`, and `ws_max_connections_per_client`, and the route's circuit breaker.
3. **Backend handshake.** The handshake is forwarded to the backend unchanged (`Sec-WebSocket-*`, `Origin`, credentials, and so on), with the incoming `Host` kept and the client's address appended to `X-Forwarded-For`, the same as for HTTP routes. If the backend answers `101 Switching Protocols`, the client gets that `101` with the backend's handshake headers, plus the `X-RateLimit-*` and CORS headers the chain added. If the backend answers anything else, that response is passed to the client as-is.
4. **Relay.** Frames are relayed in both directions, byte for byte. Masking, extensions such as `permessage-deflate`, fragmentation, and ping/pong all pass through untouched. The relay reads frame boundaries but never changes frame contents. Knowing the boundaries lets the gateway send its own Close frame between frames when it needs to, without ever splitting a frame.

**How it interacts with the rest of the gateway.**

| Feature | Behaviour for WebSocket |
|---|---|
| Rate limiting | Each connection attempt (handshake) costs one token. Frames never touch the limiter, so a client can send as many messages as it likes over a connection it already has. |
| `proxy.timeout` | Bounds the backend handshake only: dial, upgrade request, and `101` response. It never applies to an established connection. |
| `server.read_timeout` / `write_timeout` | Cleared as soon as the connection is upgraded. A long-lived WebSocket is not killed by the server's HTTP timeouts. |
| Retries | Never. An upgrade request is sent once. A failed handshake goes straight back to the client (`502` if the backend is unreachable, otherwise the backend's own response). |
| Response caching | Never. Upgrade requests skip the cache entirely: no read, no write. |
| Circuit breaker | Counts **handshakes** only. A dial failure, timeout, or `5xx` handshake response is a failure, and a `101` is a success. How long a connection then stays open, and how it ends, is never reported. An open circuit fails new handshakes fast with `503`. Connections that are already open are not affected. |
| Config reload (`SIGHUP`) | Open connections keep running on the settings they were opened with, and still count toward their route's connection limits. New handshakes use the new config. |

**Configuration.** Per route, in `configs/config.yaml`. Every field is optional:

```yaml
routes:
  - path_prefix: "/ws"
    target: "http://localhost:9000"     # http:// or ws:// (https:// or wss:// for TLS backends)
    websocket: true                     # default: true. false = refuse upgrades with 403
    ws_idle_timeout: 5m                 # default: 5m. Close after this long with no frames either way
    ws_max_connections: 1000            # default: 0 (unlimited). Extras get 503
    ws_max_connections_per_client: 10   # default: 0 (unlimited). Extras get 429
    ws_allowed_origins:                 # default: [] (any origin). Others get 403
      - "https://app.example.com"
```

- **`ws_idle_timeout`.** Any frame in either direction counts as activity, including pings and pongs. When a connection goes idle, the gateway sends both sides a Close frame (`1001`, `"idle timeout"`), waits briefly for the closing handshake, then drops the connection. Clients that need longer quiet periods should send pings.
- **`ws_max_connections_per_client`** identifies clients the same way the rate limiter does: by the JWT client claim for JWT-authenticated requests, otherwise by `rate_limit.scope` (API key, IP, or header). Both limits count connections that are currently open, and a slot frees up as soon as a connection closes.
- **`ws_allowed_origins`** is matched case-insensitively against the `Origin` header, and `"*"` allows any origin. A handshake *without* an `Origin` header is allowed: browsers always send one, so a missing `Origin` means a non-browser client, which could send any `Origin` value it wanted anyway. This check protects browser users against cross-site WebSocket hijacking. It is not a substitute for auth.

**Handshake rejections.**

| Status | Cause | `reason` label |
|---|---|---|
| `401` | Missing or invalid API key / JWT | `auth` |
| `429` | Rate limit exceeded | `rate_limit` |
| `403` | `Origin` not in `ws_allowed_origins` | `origin` |
| `403` | `websocket: false` on the route | `disabled` |
| `429` | Client already at `ws_max_connections_per_client` | `max_connections` |
| `503` | Route already at `ws_max_connections` | `max_connections` |
| `503` | Route's circuit breaker is open | `circuit_open` |
| `503` | Gateway is shutting down | `shutting_down` |
| `502` / backend's status | Backend unreachable, or it refused the upgrade | `backend` |

**Closing.** When either side closes normally, the Close frames are relayed and the connection is torn down. When one side disappears *without* a closing handshake, the other side still gets a Close frame instead of a bare TCP reset. A client whose backend vanished gets `1014` (bad gateway). A backend whose client vanished gets `1001` (going away).

**Graceful shutdown.** Once a connection is upgraded, `http.Server.Shutdown` no longer tracks it. On `SIGINT` / `SIGTERM`, Gatekeeper therefore also closes every WebSocket itself:

1. New handshakes are refused with `503`.
2. Every open connection gets a Close frame (`1001`, `"server shutting down"`) on both sides.
3. Connections have until the end of the 10s shutdown window to finish the closing handshake. Anything still open after that is dropped.

**Trying it out.** The mock backend in [`mockbackend/`](mockbackend/) serves a WebSocket echo endpoint at `/ws/echo`, and [`configs/config.docker.yaml`](configs/config.docker.yaml) routes `/ws` to it. Start the stack with `docker-compose up --build`, then use [`websocat`](https://github.com/vi/websocat):

```bash
websocat -H "X-API-Key: demo-free-key" ws://localhost:8080/ws/echo
```

Each line you type is echoed back through the gateway. Without the header, the handshake is refused:

```bash
websocat ws://localhost:8080/ws/echo
# fails: the gateway answers the handshake with 401 Unauthorized
```

If you don't have `websocat`, the repo includes a small Go client, [`scripts/wsclient`](scripts/wsclient/main.go):

```bash
go run ./scripts/wsclient -url ws://localhost:8080/ws/echo -api-key demo-free-key -message hello -message world
```

```
connected (101 Switching Protocols, X-RateLimit-Remaining: 9)
< hello
< world
closed cleanly (1000)
```

You can do the same without Docker: run the mock backend with `cd mockbackend && go run .` (it listens on `:9000`), then run the gateway with the default `configs/config.yaml`, which also routes `/ws` to `localhost:9000`.

> **Browser clients:** the browser `WebSocket` API can't set custom headers, so it can't send `X-API-Key` or `Authorization`. Browser apps on an authenticated route need to get their credential onto the handshake some other way, for example with a same-origin cookie checked by a JWT-issuing proxy in front of Gatekeeper. Alternatively, use a non-browser client.

## TLS and mTLS

Gatekeeper can serve HTTPS itself, verify client certificates (mutual TLS), authenticate and rate-limit clients by certificate, and talk TLS (including mTLS) to its backends. All of it is off by default. With `tls.enabled: false`, the gateway serves plain HTTP exactly as before, and existing configs need no changes.

### HTTPS listener

```yaml
tls:
  enabled: true
  cert_file: "certs/server.pem"       # PEM certificate, followed by any intermediates
  key_file: "certs/server-key.pem"
  min_version: "1.2"                  # default "1.2"; "1.3" for TLS 1.3 only
  # cipher_suites:                    # optional TLS 1.2 allow-list; default is Go's secure set
  #   - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  #   - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  redirect_http_port: 8080            # optional plain-HTTP listener that 308-redirects to HTTPS
  hsts:
    enabled: true                     # adds Strict-Transport-Security to HTTPS responses
    max_age: 31536000                 # seconds (default: one year)
    include_subdomains: false
    preload: false
```

`server.listen_addr` becomes the HTTPS address. Everything behind the listener works over TLS unchanged: routes, auth, rate limiting, caching, WebSockets (`wss://`), and `/metrics`. HTTP/2 is negotiated automatically for clients that support it.

**Secure defaults.**
- The minimum version is TLS 1.2, and TLS 1.0/1.1 are refused.
- Cipher suites default to Go's secure list. `cipher_suites` only accepts suites from that list, never the insecure ones. It must include one of the two `AES_128_GCM_SHA256` ECDHE suites, because HTTP/2 requires them.
- TLS 1.3 suites aren't configurable, so `cipher_suites` together with `min_version: "1.3"` is rejected.
- Go picks the cipher suite order itself, taking the hardware into account. The old "prefer server cipher order" option is ignored by Go, so there's nothing to set.

**Contradictory config fails at startup** with a clear error. For example:
- `tls.enabled` without both `cert_file` and `key_file`.
- `client_auth`, `redirect_http_port`, or `hsts` while TLS is off.
- A verifying `client_auth` mode without `client_ca_file`.
- An `mtls` route without client certificate verification.
- A redirect port equal to the HTTPS port.

The certificate, key, and client CA bundle are loaded at startup. A missing, mismatched, expired, or malformed file stops the gateway with an error naming the file. Key and certificate contents are never logged.

**`tls.*` is read at startup only**, like `server.*`, with one exception: the certificate itself.

### Certificate hot reload

The server certificate is served through `tls.Config.GetCertificate`, so it can be replaced without a restart:

- **On `SIGHUP`**, together with the normal config reload. If the reloaded config changes `cert_file` / `key_file`, the new paths are used.
- **When the files change on disk.** Their modification time and size are checked every `tls.reload_interval` (default `30s`). That covers certificate renewers such as cert-manager or certbot hooks.

New handshakes get the new certificate, and connections that are already open keep theirs, so nothing in flight is dropped. A reload that fails keeps the previous certificate in use and logs why. Failures include unreadable files, a key that doesn't match, an expired certificate, or a half-written pair. A half-written pair (new certificate, old key) is retried as soon as the second file changes.

### Client certificates (mTLS)

```yaml
tls:
  client_auth: require_and_verify     # none | request | require | verify_if_given | require_and_verify
  client_ca_file: "certs/ca.pem"      # PEM bundle of CAs client certificates must chain to
```

| `client_auth` | Certificate required? | Verified against `client_ca_file`? | Usable for auth? |
|---|---|---|---|
| `none` (default) | no, and not requested | — | no |
| `request` | no | no | no |
| `require` | yes | no | no |
| `verify_if_given` | no | yes, if one is sent | yes |
| `require_and_verify` | yes | yes | yes |

With `require_and_verify`, a client without a valid certificate never completes the handshake. That covers a client with no certificate, one from an untrusted CA, and one that has expired. `verify_if_given` is the flexible option: clients without a certificate still connect and authenticate some other way, such as an API key, while certificate holders can use `mtls` routes. Only a certificate that `crypto/tls` actually **verified** is ever trusted. A certificate that was merely presented under `request` / `require` never authenticates anyone.

### Auth modes and certificate identity

Routes gain a fourth `auth_mode`, and `either` now accepts certificates too:

| `auth_mode` | Accepts |
|---|---|
| `api_key` (default) | a valid API key, as before |
| `jwt` | a valid JWT, as before |
| `mtls` | a verified client certificate (needs `client_auth: verify_if_given` or `require_and_verify`) |
| `either` | a valid API key, else a valid JWT, else a verified client certificate, in that order |

Routes without an `auth_mode` behave exactly as before. A route without a JWT block can now be `either`, as long as client certificates are verified.

For rate limiting, a certificate-authenticated client is identified by one field of its certificate and mapped to a tier, the same way a JWT client is identified by its claims:

```yaml
auth:
  mtls:
    identity_field: cn                # cn (default) | san_dns (first DNS SAN) | serial (hex)
    tiers:                            # optional; unmatched certificates get "default"
      premium:
        cn: ["acme-billing"]          # exact CN matches...
        ou: ["premium-customers"]     # ...or any of the certificate's OUs
      free:
        ou: ["trial"]
```

The rate-limit key is `mtls:<identity>`. It never collides with an API key, IP, or JWT client. A CN match beats an OU match. Tiers must exist under `rate_limit.tiers`, and a CN or OU can't be listed under two tiers. A certificate that lacks the configured identity field (for example, no DNS SAN with `san_dns`) is rejected with `401`. `auth.mtls` reloads on `SIGHUP` like the rest of `auth`.

Whatever a route's mode, a verified client certificate's identity is attached to the request for later middleware, even on `api_key` routes and even with `auth.enabled: false`. It only *authenticates* on `mtls` / `either` routes.

### Backend TLS

A route whose `target` is `https://` already works with publicly trusted backends, as before. `backend_tls` adds private CAs, mutual TLS to the backend, and name overrides:

```yaml
routes:
  - path_prefix: "/api/orders"
    target: "https://orders.internal:9443"
    backend_tls:
      enabled: true
      ca_file: "certs/backend-ca.pem"               # trust this CA (replaces the system trust store for this backend)
      client_cert_file: "certs/gateway-client.pem"  # present a client certificate (mTLS to the backend)
      client_key_file: "certs/gateway-client-key.pem"
      server_name: "orders.internal"                # name to verify / send as SNI (default: target host)
      insecure_skip_verify: false                   # never in production; logs a loud warning when true
```

- **Composes with the rest of the proxy.** Only the innermost HTTP transport changes. Retries, timeouts, the circuit breaker, and response caching wrap a TLS backend exactly as they wrap a plain one. WebSocket upgrades on the route go to the backend as `wss://`, with the same CA, client certificate, and server name.
- **Files are checked when the router is built.** The CA and client certificate are loaded at startup or reload, so a bad path fails there rather than on the first request.
- **`backend_tls.enabled` requires an `https://` target.**

### TLS metrics

| Metric | Labels | Meaning |
|---|---|---|
| `gatekeeper_tls_handshakes_total` | `version` (`TLS 1.2`, `TLS 1.3`) | Completed handshakes by protocol version |
| `gatekeeper_tls_handshake_errors_total` | `reason` (`protocol_version`, `cipher_suite`, `client_certificate`, `other`) | Failed handshakes |
| `gatekeeper_mtls_verifications_total` | `result`, `reason` (`verified`; `no_certificate`, `unknown_authority`, `expired`, `invalid`) | Client certificate verification outcomes |
| `gatekeeper_tls_certificate_expiry_seconds` | — | Seconds until the server certificate in use expires; alert well before it reaches 0 |
| `gatekeeper_tls_certificate_reloads_total` | `result` (`success`, `failure`) | Certificate loads, including the initial one |

`gatekeeper_auth_requests_total` also gains `method="mtls"`. Handshake failures are classified from the errors `crypto/tls` reports to `net/http`. A failure Go doesn't describe specifically is counted as `other` / `invalid`.

With `client_auth: require_and_verify`, `/metrics` is behind client certificates too, so give your Prometheus scraper a client certificate (`tls_config` in its scrape config).

### Trying it out

[`scripts/gencerts`](scripts/gencerts/main.go) writes a throwaway development PKI. It's a plain Go program, so it works the same on Linux, macOS, and Windows (PowerShell or Git Bash), with no `openssl` needed:

```bash
go run ./scripts/gencerts
# certs/ca.pem, certs/server.pem + server-key.pem (localhost, 127.0.0.1, ::1, gatekeeper),
# certs/client.pem + client-key.pem (CN=dev-client)
```

`certs/` and `*-key.pem` are git-ignored. Never commit them, and never use them outside development. The program refuses to overwrite an existing CA unless you pass `-force`. Use `-client-cn` and `-client-ou` to try out tier mapping, and `-hosts` to change the server names.

Point `configs/config.yaml` at them:

```yaml
server:
  listen_addr: ":8443"
tls:
  enabled: true
  cert_file: "certs/server.pem"
  key_file: "certs/server-key.pem"
  client_auth: verify_if_given
  client_ca_file: "certs/ca.pem"
```

Then:

```bash
# HTTPS with an API key (no client certificate needed under verify_if_given):
curl --cacert certs/ca.pem https://localhost:8443/api/ping -H "X-API-Key: demo-free-key"

# mTLS: present the client certificate (on an mtls or either route):
curl --cacert certs/ca.pem --cert certs/client.pem --key certs/client-key.pem https://localhost:8443/api/secure/ping

# TLS 1.1 is refused:
curl --cacert certs/ca.pem --tlsv1.1 --tls-max 1.1 https://localhost:8443/
```

> **Windows `curl`:** the `curl.exe` that ships with Windows (and Git for Windows) uses Schannel rather than OpenSSL. It needs two adjustments:
> - Add `--ssl-no-revoke`, because a local dev CA has no revocation endpoint.
> - Schannel can't read PEM client certificates. Use a curl built with OpenSSL (for example from WSL or MSYS2) for the `--cert` / `--key` examples, or bundle the client certificate into a `.pfx` with `openssl pkcs12 -export`.

**With Docker Compose.** [`docker-compose.tls.yml`](docker-compose.tls.yml) is an opt-in override that runs the stack with [`configs/config.docker.tls.yaml`](configs/config.docker.tls.yaml). That config serves HTTPS on `8443` and redirects plain HTTP on `8080` to it. It verifies client certificates when they're given, has an `mtls`-only route at `/api/secure`, and makes `/` an `either` route. The base `docker-compose.yml` is untouched and still serves plain HTTP.

```bash
go run ./scripts/gencerts            # on Linux add: -key-mode 0644 (the container's non-root user must read the keys)
docker-compose -f docker-compose.yml -f docker-compose.tls.yml up --build

curl --cacert certs/ca.pem --cert certs/client.pem --key certs/client-key.pem https://localhost:8443/api/secure/ping
curl -i http://localhost:8080/api/ping     # 308 Permanent Redirect -> https://localhost:8443/api/ping
```

## Distributed tracing

Gatekeeper can produce an [OpenTelemetry](https://opentelemetry.io/) trace for every request. Each trace has a span for each stage of the pipeline and one span per backend attempt, so retries are visible. Trace context is propagated to backends with the W3C `traceparent` / `tracestate` / `baggage` headers, so a trace started by your client continues through the gateway into your services. Traces are exported over OTLP to any OpenTelemetry Collector or compatible backend: Jaeger, Grafana Tempo, Honeycomb, and so on. See [ADR 5](docs/adr/0005-opentelemetry-otlp-tracing.md) for why.

Tracing is **off by default**. With it off, no spans are created, nothing is exported, and incoming `traceparent` / `tracestate` / `baggage` headers are forwarded to backends untouched, exactly as before.

### Tracing configuration

```yaml
tracing:
  enabled: true
  exporter: otlp_grpc                  # otlp_grpc (default) | otlp_http | stdout
  endpoint: "otel-collector:4317"      # host:port or URL; default localhost:4317 (gRPC) / localhost:4318 (HTTP)
  insecure: true                       # plaintext, for a local collector
  service_name: gatekeeper             # default "gatekeeper"
  sample_ratio: 1.0                    # fraction of NEW traces recorded (default 1.0)
  resource_attributes:                 # optional
    deployment.environment: production
    service.version: "2.3.0"
  response_header: X-Trace-Id          # optional: return the trace ID to clients (default off)
```

- **Sampling is parent-based.** `sample_ratio` decides only for requests that arrive without a `traceparent`. A request whose caller already decided (the sampled flag in its `traceparent`) follows that decision, so a trace is never recorded in some services and not others. An unsampled request is still propagated, with the sampled flag cleared, so the trace ID still links your logs.
- **`stdout`** pretty-prints each span to standard output. Use it to check that instrumentation works without running a collector.
- **`SIGHUP`** picks up changes to the `tracing` section: a new exporter, endpoint, sample ratio, or switching tracing on or off. The old pipeline keeps running for 15 seconds so requests already in flight can still export their spans.
- **Shutdown flushes buffered spans.** On `SIGINT` / `SIGTERM`, once the listener has drained, buffered spans are flushed to the collector, for at most 5 seconds.

**Standard `OTEL_*` environment variables override the file**, as OpenTelemetry users expect:

| Variable | Effect |
|---|---|
| `OTEL_SDK_DISABLED=true`, `OTEL_TRACES_EXPORTER=none` | Tracing off, whatever the file says |
| `OTEL_TRACES_EXPORTER=console` / `otlp` | stdout / OTLP exporter |
| `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `grpc` or `http/protobuf` |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Collector endpoint (replaces `endpoint`) |
| `OTEL_EXPORTER_OTLP_INSECURE`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TIMEOUT` | Transport security, auth headers (e.g. vendor API keys), timeout |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | Resource attributes (replace `service_name` / `resource_attributes`) |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Sampler (replaces `sample_ratio`) |
| `OTEL_BSP_*` | Batch processor queue size, batch size, delays |

The environment variables only override settings. Tracing is switched *on* in the config file.

### Span structure

A request on `/api/users` whose first backend attempt gets a `503` and whose retry succeeds:

```
GET /api/users                    server  http.route=/api/users  http.response.status_code=200
├── auth                                  gatekeeper.auth.mode=api_key  gatekeeper.auth.result=success
├── rate_limit                            gatekeeper.ratelimit.allowed=true  .algorithm=token_bucket  .store=redis
│                                         gatekeeper.client.tier=free  gatekeeper.client.id_hash=3f9a1c0e5b7d2a64
├── cache.lookup                          gatekeeper.cache.hit=false
├── circuit_breaker.check                 gatekeeper.circuit_breaker.state=closed  .allowed=true
├── backend.attempt               client  gatekeeper.backend.attempt=1  http.response.status_code=503  ERROR
├── circuit_breaker.check                 gatekeeper.circuit_breaker.state=closed  .allowed=true
└── backend.attempt               client  gatekeeper.backend.attempt=2  .retry=true  http.response.status_code=200
    └── (your backend's spans — its traceparent names this attempt as the parent)
```

- **The server span** is named `<METHOD> <route>`, using the matched route's prefix (or host), or `unmatched`. Its status is set to error only for `5xx` responses, following the HTTP semantic conventions. A `401` or `429` is the client's problem, not the gateway's.
- **The stage spans are siblings** under the server span, and each covers only its own stage.
  - A stage that rejects the request is marked `ERROR` with a fixed description: `auth` says `unauthorized`, and `rate_limit` says `rate limit exceeded`. No later stage span appears.
  - A cache hit has no `circuit_breaker.check` or `backend.attempt` spans at all.
- **Every attempt is its own `backend.attempt` client span**, and each is propagated to the backend with *its own* span as the parent.
  - It records the route, method, scheme, backend host and port, attempt number, and status.
  - A transport failure is recorded as a classified `error.type`: `timeout`, `connection_refused`, `tls`, `dns`, `connection_closed`, `canceled`, or `other`.
  - A circuit breaker that is open fails `circuit_breaker.check` and no attempt is made.
- **WebSocket upgrades** get a `websocket.handshake` span (policy checks, backend dial, `101`) and a `websocket.connection` span from the `101` until the tunnel closes. The connection span's `gatekeeper.websocket.close_reason` is `client`, `backend`, `idle_timeout`, or `shutdown`. The backend's upgrade request carries the handshake span's `traceparent`.

### Privacy and safety guarantees

- **Only an explicit allow-list of attributes is recorded.** That's method, route, scheme, protocol version, status codes, backend host and port, the stage outcomes shown above, the client tier, and a **keyed hash of the client identity**.
- **The client identity is hashed.** The identity can be an API key, so only `gatekeeper.client.id_hash` is recorded: an HMAC-SHA256 with a random per-process key, truncated to 16 hex characters. It correlates one client's requests within a running gateway but can't be reversed by guessing keys offline.
- **No headers are recorded.** That covers `Authorization`, `X-API-Key`, `Cookie`, and every other header, including the user agent.
- **No JWTs, request or response bodies, URL paths, or query strings are recorded.** Paths are left out because they often carry IDs.
- **Raw error messages are never recorded.** They can embed the full URL, query string included, so failures are classified into fixed `error.type` values instead.
- **Non-standard HTTP methods are recorded as `_OTHER`**, so a client can't inject arbitrary text through the method.
- A test sends a JWT, an API key, cookies, a query-string token, and a body through every path, including a failing backend, and asserts none of them appear anywhere in any span.

**Tracing is fail-open.**
- Ending a span is an in-memory enqueue. A batch processor exports in the background from a bounded queue, and when the queue is full it drops spans instead of blocking.
- Creating the exporter never contacts the collector. An unreachable or slow collector therefore can't delay startup, delay requests, or fail them.
- Export retries give up after 15 seconds.
- Export errors are logged at most once every 30 seconds, with a count of the errors held back.
- A test runs 300 requests against an unreachable collector over both OTLP protocols and checks that none of them is slowed down.

### Correlating traces, logs, and metrics

- **Logs:** every request log line ends with `trace_id=<32 hex chars>` when tracing is on. Without tracing, the line is unchanged.
- **Clients:** with `tracing.response_header: X-Trace-Id`, every response, including `401` and `429`, carries its trace ID, which is useful in bug reports.
- **Metrics:** Prometheus exemplars aren't attached. Go from a dashboard panel to a trace by searching Jaeger/Tempo by `http.route` / `http.response.status_code`, or by a trace ID from the logs. See [`grafana/README.md`](grafana/README.md#optional-traces-in-grafana-jaeger-or-tempo).

### Running Jaeger locally

[`docker-compose.tracing.yml`](docker-compose.tracing.yml) is an opt-in add-on. It starts an OpenTelemetry Collector (config in [`observability/otel-collector.yaml`](observability/otel-collector.yaml)) and Jaeger, and runs Gatekeeper with [`configs/config.docker.tracing.yaml`](configs/config.docker.tracing.yaml). That config is the compose config plus a `tracing` section pointing at the collector, with `X-Trace-Id` responses turned on. The plain `docker-compose up` is unchanged.

```bash
docker-compose -f docker-compose.yml -f docker-compose.tracing.yml up --build
# add -f docker-compose.monitoring.yml to run Prometheus + Grafana as well
```

Join an existing trace by sending your own `traceparent`, here with trace ID `4bf92f3577b34da6a3ce929d0e0e4736`:

```bash
curl -i http://localhost:8080/api/ping \
  -H "X-API-Key: demo-free-key" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
```

```
HTTP/1.1 200 OK
X-Trace-Id: 4bf92f3577b34da6a3ce929d0e0e4736
...
{"message":"hello from mock-backend", ..., "traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-<attempt span id>-01", ...}
```

The response's `X-Trace-Id` matches the trace you sent, and the mock backend echoes the `traceparent` it received. It has the same trace ID and the gateway's `backend.attempt` span as its parent. Open the Jaeger UI at <http://localhost:16686>, paste `4bf92f3577b34da6a3ce929d0e0e4736` into the trace ID search box at the top (or go straight to `http://localhost:16686/trace/4bf92f3577b34da6a3ce929d0e0e4736`), and you'll see the span tree above. To browse instead, choose service **gatekeeper** and filter by tag, for example `http.response.status_code=429`. Leave the `traceparent` header out to have Gatekeeper start a fresh trace; the `X-Trace-Id` response header tells you which one.

Running without Docker works the same way: run any OTLP collector, or set `exporter: stdout` to print spans to the gateway's own output.

## JWT authentication

Besides API keys, Gatekeeper can authenticate requests with a JSON Web Token sent as `Authorization: Bearer <token>`. Which credential a route requires is set per route, so API key clients and JWT clients can share one gateway.

### Auth modes

Each route gets an `auth_mode`:

| `auth_mode` | Accepts | On failure |
|---|---|---|
| `api_key` (default) | A valid key in `auth.header` (`X-API-Key` by default) | `401`, body `invalid or missing API key`, the same response as before JWT support existed |
| `jwt` | A valid bearer token | `401` + `WWW-Authenticate: Bearer` challenge, body `unauthorized` |
| `either` | A valid API key **or** a valid bearer token (the API key is checked first) | `401` + `WWW-Authenticate: Bearer` challenge, body `unauthorized` |

A route without `auth_mode` uses `api_key`, so **existing configs keep working unchanged**. `auth.enabled` is still the master switch: when it's `false`, every route is open whatever its `auth_mode` says. Gatekeeper logs a warning at startup and on reload if any route asks for `jwt` or `either` while auth is off. On an `either` route you can leave `auth.api_keys` empty, and the route then accepts JWTs only.

The auth middleware uses the same route matching as the proxy (host first, then longest path prefix), so a request is always authenticated under the rules of the route it's sent to. A request that matches no route is treated as `api_key` and then gets a `404` from the router.

### Configuration

```yaml
auth:
  enabled: true
  header: "X-API-Key"
  api_keys: ["demo-free-key", "demo-premium-key"]
  jwt:
    algorithm: HS256                 # HS256 or RS256; tokens using any other alg are rejected
    secret_env: GATEKEEPER_JWT_SECRET  # HS256: env var holding the secret (or `secret:` inline)
    # public_key_file: "keys/jwt-public.pem"   # RS256: PEM-encoded RSA public key
    issuer: "https://auth.example.com" # optional: required `iss` value
    audience: "gatekeeper"             # optional: required `aud` value
    leeway: 30s                        # optional: clock skew allowed for exp/nbf
    client_id_claim: sub               # claim that identifies the client (default: sub)
    tier_claim: tier                   # optional: claim that picks the rate-limit tier

routes:
  - path_prefix: "/api/users"
    target: "http://localhost:9001"      # no auth_mode: API key only, as before
  - path_prefix: "/api/orders"
    target: "http://localhost:9002"
    auth_mode: either
  - path_prefix: "/internal"
    target: "http://localhost:9003"
    auth_mode: jwt
```

| Field | Notes |
|---|---|
| `algorithm` | `HS256` (shared secret) or `RS256` (RSA public key). Only this algorithm is accepted, which blocks algorithm-confusion attacks: a token with `alg: none`, or an HS256 token signed with your RS256 public key as its HMAC secret, is rejected before any key is used. |
| `secret` / `secret_env` | HS256 only. Set exactly one. Prefer `secret_env` so the secret never sits in the config file. The secret must be at least 32 bytes (RFC 7518's minimum for HS256). |
| `public_key_file` | RS256 only. A PEM `PUBLIC KEY` or `RSA PUBLIC KEY` of at least 2048 bits. A relative path resolves against the gateway's working directory. The file is read at startup and on each `SIGHUP` reload, so a reload picks up a rotated key. A missing or invalid key fails startup, and fails a reload while the old config keeps serving. |
| `issuer`, `audience` | When set, the token's `iss` must match, and one of its `aud` values must match. When unset, those claims aren't checked. |
| `leeway` | Clock skew tolerated when checking `exp` and `nbf`. Default `0s`. |
| `client_id_claim` | Default `sub`. Must be a non-empty string, or the token is rejected. |
| `tier_claim` | Optional. See below. |

Every token must have an `exp` claim, and tokens without one are rejected. A token with `nbf` in the future is rejected too. Gatekeeper never logs tokens or secrets: the request log records only method, path, status, duration and remote address, and config errors name the setting at fault but not its value.

### Rate limiting and tiers from claims

When a request authenticates with a JWT, the rate limiter identifies the client by the `client_id_claim` value instead of `rate_limit.scope`. The value is prefixed with `jwt:`, so a token with `sub: alice` gets its own `jwt:alice` bucket and appears as `client="jwt:alice"` in `/metrics`. The prefix means a token can never share, or drain, the bucket of an API key, IP or header value that happens to be the same string.

If `tier_claim` is set, that claim's value picks the tier directly, so `"tier": "premium"` gets the `premium` limits from `rate_limit.tiers`. The client falls back to the `default` tier when the claim is missing, isn't a string, or names a tier that isn't configured. A token can't invent its own tier. The `rate_limit.clients` map only applies to API key, IP and header clients, not to JWT clients.

Requests authenticated by API key, including API key requests on an `either` route, are rate-limited exactly as before.

The response cache already includes the `Authorization` header in its key (see [Response caching](#response-caching)), so two JWT holders never get each other's cached responses.

### Error responses

A missing token gets a challenge without an error code, and a bad token gets `error="invalid_token"` (RFC 6750):

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="gatekeeper", error="invalid_token"

unauthorized
```

The body is the same whether the token was expired, badly signed, issued for another audience or malformed, so it gives an attacker nothing to probe with.

### Trying it out

Generate a test HS256 token with nothing but `openssl` (bash, Git Bash or WSL). The secret must match the gateway's:

```bash
export GATEKEEPER_JWT_SECRET='replace-me-with-a-random-secret-of-32-bytes-or-more'

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
payload=$(printf '{"sub":"alice","tier":"premium","aud":"gatekeeper","iss":"https://auth.example.com","exp":%d}' \
  "$(( $(date +%s) + 3600 ))" | b64url)
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -hmac "$GATEKEEPER_JWT_SECRET" -binary | b64url)
TOKEN="$header.$payload.$sig"
```

Start the gateway in the same shell, so it sees `GATEKEEPER_JWT_SECRET`, with a config like the one above. Then:

```bash
curl -i http://localhost:8080/api/orders/42 -H "Authorization: Bearer $TOKEN"
```

```
HTTP/1.1 200 OK
X-Ratelimit-Limit: 100
X-Ratelimit-Remaining: 99
```

The `premium` limit applies because of the `tier` claim. The same route still takes an API key, because it's an `either` route:

```bash
curl -i http://localhost:8080/api/orders/42 -H "X-API-Key: demo-free-key"
```

For RS256, sign with a private key and give the gateway the matching public key:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem   # -> auth.jwt.public_key_file

header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign jwt-private.pem -binary | b64url)
TOKEN="$header.$payload.$sig"
```

In production, tokens come from your identity provider. Keep only the public key on the gateway for RS256, and never commit HS256 secrets or private keys.

## Setup

Requires Go 1.26+ (see `go.mod`). Redis is optional, only needed if you set `storage.backend: redis`.

```bash
git clone <this-repo>
cd gatekeeper
go build -o bin/gatekeeper ./cmd/gatekeeper
```

Edit [`configs/config.yaml`](configs/config.yaml) so `routes` points at your actual backend services, then run:

```bash
./bin/gatekeeper -config configs/config.yaml
```

By default Gatekeeper listens on `:8080` and exposes metrics on `/metrics`.

### Windows launchers

Two `.bat` files are included so you don't have to type any of the above by hand:

- **[`start.bat`](start.bat)** — builds and runs the real `gatekeeper` binary against `configs/config.yaml`. Edit that config's `routes` first so they point at real services. No demo backend, no dashboard — this is the production-shaped path.
- **[`start-demo.bat`](start-demo.bat)** — a self-contained demo. Builds a throwaway stand-in backend and Gatekeeper, starts both, and opens an interactive dashboard in your browser (`-dashboard` flag, served by Gatekeeper itself at `/_dashboard`). Pick a client — free, premium, or no key — fire a single request or a burst of concurrent ones, and watch allowed vs. rate-limited counts update live next to `/metrics`. Good for seeing the limiter actually do something without wiring up real services first.

## Dynamic config reload (SIGHUP)

Gatekeeper re-reads its config file on `SIGHUP`, so you can change routes,
rate-limit rules, client tiers, the algorithm, and the auth/CORS settings
without restarting the process or dropping in-flight requests.

Edit `configs/config.yaml` (the same path passed to `-config`), then:

```bash
kill -HUP <pid>
```

On reload Gatekeeper re-parses and validates the file, builds a fresh
routing table and set of per-tier limiters, and swaps them in atomically.
A request in flight during the swap finishes on the config it started
with; the next request uses the new one. An open WebSocket connection
keeps running on the route settings it was opened with. Rate-limit counter state is kept
across the reload rather than reset.

If the new config is missing, malformed, or fails validation, the reload
is **rejected**: Gatekeeper logs the error and keeps serving with the
previous config. It never crashes or serves a half-applied config.

```
gatekeeper: SIGHUP received, reloading config
gatekeeper: config reload failed, keeping previous config: config: invalid: rate_limit.tiers.free.burst must be > 0
```

`server.*`, `storage.*`, `metrics.*`, and `tls.*` are read only at
startup — changing the listen address, the storage backend, the metrics
path, or TLS settings still requires a restart. The one exception is the
TLS certificate itself: `SIGHUP` also reloads the server certificate and
key (see [Certificate hot reload](#certificate-hot-reload)). The `tracing`
section is reloaded too (see [Distributed tracing](#distributed-tracing)).

## Run with Docker

A multi-stage [`Dockerfile`](Dockerfile) is included: it builds the `gatekeeper` binary in a `golang:1.26-alpine` stage, then copies just the binary and `configs/config.yaml` into a minimal `alpine` runtime image.

Build the image:

```bash
docker build -t gatekeeper .
```

Run it with the bundled config:

```bash
docker run --rm -p 8080:8080 gatekeeper
```

To use your own config instead of the one baked into the image, mount it over the in-image path:

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/configs/config.yaml:/app/configs/config.yaml:ro" \
  gatekeeper
```

If `routes` in your config point at services on the host (e.g. `localhost:9000`), remember that `localhost` inside the container refers to the container itself. On Docker Desktop (Mac/Windows), point routes at `host.docker.internal` instead; on Linux, add `--add-host=host.docker.internal:host-gateway` to the `docker run` command or use `--network host`.

The image exposes port `8080`, matching the default `server.listen_addr` in [`configs/config.yaml`](configs/config.yaml) — adjust the `-p` mapping if you change that value.

## Run the full stack with Docker Compose

[`docker-compose.yml`](docker-compose.yml) brings up a complete, self-contained stack so you can exercise the whole gateway — routing, auth, rate limiting, and Redis-backed counters — without standing up any real backend services first:

- **`gatekeeper`** — built from the [`Dockerfile`](Dockerfile), same as above.
- **`redis`** (`redis:alpine`) — backs the rate limiter's shared counters.
- **`mock-backend`** — a tiny standalone HTTP server in [`mockbackend/`](mockbackend/) that echoes back the request it received as JSON, standing in for a real upstream so requests have somewhere to be proxied to. It also serves a WebSocket echo endpoint at `/ws/echo` (see [WebSocket proxying](#websocket-proxying)).

Gatekeeper runs against [`configs/config.docker.yaml`](configs/config.docker.yaml) inside the stack (mounted over the image's baked-in config), not `configs/config.yaml`. It's identical except `storage.redis.addr` points at `redis:6379` and every route's `target` points at `http://mock-backend:9000` — both reached by their compose service name rather than `localhost`, since each service is its own container on the compose network.

Start everything with:

```bash
docker-compose up --build
```

To view traces in Jaeger, add the opt-in [`docker-compose.tracing.yml`](docker-compose.tracing.yml) override; see [Running Jaeger locally](#running-jaeger-locally). To run the same stack over HTTPS with mTLS, add the opt-in [`docker-compose.tls.yml`](docker-compose.tls.yml) override; see [TLS and mTLS](#tls-and-mtls).

Only `gatekeeper` publishes a port to the host — `8080`, matching `server.listen_addr`. `redis` and `mock-backend` are reachable from `gatekeeper` on the compose network but not from the host.

Once the stack is up, hit it the same way as [Example usage](#example-usage) below, just via `docker-compose` instead of a locally built binary:

```bash
curl -i http://localhost:8080/api/ping -H "X-API-Key: demo-free-key"
```

```
HTTP/1.1 200 OK
X-Ratelimit-Limit: 10
X-Ratelimit-Remaining: 9

{"message":"hello from mock-backend","method":"GET","path":"/api/ping", ...}
```

The JSON body comes from `mock-backend`, confirming the request actually made it through Gatekeeper's auth and rate-limit middleware and was proxied end-to-end. Send more than 10 requests in quick succession with the same key and you'll start getting `429 Too Many Requests` back, same as in [Example usage](#example-usage). `curl http://localhost:8080/metrics` and the gateway's own logs (`docker-compose logs gatekeeper`) work as usual too.

## Example usage

Using the example config's `demo-free-key` (free tier: 5 req/s, burst 10) against a route proxying `/api/*` to a backend:

```bash
curl -i http://localhost:8080/api/ping -H "X-API-Key: demo-free-key"
```

```
HTTP/1.1 200 OK
X-Ratelimit-Limit: 10
X-Ratelimit-Remaining: 9

pong
```

Every response carries `X-RateLimit-Limit` / `X-RateLimit-Remaining`. Once the tier's allowance is gone, Gatekeeper answers directly without ever touching the backend:

```bash
curl -i http://localhost:8080/api/ping -H "X-API-Key: demo-free-key"
```

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1

rate limit exceeded
```

### Metrics

```bash
curl http://localhost:8080/metrics
```

```
gatekeeper_limiter_remaining{client="demo-free-key",tier="free"} 0
gatekeeper_limiter_remaining{client="demo-premium-key",tier="premium"} 0
gatekeeper_requests_allowed_total{client="demo-free-key",tier="free"} 11
gatekeeper_requests_allowed_total{client="demo-premium-key",tier="premium"} 102
gatekeeper_requests_rejected_total{client="demo-free-key",tier="free"} 190
gatekeeper_requests_rejected_total{client="demo-premium-key",tier="premium"} 98
gatekeeper_proxy_retries_total{route="/api"} 4
gatekeeper_proxy_request_outcomes_total{route="/api",outcome="success"} 108
gatekeeper_proxy_request_outcomes_total{route="/api",outcome="failure"} 3
gatekeeper_cache_hits_total{route="/api"} 76
gatekeeper_cache_misses_total{route="/api"} 32
gatekeeper_circuit_breaker_state{route="/api"} 0
gatekeeper_circuit_breaker_rejections_total{route="/api"} 0
gatekeeper_auth_requests_total{method="api_key",result="success"} 213
gatekeeper_auth_requests_total{method="api_key",result="failure"} 4
gatekeeper_auth_requests_total{method="jwt",result="success"} 57
gatekeeper_auth_requests_total{method="jwt",result="failure"} 2
gatekeeper_websocket_active_connections{route="/ws"} 12
gatekeeper_websocket_connections_opened_total{route="/ws"} 40
gatekeeper_websocket_connections_closed_total{route="/ws",reason="client"} 25
gatekeeper_websocket_connections_closed_total{route="/ws",reason="idle_timeout"} 3
gatekeeper_websocket_handshake_rejections_total{route="/ws",reason="auth"} 2
gatekeeper_websocket_handshake_rejections_total{route="/ws",reason="max_connections"} 1
gatekeeper_websocket_connection_duration_seconds_count{route="/ws"} 28
gatekeeper_tls_handshakes_total{version="TLS 1.3"} 512
gatekeeper_tls_handshake_errors_total{reason="client_certificate"} 3
gatekeeper_mtls_verifications_total{result="success",reason="verified"} 120
gatekeeper_mtls_verifications_total{result="failure",reason="unknown_authority"} 2
gatekeeper_tls_certificate_expiry_seconds 7.7e+06
gatekeeper_tls_certificate_reloads_total{result="success"} 2
```

`gatekeeper_proxy_retries_total` counts individual retry attempts against a backend (not the initial attempt), and `gatekeeper_proxy_request_outcomes_total` counts each proxied request exactly once — as `success` or `failure` — after all retries are done. Both are independent of `gatekeeper_requests_allowed_total`/`_rejected_total`, which reflect the rate limiter's decision on the original client request, not what happened while forwarding it.

`gatekeeper_cache_hits_total`/`gatekeeper_cache_misses_total` count cache-eligible `GET` requests per route — a hit was served without touching the backend, a miss reached the backend and (usually) refreshed the cache. Neither counter moves for a route with caching disabled, a non-`GET` request, or a request sent with `X-Bypass-Cache`.

`gatekeeper_circuit_breaker_state` reports each route's current breaker state as a number — `0` (closed), `1` (open), `2` (half-open) — so you can alert on a route sitting at `1` for longer than expected. `gatekeeper_circuit_breaker_rejections_total` counts requests that were failed fast because the breaker was open; these never reach the backend and are separate from `gatekeeper_proxy_request_outcomes_total`. Neither series appears for a route with circuit breaking disabled.

`gatekeeper_auth_requests_total` counts every auth decision once, by `method` (`api_key` or `jwt`) and `result` (`success` or `failure`). A rejected request on an `either` route counts as a `jwt` failure if it carried a bearer token and as an `api_key` failure otherwise. Nothing is counted while `auth.enabled` is false. See [JWT authentication](#jwt-authentication).

`gatekeeper_websocket_active_connections` is the number of WebSocket connections open right now on each route. `gatekeeper_websocket_connections_opened_total` counts connections that completed the upgrade. `gatekeeper_websocket_connections_closed_total` counts connections that have ended, split by `reason`: `client` or `backend` (that side closed or disconnected), `idle_timeout`, or `shutdown`. `gatekeeper_websocket_handshake_rejections_total` counts upgrade requests refused before a connection was established, by `reason` (`auth`, `rate_limit`, `origin`, `max_connections`, `disabled`, `circuit_open`, `shutting_down`, `backend`). See the rejection table in [WebSocket proxying](#websocket-proxying). `gatekeeper_websocket_connection_duration_seconds` is a histogram of how long connections stayed open, with buckets from 100ms to 4h. A handshake's backend outcome is also counted once in `gatekeeper_proxy_request_outcomes_total`.

The TLS metrics (`gatekeeper_tls_*`, `gatekeeper_mtls_verifications_total`) only appear with `tls.enabled`. See the table in [TLS metrics](#tls-metrics) for what each one means.

(`gatekeeper_request_duration_seconds` is also exposed as a histogram, alongside the usual Go/process collectors.)

### Grafana dashboard

[`grafana/gatekeeper-dashboard.json`](grafana/gatekeeper-dashboard.json) is a ready-to-import Grafana dashboard for these metrics. It shows allowed vs rejected requests per client and tier, rate-limit quota remaining, cache hit/miss ratio, latency percentiles and a latency histogram, and backend retry counts and outcomes.

<!-- TODO: Add a screenshot of the imported dashboard here. -->
![Grafana dashboard](docs/images/grafana-dashboard.png)

> **Screenshot placeholder:** add a screenshot of the imported dashboard at `docs/images/grafana-dashboard.png`.

To use it:

1. Point a Prometheus instance at Gatekeeper's metrics endpoint (`<listen_addr><metrics.path>`, e.g. `localhost:8080/metrics`). The endpoint needs no API key.
2. In Grafana, go to **Dashboards → New → Import**, upload `grafana/gatekeeper-dashboard.json`, and pick that Prometheus data source from the **Data source** dropdown at the top of the dashboard.

To try it locally, an opt-in compose file runs Prometheus and Grafana next to the existing stack, with the dashboard already provisioned. Grafana is then at <http://localhost:3000> (`admin` / `admin`):

```bash
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up --build
```

See [`grafana/README.md`](grafana/README.md) for the full walkthrough.

## Testing

```bash
go test ./...
```

What's covered:
- Each algorithm's correctness, including edge-of-burst behavior and concurrent goroutines hammering a single client — asserting the allowed count never sneaks past the configured burst (see `TestTokenBucket_ConcurrentRequestsNeverExceedBurst` for an example).
- A shared conformance suite (`store.testStoreConformance`) that runs against *both* `MemoryStore` and a `miniredis`-backed `RedisStore`, so the two backends are held to identical guarantees without needing a real Redis instance in CI.
- `FallbackStore` failover and recovery.
- Gateway routing: longest-path-prefix matching, host-based routing, a 404 when nothing matches, a 502 when the backend is dead.
- Backend timeout/retry: a request that succeeds on the first try, one that fails once then succeeds on retry, one that exhausts all retries and fails, a connection-refused backend being retried, and confirming a `4xx` response is never retried — including that retries never inflate the request's rate-limit cost.
- Response caching (`internal/cache` and `internal/proxy/cache_test.go`): a miss followed by a hit for the same request, TTL expiration forcing a fresh backend call, a `Cache-Control: no-store` response never being cached, `X-Bypass-Cache` skipping the cache without disturbing the existing entry, a route with caching disabled always reaching the backend, and caching degrading gracefully (fail open, no crash) when its store errors on every call — simulating Redis being down.
- Circuit breaker (`internal/circuitbreaker` and `internal/proxy/circuitbreaker_test.go`): tripping to Open after `failure_threshold` consecutive failures, requests failing fast (and never reaching the backend) while Open, transitioning to Half-Open once the cooldown elapses, a successful trial closing the breaker, a failed trial re-opening it, Half-Open's concurrent-trial limit, and confirming a request never retries into an already-open circuit.
- WebSocket proxying (`internal/proxy/websocket_test.go`, `internal/gateway/websocket_test.go`, `internal/websocket`): messages relayed in both directions, including large frames, with handshake headers passed through. The handshake is blocked by a missing or invalid API key or JWT and rate limited per attempt, while frames are not limited. Also covered: origin rejection, per-route and per-client connection caps, the idle timeout closing a quiet connection, a backend or client disconnect closing the other side with a Close frame, upgrades never being retried or cached, connections outliving `proxy.timeout` and the server's read/write timeouts, the circuit breaker counting failed handshakes but not long-lived connections, graceful shutdown (including forced close at the deadline), connections surviving a config reload, and plain HTTP on a WebSocket-enabled route behaving exactly as before.
- TLS and mTLS (`internal/server`, `internal/middleware/mtls_test.go`, `internal/proxy/backendtls_test.go`, `internal/config`):
  - HTTPS serving with a generated certificate, and plain HTTP unchanged when TLS is off.
  - TLS 1.1 refused, `min_version: "1.3"` refusing TLS 1.2, and the cipher-suite allow-list enforced.
  - `require_and_verify` rejecting a client with no certificate, one from an untrusted CA, and an expired one, while accepting a valid one; each failure counted by reason.
  - Startup failing on missing or invalid certificate, key, or CA files.
  - Certificate hot reload through the file watcher and `SIGHUP`, with open connections surviving it, and invalid reloads keeping the old certificate.
  - The HTTP→HTTPS redirect and HSTS.
  - The `mtls` and `either` auth modes, with unverified certificates never trusted, and `cn` / `san_dns` / `serial` identity extraction with CN/OU tier mapping driving rate limits, end to end through the real gateway.
  - Backend TLS: a custom CA, a `server_name` override, mTLS to the backend, `insecure_skip_verify`, retries over TLS, and `wss` with backend mTLS.
  - Contradictory TLS config rejected, and every shipped config file loading cleanly.
- Distributed tracing (`internal/gateway/tracing_test.go`, `internal/tracing`), using OpenTelemetry's in-memory span recorder against the real pipeline:
  - The expected span tree for a normal request, and cache hit vs miss attributes.
  - One `backend.attempt` span per retry, each propagated with its own span as the backend's parent.
  - Attributes and status for unauthorized and rate-limited requests.
  - An incoming `traceparent` joined (with `tracestate` and baggage) and propagated, including to an HTTPS backend and over a WebSocket upgrade.
  - Secrets never appearing in any span, and transport errors classified instead of quoted.
  - Sampling: ratio 0 / 0.5 / 1, and parent-based decisions both ways.
  - Tracing disabled producing no spans and changing nothing on the wire.
  - The `X-Trace-Id` response header and `trace_id` in log lines.
  - An unreachable OTLP collector (gRPC and HTTP) not slowing requests or hanging shutdown.
  - `SIGHUP` turning tracing on and off.
  - `OTEL_*` overrides, and the rate-limited exporter error log.
- A full end-to-end test (`TestGateway_EndToEnd`) that wires config → storage → limiters → the whole middleware chain → the proxy, then drives it through auth, CORS, per-tier rate limiting, and routing together, not in isolation.

## Load testing

[`scripts/loadtest`](scripts/loadtest/main.go) is a small goroutine-based Go program that fires concurrent requests at a running Gatekeeper instance and reports how many got through versus rate-limited, plus latency percentiles.

```bash
go run ./scripts/loadtest -target http://localhost:8080/api/ping -api-key demo-free-key -requests 200 -concurrency 20
```

This is real output from a local run against the example config's `free` tier (5 req/s, burst 10), token-bucket algorithm, in-memory store:

```
Gatekeeper load test
=====================
requests:      200 (concurrency 20)
wall time:     33ms (6031.0 req/s)
allowed (2xx): 10
rejected (429):190
failed:        0

latency  min=0s  p50=1.61ms  p95=14.103ms  p99=17.202ms  max=17.84ms
```

Exactly 10 got through — the tier's configured burst — and the rest were rejected in that same wave of concurrent traffic, which is precisely what Token Bucket promises. Same run against the `premium` tier (50 req/s, burst 100):

```
Gatekeeper load test
=====================
requests:      200 (concurrency 20)
wall time:     54ms (3695.4 req/s)
allowed (2xx): 102
rejected (429):98
failed:        0

latency  min=0s  p50=2.447ms  p95=21.656ms  p99=22.16ms  max=22.674ms
```

102 allowed, not a round 100 — those extra 2 came from the bucket refilling at 50 tokens/sec during the ~54ms it took to send the burst. That's Token Bucket's continuous refill showing up in practice, as opposed to the hard cutoff you'd get from a Fixed Window Counter.

## Benchmarks

[`internal/ratelimiter/bench_test.go`](internal/ratelimiter/bench_test.go) benchmarks all three algorithms against both storage backends, driving `Limiter.Allow` in a tight sequential loop for a single client key. The Redis numbers run against [`miniredis`](https://github.com/alicebob/miniredis) — an in-process fake Redis reached over a real TCP loopback connection — so they capture the cost of the Lua round trip and payload serialization without requiring a live Redis instance to reproduce:

```bash
go test -bench=. -benchmem ./...
```

This is real output from a local run (Windows, 13th Gen Intel Core i7-13700HX):

```
goos: windows
goarch: amd64
pkg: gatekeeper/internal/ratelimiter
cpu: 13th Gen Intel(R) Core(TM) i7-13700HX
BenchmarkTokenBucket_Memory-24         	  787939	      1428 ns/op	     440 B/op	       9 allocs/op
BenchmarkTokenBucket_Redis-24          	    4186	    429837 ns/op	  219485 B/op	     845 allocs/op
BenchmarkSlidingWindowLog_Memory-24    	   10000	    304404 ns/op	   81168 B/op	      19 allocs/op
BenchmarkSlidingWindowLog_Redis-24     	    3078	    930296 ns/op	  422332 B/op	     867 allocs/op
BenchmarkFixedWindow_Memory-24         	 5546469	       194.3 ns/op	      48 B/op	       3 allocs/op
BenchmarkFixedWindow_Redis-24          	    3928	    302200 ns/op	  187867 B/op	     750 allocs/op
```

Summarized, with throughput derived from ns/op:

| Algorithm | Store | ns/op | B/op | allocs/op | Throughput (ops/sec) |
|---|---|--:|--:|--:|--:|
| Token Bucket | Memory | 1,428 | 440 | 9 | ~700,000 |
| Token Bucket | Redis | 429,837 | 219,485 | 845 | ~2,300 |
| Sliding Window Log | Memory | 304,404 | 81,168 | 19 | ~3,300 |
| Sliding Window Log | Redis | 930,296 | 422,332 | 867 | ~1,100 |
| Fixed Window Counter | Memory | 194.3 | 48 | 3 | ~5,150,000 |
| Fixed Window Counter | Redis | 302,200 | 187,867 | 750 | ~3,300 |

This lines up with the trade-offs described above. **Fixed Window Counter is the fastest and lightest by a wide margin** — a single atomic increment and O(1) storage, no CAS loop — at the cost of the boundary-doubling behavior described earlier. **Token Bucket sits in the middle**: its CAS loop and float refill math cost roughly 7x Fixed Window on the memory store, but its per-client state stays a fixed size regardless of burst, so that cost doesn't grow with configured limits. **Sliding Window Log is the memory-heaviest of the three**, and it shows: on the memory store it's already ~200x slower than Fixed Window and allocates ~1.7KB per call, because every `Allow` has to unmarshal, prune, and re-marshal a per-client log of up to `burst` timestamps — exactly the O(burst) cost the trade-off table above calls out.

The Redis numbers tell a second, independent story: every algorithm gets roughly 300–1000x slower once state has to round-trip a Lua script over the network instead of staying behind a local mutex, which is the real cost of coordinating limits fleet-wide ([ADR 2](docs/adr/0002-redis-lua-atomic-operations.md)) — and it's also why [`FallbackStore`](docs/adr/0004-fallback-store-graceful-degradation.md) existing at all matters: losing Redis costs you fleet-wide accuracy, but staying on it costs raw throughput even when it's healthy.

## Architecture Decisions

Short records of the reasoning behind Gatekeeper's key architectural choices — why Token Bucket is the default, why Redis coordination uses Lua scripts, why storage sits behind a `Store` interface, why `FallbackStore` exists — live in [`docs/adr/`](docs/adr/).

## Configuration reference

See the fully-commented [`configs/config.yaml`](configs/config.yaml) for every field. The shape at a glance:

```yaml
server:      { listen_addr, read_timeout, write_timeout, idle_timeout }
storage:     { backend: memory|redis, redis: { addr, password, db, dial_timeout } }
rate_limit:  { algorithm, scope: api_key|ip|header, header_name, tiers: {...}, clients: {...} }
auth:        { enabled, header, api_keys: [...], jwt: { algorithm: HS256|RS256, secret | secret_env, public_key_file, issuer, audience, leeway, client_id_claim, tier_claim }, mtls: { identity_field: cn|san_dns|serial, tiers: { <tier>: { cn: [...], ou: [...] } } } }
cors:        { enabled, allowed_origins, allowed_methods, allowed_headers, allow_credentials, max_age }
routes:      [ { path_prefix | host, target, auth_mode: api_key|jwt|mtls|either, backend_tls: { enabled, ca_file, client_cert_file, client_key_file, server_name, insecure_skip_verify }, cache: { enabled, ttl }, circuit_breaker: { enabled, failure_threshold, open_duration, half_open_max_requests, half_open_successes_to_close, half_open_failures_to_reopen }, websocket, ws_idle_timeout, ws_max_connections, ws_max_connections_per_client, ws_allowed_origins: [...] } ]
metrics:     { enabled, path }
proxy:       { timeout, retry: { max_retries, base_backoff, max_backoff } }
tracing:     { enabled, exporter: otlp_grpc|otlp_http|stdout, endpoint, insecure, service_name, sample_ratio, resource_attributes: {...}, response_header }
tls:         { enabled, cert_file, key_file, min_version: "1.2"|"1.3", cipher_suites: [...], client_auth: none|request|require|verify_if_given|require_and_verify, client_ca_file, reload_interval, redirect_http_port, hsts: { enabled, max_age, include_subdomains, preload } }
```

---

<p align="center"><i>-by Deipedra</i></p>
