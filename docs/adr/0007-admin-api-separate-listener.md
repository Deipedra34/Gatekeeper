# 7. Admin API on a separate, authenticated listener

## Status

Accepted

## Context

Operators needed to inspect and steer a running gateway without editing
files and sending signals: see backend health and rate limit state,
reload the config, purge the cache, take a backend out of rotation,
reset a circuit breaker. Those are powerful operations. A reset rate
limit or a drained backend changes what every client sees, and the
config holds API keys and JWT secrets.

The proxy listener is the most exposed surface Gatekeeper has. It's
reachable by every client, and its paths belong to the backends. Any
`/admin` prefix we reserved there could collide with a real backend
route. It would also be one routing bug away from public exposure.

## Decision

- **The admin API has its own listener, off by default.** `admin.enabled`
  defaults to false, and nothing is opened unless it's set. The default
  address is `127.0.0.1:9090`, loopback only. The config rejects an
  admin port equal to the proxy's. The admin handlers are registered only
  on the admin listener's mux and never on the proxy's. So
  `/admin/v1/...` on the proxy port is just another path, proxied to
  whatever route matches it.
- **Every endpoint requires authentication, with no anonymous mode.**
  Enabling the API without tokens or mTLS fails startup.
  - **Bearer tokens.** The config stores only their SHA-256, so a leaked
    config file doesn't leak a credential. A presented token is hashed
    and compared against every configured hash with
    `subtle.ConstantTimeCompare`, without stopping at a match. Response
    timing then reveals neither which token matched nor how close a
    guess was.
  - **Client certificates.** These are verified by `crypto/tls` against
    the admin CA, optionally limited to listed CNs. The admin listener
    reuses `server.Server`, so it gets the same TLS settings, hot reload
    and handshake verification as the main listener.
- **Defence in depth around authentication.**
  - An optional CIDR allowlist is checked before credentials.
  - Each source IP is locked out (429) after N failures in a window,
    checked *before* credentials, so a correct guess made while locked
    out still fails.
  - The source IP is the TCP peer. `X-Forwarded-For` is ignored, so a
    header can't get around either check.
  - Request bodies are size-limited, and the listener has its own
    timeouts.
- **Everything is observable without exposing secrets.**
  - Each request gets one JSON audit record: time, source IP, identity
    (`token:<id>` or `cert:<CN>`), method, path, endpoint, status,
    result, and trace ID.
  - Audit records never include bodies or credentials. A rate limit
    client in a path is logged only in a non-secret form (fingerprint,
    `jwt:`, `mtls:`, IP), never as a raw key.
  - Each request gets an OpenTelemetry span and is counted in
    `/metrics`.
  - `/admin/v1/config` redacts secrets on a copy of the config. API keys
    become the same fingerprints `/metrics` uses.
- **Destructive actions are guarded.**
  - Purging the cache needs an explicit filter or `"all": true`.
  - Draining a route's last in-rotation backend needs `force=true`.
  - Most actions accept `dry_run=true`.
  - `POST /admin/v1/reload` goes through the same function as SIGHUP, so
    the two can't drift apart.

## Consequences

- No backend route can shadow the admin API, and exposing it is an
  explicit decision (`admin.listen`) rather than something that happens
  as a side effect of the proxy being public.
- There's a second port to manage. Inside containers it has to be
  published on purpose, and binding it beyond loopback without
  `admin.tls` logs a warning, because tokens would cross the network in
  plain text.
- The admin section is read at startup only, tokens included. Rotating a
  token needs a restart. In return, a bad reload can never lock the
  operator out or silently disable admin auth.
- Some state is per process.
  - Cache purges and cache stats use an index of the entries *this*
    instance cached, because cache keys are hashes. With a shared Redis
    store, purge on each instance. Other instances' entries expire on
    their own TTL.
  - The failed-auth lockout is also per process.
  - Draining a backend lasts until it's re-enabled or the process
    restarts. A reload that keeps the backend keeps it drained.
