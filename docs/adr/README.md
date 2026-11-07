# Architecture Decision Records

Short records of the architectural choices behind Gatekeeper, in the
format: Title, Status, Context, Decision, Consequences.

1. [Token Bucket as the default rate-limiting algorithm](0001-token-bucket-as-default.md)
2. [Redis + Lua scripts for atomic distributed rate limiting](0002-redis-lua-atomic-operations.md)
3. [A Store interface to decouple algorithms from storage backends](0003-store-interface-abstraction.md)
4. [FallbackStore for graceful degradation when Redis is unreachable](0004-fallback-store-graceful-degradation.md)
5. [OpenTelemetry with OTLP for distributed tracing](0005-opentelemetry-otlp-tracing.md)
6. [Load balancing: per-backend state, per-attempt selection, and drain-on-reload](0006-load-balancing.md)
7. [Admin API on a separate, authenticated listener](0007-admin-api-separate-listener.md)
8. [Request and response transformation with a fixed variable whitelist](0008-request-response-transformation.md)
