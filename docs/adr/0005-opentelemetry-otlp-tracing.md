# 5. OpenTelemetry with OTLP for distributed tracing

## Status

Accepted

## Context

A request through Gatekeeper passes auth, rate limiting, the response
cache, the circuit breaker, and up to `max_retries + 1` backend attempts.
Metrics say *how often* each of those happens, but not *which* stage made
a particular request slow or failed it, and nothing connects a gateway
request to the backend work it caused. That needs distributed tracing:
per-request spans, with trace context carried across the proxy hop.

Requirements that shaped the choice:

- **Join the caller's trace and continue it to backends**, whatever
  tracing those services use — so the wire format must be a standard,
  not a vendor's.
- **No lock-in on where traces go.** Operators run Jaeger, Grafana Tempo,
  Honeycomb, Datadog, or a cloud vendor; the gateway shouldn't care.
- **Fail-open.** A dead or slow tracing backend must never add latency to
  or fail a request; the gateway's availability can't depend on it (the
  same principle as [ADR 4](0004-fallback-store-graceful-degradation.md)).
- **Zero cost and zero behaviour change when off**, so existing
  deployments are unaffected.

## Decision

- **OpenTelemetry** (`go.opentelemetry.io/otel`) for the API and SDK.
  It's the CNCF standard that superseded OpenTracing and OpenCensus,
  every major backend accepts its data, and the Go SDK is stable.
- **W3C Trace Context and Baggage** (`traceparent`, `tracestate`,
  `baggage`) as the only propagation formats — the IETF/W3C standard
  OpenTelemetry defaults to and other ecosystems understand.
- **OTLP** as the export protocol (gRPC by default, HTTP as an option),
  plus a stdout exporter for local debugging. OTLP is what the
  OpenTelemetry Collector and most backends ingest natively, so the
  recommended deployment is gateway → Collector → any backend: changing
  backends is a Collector config change, never a gateway change. No
  vendor-specific exporter (Jaeger Thrift, Zipkin) is linked in.
- **Batch span processor** with the SDK's bounded, non-blocking queue:
  ending a span is an in-memory enqueue; export happens in the
  background, and a full queue drops spans instead of blocking.
- **Hand-written server span instead of `otelhttp`**, so exactly which
  attributes are recorded is decided — and reviewed — in this codebase.
  A generic instrumentation library chooses its own attribute set, and
  that set has changed between releases as the HTTP semantic
  conventions evolved; a gateway carrying credentials needs a fixed set
  it controls.
- **Spans are started from the span already in the request context**
  rather than from a tracer plumbed through every component. With
  tracing off there is no span in the context and every call is a no-op.
- **The standard `OTEL_*` environment variables override the config
  file**, as operators of OpenTelemetry-instrumented services expect.

## Consequences

- Traces flow into any OTLP-capable backend, and a trace started by a
  caller continues through Gatekeeper into its backends.
- New dependencies: the OpenTelemetry API/SDK and OTLP exporters, which
  pull in gRPC and protobuf. They're only exercised when tracing is
  enabled, but they do enlarge the binary and the module graph.
- Under a collector outage, spans are dropped once the queue fills;
  requests are unaffected, and export errors are logged at most once
  every 30 seconds. Traces are best-effort by design.
- Because the attribute set is hand-picked, it's narrower than generic
  HTTP instrumentation (no path, query, headers, or user agent). That's
  the privacy guarantee, and it means adding an attribute is a
  deliberate code change, reviewed for safety.
- OpenTelemetry's error handler is process-global, so the rate-limited
  handler is installed once per process.
