package tracing

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"gatekeeper/internal/config"
)

// Provider is one tracing pipeline built from a config.TracingConfig. A
// disabled Provider is valid and does nothing.
type Provider struct {
	cfg            config.TracingConfig
	tp             *sdktrace.TracerProvider // nil when disabled
	propagator     propagation.TextMapPropagator
	responseHeader string
	description    string
}

// Option customises New; used by tests.
type Option func(*options)

type options struct {
	processors []sdktrace.SpanProcessor
	stdout     io.Writer
}

// WithSpanProcessor adds a span processor alongside the exporter's (for
// example an in-memory recorder in tests).
func WithSpanProcessor(sp sdktrace.SpanProcessor) Option {
	return func(o *options) { o.processors = append(o.processors, sp) }
}

// WithStdoutWriter redirects the stdout exporter.
func WithStdoutWriter(w io.Writer) Option {
	return func(o *options) { o.stdout = w }
}

// New builds a Provider for cfg, with the standard OTEL_* environment
// variables taking precedence over it:
//
//   - OTEL_SDK_DISABLED=true, or OTEL_TRACES_EXPORTER=none, disables tracing.
//   - OTEL_TRACES_EXPORTER=console selects the stdout exporter, =otlp an
//     OTLP one, with OTEL_EXPORTER_OTLP[_TRACES]_PROTOCOL ("grpc" or
//     "http/protobuf") choosing which.
//   - OTEL_EXPORTER_OTLP[_TRACES]_ENDPOINT, _INSECURE, _HEADERS, _TIMEOUT,
//     OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES, OTEL_TRACES_SAMPLER[_ARG],
//     and OTEL_BSP_* are honoured as the OpenTelemetry SDK defines them.
//
// Creating the exporter never contacts the collector, so an unreachable
// collector can't block or fail startup; spans are exported in the
// background by a batch processor with a bounded queue that drops spans
// rather than ever blocking a request.
func New(ctx context.Context, cfg config.TracingConfig, logger *log.Logger, opts ...Option) (*Provider, error) {
	if logger == nil {
		logger = log.Default()
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	p := &Provider{cfg: cfg, description: "disabled"}
	if !cfg.Enabled || envTrue("OTEL_SDK_DISABLED") || strings.EqualFold(os.Getenv("OTEL_TRACES_EXPORTER"), "none") {
		return p, nil
	}
	installErrorHandler(logger)

	exporterName := effectiveExporter(cfg.Exporter)
	exp, err := newExporter(ctx, exporterName, cfg, o.stdout)
	if err != nil {
		return nil, fmt.Errorf("tracing: creating %s exporter: %w", exporterName, err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(resourceAttributes(cfg)...),
		resource.WithFromEnv(), // OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES win
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: building resource: %w", err)
	}

	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		// Bounded queue, non-blocking: a slow or dead collector costs
		// dropped spans, never request latency. Queue/batch sizes and
		// timeouts come from OTEL_BSP_* or the SDK defaults.
		sdktrace.WithBatcher(exp),
	}
	sampling := fmt.Sprintf("parentbased_traceidratio=%g", cfg.EffectiveSampleRatio())
	if os.Getenv("OTEL_TRACES_SAMPLER") == "" {
		tpOpts = append(tpOpts, sdktrace.WithSampler(
			sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.EffectiveSampleRatio()))))
	} else {
		sampling = "from OTEL_TRACES_SAMPLER"
	}
	for _, sp := range o.processors {
		tpOpts = append(tpOpts, sdktrace.WithSpanProcessor(sp))
	}

	p.tp = sdktrace.NewTracerProvider(tpOpts...)
	p.propagator = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	p.responseHeader = cfg.ResponseHeader
	p.description = fmt.Sprintf("exporter=%s endpoint=%s sampler=%s", exporterName, describeEndpoint(exporterName, cfg), sampling)
	return p, nil
}

// Enabled reports whether this Provider records spans.
func (p *Provider) Enabled() bool { return p != nil && p.tp != nil }

// Config returns the config the Provider was built from.
func (p *Provider) Config() config.TracingConfig { return p.cfg }

// Description summarises the effective setup for the startup log line.
// It never includes credentials (OTLP headers are not shown).
func (p *Provider) Description() string { return p.description }

// Shutdown flushes buffered spans and stops the exporter, waiting at
// most until ctx is done. A disabled Provider returns immediately.
func (p *Provider) Shutdown(ctx context.Context) error {
	if !p.Enabled() {
		return nil
	}
	return p.tp.Shutdown(ctx)
}

// ForceFlush exports every span ended so far; used by tests.
func (p *Provider) ForceFlush(ctx context.Context) error {
	if !p.Enabled() {
		return nil
	}
	return p.tp.ForceFlush(ctx)
}

// effectiveExporter applies OTEL_TRACES_EXPORTER and the OTLP protocol
// variables to the configured exporter.
func effectiveExporter(configured string) string {
	exporter := configured
	switch strings.ToLower(os.Getenv("OTEL_TRACES_EXPORTER")) {
	case "console":
		return config.TraceExporterStdout
	case "otlp":
		if exporter == config.TraceExporterStdout {
			exporter = config.TraceExporterOTLPGRPC
		}
	}
	if exporter == config.TraceExporterStdout {
		return exporter
	}
	protocol := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
	if protocol == "" {
		protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch strings.ToLower(protocol) {
	case "grpc":
		return config.TraceExporterOTLPGRPC
	case "http/protobuf", "http/json":
		return config.TraceExporterOTLPHTTP
	}
	return exporter
}

func newExporter(ctx context.Context, name string, cfg config.TracingConfig, stdout io.Writer) (sdktrace.SpanExporter, error) {
	endpointFromEnv := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
	insecureFromEnv := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_INSECURE") != "" || os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") != ""
	endpointIsURL := strings.Contains(cfg.Endpoint, "://")

	switch name {
	case config.TraceExporterStdout:
		if stdout == nil {
			stdout = os.Stdout
		}
		return stdouttrace.New(stdouttrace.WithWriter(stdout), stdouttrace.WithPrettyPrint())

	case config.TraceExporterOTLPHTTP:
		var opts []otlptracehttp.Option
		if cfg.Endpoint != "" && !endpointFromEnv {
			if endpointIsURL {
				opts = append(opts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
			} else {
				opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
			}
		}
		if cfg.Insecure && !insecureFromEnv {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		opts = append(opts, otlptracehttp.WithRetry(exportRetry))
		return otlptracehttp.New(ctx, opts...)

	default: // config.TraceExporterOTLPGRPC
		var opts []otlptracegrpc.Option
		if cfg.Endpoint != "" && !endpointFromEnv {
			if endpointIsURL {
				opts = append(opts, otlptracegrpc.WithEndpointURL(cfg.Endpoint))
			} else {
				opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
			}
		}
		if cfg.Insecure && !insecureFromEnv {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		opts = append(opts, otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig(exportRetry)))
		return otlptracegrpc.New(ctx, opts...)
	}
}

// exportRetry bounds how long the background exporter keeps retrying a
// failed batch, so a dead collector doesn't pin batches for long.
var exportRetry = otlptracehttp.RetryConfig{
	Enabled:         true,
	InitialInterval: time.Second,
	MaxInterval:     5 * time.Second,
	MaxElapsedTime:  15 * time.Second,
}

func describeEndpoint(exporter string, cfg config.TracingConfig) string {
	switch {
	case exporter == config.TraceExporterStdout:
		return "stdout"
	case os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "":
		return "from OTEL_EXPORTER_OTLP_*_ENDPOINT"
	case cfg.Endpoint != "":
		return cfg.Endpoint
	default:
		return "default"
	}
}

func resourceAttributes(cfg config.TracingConfig) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String("service.name", cfg.ServiceName)}
	for k, v := range cfg.ResourceAttributes {
		if k == "service.name" {
			attrs[0] = attribute.String(k, v)
			continue
		}
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}

func envTrue(name string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(name)), "true")
}

// errorHandler reports OpenTelemetry's internal errors — almost always
// export failures while a collector is down — at most once per interval,
// with a count of what it held back, so an outage doesn't flood the log.
type errorHandler struct {
	logger   *log.Logger
	interval time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (h *errorHandler) Handle(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.last.IsZero() && now.Sub(h.last) < h.interval {
		h.suppressed++
		return
	}
	if h.suppressed > 0 {
		h.logger.Printf("tracing: export error (%d similar errors suppressed in the last %s): %v", h.suppressed, h.interval, err)
	} else {
		h.logger.Printf("tracing: export error (requests are unaffected; spans may be dropped): %v", err)
	}
	h.last = now
	h.suppressed = 0
}

var installOnce sync.Once

// installErrorHandler routes OpenTelemetry's global error reporting
// through a rate-limited logger. OpenTelemetry only offers a global hook
// for this, so it's installed once per process.
func installErrorHandler(logger *log.Logger) {
	installOnce.Do(func() {
		otel.SetErrorHandler(&errorHandler{logger: logger, interval: 30 * time.Second})
	})
}
