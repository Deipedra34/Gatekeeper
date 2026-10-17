package config

import (
	"fmt"
	"net/http"
	"strings"
)

// Trace exporters for TracingConfig.Exporter.
const (
	TraceExporterOTLPGRPC = "otlp_grpc"
	TraceExporterOTLPHTTP = "otlp_http"
	TraceExporterStdout   = "stdout"
)

// DefaultTracingServiceName is the service.name reported when none is
// configured.
const DefaultTracingServiceName = "gatekeeper"

// TracingConfig controls OpenTelemetry distributed tracing. It's off by
// default; with it off, Gatekeeper creates no spans and forwards any
// incoming traceparent/tracestate/baggage headers untouched, exactly as
// before. The standard OTEL_* environment variables override these
// settings (see README.md's "Distributed tracing" section). Changes are
// picked up on SIGHUP.
type TracingConfig struct {
	Enabled bool `yaml:"enabled"`

	// Exporter is "otlp_grpc" (the default), "otlp_http", or "stdout"
	// (pretty-printed spans, for local debugging).
	Exporter string `yaml:"exporter"`

	// Endpoint is the collector address: "host:port", or a URL such as
	// "http://collector:4318". Defaults to the exporter's standard local
	// endpoint (localhost:4317 for gRPC, localhost:4318 for HTTP).
	Endpoint string `yaml:"endpoint"`

	// Insecure sends spans without TLS, for a local collector.
	Insecure bool `yaml:"insecure"`

	// ServiceName is reported as the service.name resource attribute.
	// Defaults to "gatekeeper".
	ServiceName string `yaml:"service_name"`

	// SampleRatio is the fraction of new traces recorded, from 0 to 1.
	// Defaults to 1. Sampling is parent-based: a request that arrives with
	// a sampled (or unsampled) traceparent follows its caller's decision.
	SampleRatio *float64 `yaml:"sample_ratio"`

	// ResourceAttributes are extra resource attributes, e.g.
	// deployment.environment or service.version.
	ResourceAttributes map[string]string `yaml:"resource_attributes"`

	// ResponseHeader, when set (e.g. "X-Trace-Id"), returns each
	// request's trace ID to the client in that response header. Off by
	// default.
	ResponseHeader string `yaml:"response_header"`
}

// EffectiveSampleRatio returns SampleRatio, defaulting to 1.
func (t TracingConfig) EffectiveSampleRatio() float64 {
	if t.SampleRatio == nil {
		return 1
	}
	return *t.SampleRatio
}

func (t *TracingConfig) applyDefaults() {
	if t.Exporter == "" {
		t.Exporter = TraceExporterOTLPGRPC
	}
	if t.ServiceName == "" {
		t.ServiceName = DefaultTracingServiceName
	}
}

func (t TracingConfig) validate() error {
	switch t.Exporter {
	case TraceExporterOTLPGRPC, TraceExporterOTLPHTTP, TraceExporterStdout:
	default:
		return fmt.Errorf("tracing.exporter must be one of otlp_grpc, otlp_http, stdout, got %q", t.Exporter)
	}
	if r := t.EffectiveSampleRatio(); r < 0 || r > 1 {
		return fmt.Errorf("tracing.sample_ratio must be between 0 and 1, got %v", r)
	}
	for k := range t.ResourceAttributes {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("tracing.resource_attributes keys must not be empty")
		}
	}
	if h := t.ResponseHeader; h != "" && (strings.ContainsAny(h, " \t\r\n:") || http.CanonicalHeaderKey(h) == "") {
		return fmt.Errorf("tracing.response_header %q is not a valid header name", h)
	}
	return nil
}
