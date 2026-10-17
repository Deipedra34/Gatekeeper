package tracing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"gatekeeper/internal/config"
)

func ratio(f float64) *float64 { return &f }

func TestNew_DisabledByConfigOrEnv(t *testing.T) {
	p, err := New(context.Background(), config.TracingConfig{Enabled: false}, nil)
	require.NoError(t, err)
	assert.False(t, p.Enabled())

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	assert.NotNil(t, p.Handler(next, nil))

	for env, val := range map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_TRACES_EXPORTER": "none"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, val)
			p, err := New(context.Background(), config.TracingConfig{Enabled: true, Exporter: config.TraceExporterStdout}, nil)
			require.NoError(t, err)
			assert.False(t, p.Enabled(), "%s=%s turns tracing off", env, val)
		})
	}
}

func TestEffectiveExporter_EnvOverrides(t *testing.T) {
	cases := []struct {
		configured string
		env        map[string]string
		want       string
	}{
		{config.TraceExporterOTLPGRPC, nil, config.TraceExporterOTLPGRPC},
		{config.TraceExporterOTLPGRPC, map[string]string{"OTEL_TRACES_EXPORTER": "console"}, config.TraceExporterStdout},
		{config.TraceExporterStdout, map[string]string{"OTEL_TRACES_EXPORTER": "otlp"}, config.TraceExporterOTLPGRPC},
		{config.TraceExporterOTLPGRPC, map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf"}, config.TraceExporterOTLPHTTP},
		{config.TraceExporterOTLPHTTP, map[string]string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc"}, config.TraceExporterOTLPGRPC},
		{config.TraceExporterStdout, map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"}, config.TraceExporterStdout},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			assert.Equal(t, tc.want, effectiveExporter(tc.configured))
		})
	}
}

func TestNew_ServiceNameAndResourceFromConfigAndEnv(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	cfg := config.TracingConfig{
		Enabled: true, Exporter: config.TraceExporterStdout, ServiceName: "edge-gw",
		ResourceAttributes: map[string]string{"deployment.environment": "staging", "service.version": "2.3.0"},
	}
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=prod")

	p, err := New(context.Background(), cfg, nil, WithSpanProcessor(rec), WithStdoutWriter(io.Discard))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	p.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	require.Len(t, rec.Ended(), 1)

	res := map[string]string{}
	for _, kv := range rec.Ended()[0].Resource().Attributes() {
		res[string(kv.Key)] = kv.Value.Emit()
	}
	assert.Equal(t, "edge-gw", res["service.name"])
	assert.Equal(t, "2.3.0", res["service.version"])
	assert.Equal(t, "prod", res["deployment.environment"], "OTEL_RESOURCE_ATTRIBUTES overrides config")

	t.Setenv("OTEL_SERVICE_NAME", "from-env")
	p2, err := New(context.Background(), cfg, nil, WithSpanProcessor(rec), WithStdoutWriter(io.Discard))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p2.Shutdown(context.Background()) })
	rec.Reset()
	p2.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	for _, kv := range rec.Ended()[0].Resource().Attributes() {
		if kv.Key == "service.name" {
			assert.Equal(t, "from-env", kv.Value.Emit())
		}
	}
}

func TestNew_SamplerFromEnvWins(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	p, err := New(context.Background(), config.TracingConfig{Enabled: true, Exporter: config.TraceExporterStdout, SampleRatio: ratio(1)},
		nil, WithSpanProcessor(rec), WithStdoutWriter(io.Discard))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	p.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Empty(t, rec.Ended())
}

func TestStdoutExporterWritesSpans(t *testing.T) {
	var out bytes.Buffer
	p, err := New(context.Background(), config.TracingConfig{Enabled: true, Exporter: config.TraceExporterStdout, ServiceName: "gatekeeper"},
		nil, WithStdoutWriter(&out))
	require.NoError(t, err)
	p.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	require.NoError(t, p.Shutdown(context.Background()))
	assert.Contains(t, out.String(), `"Name": "GET unmatched"`)
}

func TestHashClientID(t *testing.T) {
	a := HashClientID("sk-live-secret")
	assert.Len(t, a, 16)
	assert.Equal(t, a, HashClientID("sk-live-secret"), "stable within a process")
	assert.NotEqual(t, a, HashClientID("sk-live-secreT"))
	assert.NotContains(t, a, "secret")
	assert.Empty(t, HashClientID(""))
}

func TestErrorType(t *testing.T) {
	refused := &url.Error{Op: "Get", URL: "http://b/x?token=s3cret", Err: &net.OpError{Op: "dial", Err: errors.New("boom")}}
	cases := map[string]error{
		"":                  nil,
		"canceled":          context.Canceled,
		"timeout":           fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
		"dns":               &net.DNSError{Err: "no such host", Name: "nope.invalid"},
		"connection_closed": io.ErrUnexpectedEOF,
		"other":             refused,
	}
	for want, err := range cases {
		assert.Equal(t, want, ErrorType(err), "%v", err)
	}

	// A real refused connection, whatever language the OS reports it in.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close()
	_, err = net.DialTimeout("tcp", addr, time.Second)
	require.Error(t, err)
	assert.Equal(t, "connection_refused", ErrorType(err))
	assert.NotContains(t, ErrorType(refused), "s3cret")
}

func TestMethodNormalisation(t *testing.T) {
	assert.Equal(t, "GET", Method("GET"))
	assert.Equal(t, "_OTHER", Method("get"))
	assert.Equal(t, "_OTHER", Method("BREW-secret"))
}

func TestErrorHandlerIsRateLimited(t *testing.T) {
	var out bytes.Buffer
	h := &errorHandler{logger: log.New(&out, "", 0), interval: 50 * time.Millisecond}
	for i := 0; i < 100; i++ {
		h.Handle(errors.New("collector unreachable"))
	}
	assert.Equal(t, 1, strings.Count(out.String(), "\n"), "one line for a burst of errors")

	time.Sleep(60 * time.Millisecond)
	h.Handle(errors.New("collector unreachable"))
	assert.Contains(t, out.String(), "99 similar errors suppressed")
}

func TestHandler_ResponseHeaderAndStatus(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p, err := New(context.Background(), config.TracingConfig{Enabled: true, Exporter: config.TraceExporterStdout, ResponseHeader: "X-Trace-Id"},
		nil, WithSpanProcessor(rec), WithStdoutWriter(io.Discard))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	h := p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}), func(*http.Request) (string, bool) { return "/api", true })
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/x?secret=1", nil))

	span := rec.Ended()[0]
	assert.Equal(t, "POST /api", span.Name())
	assert.Equal(t, span.SpanContext().TraceID().String(), w.Header().Get("X-Trace-Id"))
	assert.Equal(t, "Error", span.Status().Code.String())
}
