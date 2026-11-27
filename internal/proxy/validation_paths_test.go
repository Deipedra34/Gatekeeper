package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/websocket/wstest"
)

func TestValidation_SpecPathsMatchTheBackendsPath(t *testing.T) {
	b := newRecordingBackend(t)
	spec := writeOrdersSpec(t)
	strip := validated(b.srv.URL, spec, config.RouteValidation{RejectUnknownOperations: true})
	strip.PathPrefix = "/shop/v2"
	strip.Transform.Request.StripPrefix = true
	rewrite := validated(b.srv.URL, spec, config.RouteValidation{RejectUnknownOperations: true})
	rewrite.PathPrefix = "/legacy"
	rewrite.Transform.Request.Rewrite = &config.PathRewrite{Pattern: `^/legacy/order-list(.*)$`, Replacement: "/orders$1"}
	router, _ := validationRouter(t, []config.Route{strip, rewrite}, noRetryProxyConfig(), nil, nil)

	assert.Equal(t, http.StatusBadRequest, send(router, http.MethodGet, "/shop/v2/orders?limit=50", "").Code,
		"/shop/v2/orders is /orders in the spec")
	assert.Equal(t, http.StatusOK, send(router, http.MethodGet, "/shop/v2/orders?limit=5", "").Code)
	assert.Equal(t, http.StatusBadRequest, send(router, http.MethodGet, "/legacy/order-list?limit=50", "").Code,
		"rewritten to /orders before matching")
	assert.Equal(t, http.StatusOK, send(router, http.MethodGet, "/legacy/order-list?limit=5", "").Code)
	assert.Equal(t, http.StatusOK, send(router, http.MethodGet, "/shop/v2/orders/7", "").Code)
	assert.Equal(t, http.StatusBadRequest, send(router, http.MethodGet, "/shop/v2/shop/v2/orders", "").Code,
		"only the stripped path is in the spec")

	var paths []string
	for _, r := range b.requests() {
		paths = append(paths, r.path)
	}
	assert.Equal(t, []string{"/orders", "/orders", "/orders/7"}, paths)
}

func TestValidation_SeesHeadersTheTransformSets(t *testing.T) {
	b := newRecordingBackend(t)
	rt := validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})
	rt.Transform.Request.SetHeaders = map[string]string{"X-Tenant": "acme"}
	rt.Transform.Response.AddHeaders = map[string]string{"X-Served-By": "gatekeeper"}
	router, _ := validationRouter(t, []config.Route{rt}, noRetryProxyConfig(), nil, nil)

	rec := send(router, http.MethodPost, "/orders", validOrder)
	assert.Equal(t, http.StatusOK, rec.Code, "the required header the gateway sets satisfies the spec")
	got := b.requests()
	require.Len(t, got, 1)
	assert.Equal(t, "acme", got[0].header.Get("X-Tenant"))

	rec = send(router, http.MethodPost, "/orders", invalidOrder)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "gatekeeper", rec.Header().Get("X-Served-By"), "a rejection gets the route's response transform too")
}

func TestValidation_SkipsWebSocketsHealthChecksAndMetrics(t *testing.T) {
	b := newRecordingBackend(t)
	echo := httptest.NewServer(wstest.EchoHandler())
	t.Cleanup(echo.Close)
	spec := writeOrdersSpec(t)
	strict := config.RouteValidation{RejectUnknownOperations: true}
	ws := validated(echo.URL, spec, strict)
	ws.PathPrefix = "/ws"
	m := metrics.New()
	router, _ := validationRouter(t, []config.Route{validated(b.srv.URL, spec, strict), ws},
		noRetryProxyConfig(), m, nil, WithMetricsPath("/metrics"))

	for _, path := range []string{"/healthz", "/health", "/livez", "/readyz", "/metrics"} {
		assert.Equal(t, http.StatusOK, send(router, http.MethodGet, path, "").Code, "%s isn't in the spec but is never validated", path)
	}
	assert.Equal(t, http.StatusBadRequest, send(router, http.MethodGet, "/healthz/details", "").Code, "only the exact paths are skipped")
	assert.Equal(t, http.StatusBadRequest, send(router, http.MethodGet, "/status", "", "User-Agent", "kube-probe/1.29").Code,
		"claiming to be a health check probe gets nothing past validation")

	gw := httptest.NewServer(router)
	t.Cleanup(gw.Close)
	c, resp, err := wstest.Dial("ws"+strings.TrimPrefix(gw.URL, "http")+"/ws/echo", nil)
	require.NoError(t, err, "a WebSocket upgrade isn't validated (status %d)", statusOf(resp))
	defer c.Close()
	require.NoError(t, c.WriteText("hi"))
	msg, err := c.ReadText()
	require.NoError(t, err)
	assert.Equal(t, "hi", msg)
	assert.Zero(t, testutil.ToFloat64(m.ValidationRequests.WithLabelValues("/ws", "rejected")))
}

func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

func TestValidation_RoutesWithoutItAreUnchanged(t *testing.T) {
	b := newRecordingBackend(t)
	m := metrics.New()
	plain := config.Route{PathPrefix: "/plain", Target: b.srv.URL}
	checked := validated(b.srv.URL, writeOrdersSpec(t), config.RouteValidation{})
	checked.PathPrefix = "/orders"
	disabled := config.Route{PathPrefix: "/off", Target: b.srv.URL, Validation: &config.RouteValidation{Enabled: false, OpenAPIFile: "missing.yaml"}}
	router, logs := validationRouter(t, []config.Route{plain, checked, disabled}, noRetryProxyConfig(), m, nil)

	for _, path := range []string{"/plain/anything?limit=abc", "/off/orders?limit=99"} {
		rec := send(router, http.MethodPost, path, "not json at all")
		assert.Equal(t, http.StatusOK, rec.Code, path)
	}
	got := b.requests()
	require.Len(t, got, 2)
	assert.Equal(t, "not json at all", got[0].body)
	assert.Equal(t, "not json at all", got[1].body)
	assert.Equal(t, 0, testutil.CollectAndCount(m.ValidationRequests), "nothing was validated")
	assert.Equal(t, 0, testutil.CollectAndCount(m.ValidationDuration))
	assert.Empty(t, logs.String())
	assert.Len(t, router.Validators(), 1, "only the enabled route has a validator; the disabled one's spec isn't even loaded")
}
