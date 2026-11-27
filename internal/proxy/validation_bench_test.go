package proxy

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/config"
)

// BenchmarkRouter_Validation compares a route proxied without validation
// to the same route validated against its spec, through the whole
// router to a backend, so the difference is validation's overhead.
//
// Run with: go test ./internal/proxy -run '^$' -bench Router_Validation -benchmem
func BenchmarkRouter_Validation(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	spec := filepath.Join(b.TempDir(), "orders.yaml")
	if err := os.WriteFile(spec, []byte(ordersSpec), 0o644); err != nil {
		b.Fatal(err)
	}

	plain := config.Route{PathPrefix: "/", Target: backend.URL}
	for _, tc := range []struct {
		name   string
		route  config.Route
		method string
		target string
		body   string
		want   int
	}{
		{"off/GET", plain, http.MethodGet, "/orders?limit=5", "", http.StatusOK},
		{"on/GET", validated(backend.URL, spec, config.RouteValidation{}), http.MethodGet, "/orders?limit=5", "", http.StatusOK},
		{"off/POST", plain, http.MethodPost, "/orders", validOrder, http.StatusOK},
		{"on/POST", validated(backend.URL, spec, config.RouteValidation{}), http.MethodPost, "/orders", validOrder, http.StatusOK},
		{"on/POST-invalid", validated(backend.URL, spec, config.RouteValidation{}), http.MethodPost, "/orders", invalidOrder, http.StatusBadRequest},
	} {
		b.Run(tc.name, func(b *testing.B) {
			quiet := accesscontrol.NewLogThrottle(log.New(io.Discard, "", 0), time.Second, 10)
			router, err := NewRouter([]config.Route{tc.route}, noRetryProxyConfig(), nil, nil, WithValidationLog(quiet))
			if err != nil {
				b.Fatal(err)
			}
			defer router.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Tenant", "acme")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != tc.want {
					b.Fatalf("status %d: %s", rec.Code, rec.Body.String())
				}
			}
		})
	}
}
