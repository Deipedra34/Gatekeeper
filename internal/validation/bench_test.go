package validation

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"gatekeeper/internal/config"
)

// Run with: go test ./internal/validation -run '^$' -bench . -benchmem

func benchValidator(b *testing.B) *Validator {
	b.Helper()
	spec, err := ParseSpec("bench.yaml", []byte(testSpec), "X-Api-Key")
	if err != nil {
		b.Fatal(err)
	}
	return New(spec, config.RouteValidation{})
}

// benchCheck checks a fresh request built by newReq on every iteration,
// failing if its outcome isn't want.
func benchCheck(b *testing.B, v *Validator, want Outcome, newReq func() *http.Request) {
	b.Helper()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		req := newReq()
		b.StartTimer()
		if res := v.Check(ctx, req); res.Outcome != want {
			b.Fatalf("got %v: %+v", res.Outcome, res.Violations)
		}
	}
}

func BenchmarkCheck_QueryParameters(b *testing.B) {
	v := benchValidator(b)
	benchCheck(b, v, Passed, func() *http.Request {
		return request(http.MethodGet, "/v1/items?limit=10&sort=asc&since=2026-01-02T03:04:05Z", "", "")
	})
}

func BenchmarkCheck_UnknownOperation(b *testing.B) {
	v := benchValidator(b)
	benchCheck(b, v, Unmatched, func() *http.Request { return request(http.MethodGet, "/v1/elsewhere", "", "") })
}

func BenchmarkCheck_JSONBody(b *testing.B) {
	v := benchValidator(b)
	benchCheck(b, v, Passed, func() *http.Request { return postItem(validItem) })
}

func BenchmarkCheck_InvalidJSONBody(b *testing.B) {
	v := benchValidator(b)
	benchCheck(b, v, Invalid, func() *http.Request {
		return postItem(`{"name":"","price":-1,"kind":"car","tags":["A","B"],"extra":true}`)
	})
}

func BenchmarkCheck_JSONBody64KiB(b *testing.B) {
	v := benchValidator(b)
	pad := strings.Repeat("x", 64<<10)
	body := `{"name":"hammer","price":1,"meta":{"pad":"` + pad + `"}}`
	b.SetBytes(int64(len(body)))
	benchCheck(b, v, Passed, func() *http.Request { return postItem(body) })
}

func BenchmarkNestsDeeper_1MiB(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 1<<20 {
		sb.WriteString(`{"k":[1,2,"` + strconv.Itoa(sb.Len()) + `"]},`)
	}
	data := []byte("[" + strings.TrimSuffix(sb.String(), ",") + "]")
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if nestsDeeper(data, 32) {
			b.Fatal("not that deep")
		}
	}
}
