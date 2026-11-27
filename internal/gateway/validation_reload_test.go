package gateway_test

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
)

func TestGatewayValidation_StartupFailsOnABrokenSpec(t *testing.T) {
	b := newSplitBackend(t, "b")
	dir := t.TempDir()
	for _, tc := range []struct {
		name, spec, want string
	}{
		{"missing", filepath.Join(dir, "missing.yaml"), "does not exist"},
		{"invalid", writeSpec(t, dir, "openapi: 3.0.3\ninfo: {title: T}\npaths: {}\n"), "is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, t.TempDir(), "config.yaml", validationYAML(b.srv.URL, tc.spec, 100, "", ""))
			cfg, err := config.Load(path)
			require.NoError(t, err, "the config itself is fine")
			_, err = gateway.New(cfg, path, store.NewMemoryStore(), metrics.New(), log.New(io.Discard, "", 0))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "route /api: validation: OpenAPI spec")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestGatewayValidation_ReloadSwapsTheSpec(t *testing.T) {
	b := newSplitBackend(t, "b")
	dir := t.TempDir()
	spec := writeSpec(t, dir, ordersSpecWithMax(10))
	h := newSplitHarness(t, validationYAML(b.srv.URL, spec, 1000, "", ""))
	assert.Equal(t, http.StatusBadRequest, h.send(http.MethodGet, "/api/orders?limit=50", "", testerKey, "tester").Code)
	before := h.gw.Validation()[0].Validator.Spec()

	writeSpec(t, dir, ordersSpecWithMax(100))
	require.NoError(t, h.gw.Reload(), "a reload (SIGHUP) re-reads the spec")
	assert.Equal(t, http.StatusOK, h.send(http.MethodGet, "/api/orders?limit=50", "", testerKey, "tester").Code)
	rv := h.gw.Validation()
	require.Len(t, rv, 1)
	assert.Equal(t, "100", rv[0].Validator.Spec().Version)
	assert.NotSame(t, before, rv[0].Validator.Spec(), "compiled anew")
	assert.False(t, rv[0].Validator.Spec().LoadedAt.Before(before.LoadedAt))
	assert.EqualValues(t, 1, rv[0].Stats.Snapshot().Rejected, "counts survive the reload")
	assert.Contains(t, h.logs.String(), `validation: route /api: rejecting requests that don't match `+filepath.ToSlash(spec)+` ("Orders" 100, OpenAPI 3.0.3, 2 operations`)
}

func TestGatewayValidation_InvalidSpecOnReloadKeepsTheOldOne(t *testing.T) {
	b := newSplitBackend(t, "b")
	dir := t.TempDir()
	spec := writeSpec(t, dir, ordersSpecWithMax(10))
	h := newSplitHarness(t, validationYAML(b.srv.URL, spec, 1000, "", ""))
	before := h.gw.Validation()[0].Validator.Spec()

	for _, broken := range []string{"openapi: [", "openapi: 3.0.3\npaths: {}\n"} {
		writeSpec(t, dir, broken)
		assert.Error(t, h.gw.ValidateConfigFile(), "the dry-run reload checks the spec too")
		err := h.gw.Reload()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAPI spec")
		assert.Same(t, before, h.gw.Validation()[0].Validator.Spec(), "the spec in force is kept")
		assert.Equal(t, http.StatusBadRequest, h.send(http.MethodGet, "/api/orders?limit=50", "", testerKey, "tester").Code,
			"and still enforced")
	}

	require.NoError(t, os.Remove(spec))
	require.Error(t, h.gw.Reload(), "a deleted spec fails the reload too")
	assert.Equal(t, http.StatusOK, h.send(http.MethodGet, "/api/orders?limit=5", "", testerKey, "tester").Code)
}

func TestGatewayValidation_ReloadUnderLoadDropsNothing(t *testing.T) {
	b := newSplitBackend(t, "b")
	dir := t.TempDir()
	spec := writeSpec(t, dir, ordersSpecWithMax(10))
	h := newSplitHarness(t, validationYAML(b.srv.URL, spec, 100000, "", ""))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	unexpected := map[int]int{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Valid under both specs: always forwarded.
				ok := h.send(http.MethodPost, "/api/orders", `{"qty":2}`, testerKey, "tester").Code
				// Invalid under both specs: always rejected.
				bad := h.send(http.MethodPost, "/api/orders", `{"qty":0}`, testerKey, "tester").Code
				if ok != http.StatusOK || bad != http.StatusBadRequest {
					mu.Lock()
					unexpected[ok]++
					unexpected[bad]++
					mu.Unlock()
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		max := 10
		if i%2 == 0 {
			max = 100
		}
		writeSpec(t, dir, ordersSpecWithMax(max))
		require.NoError(t, h.gw.Reload())
	}
	close(stop)
	wg.Wait()
	assert.Empty(t, unexpected, "every in-flight request finished on the old spec or the new one")
}
