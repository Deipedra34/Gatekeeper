package gateway_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/split"
)

// assignments records which variant each of n clients lands on.
func assignments(h *splitHarness, n int) []string {
	out := make([]string, n)
	for i := range out {
		key := []string{"alice", "bob", "carol"}[i%3]
		out[i] = h.get("/api/x", fmt.Sprintf("10.7.%d.%d:1", i/256, i%256), "X-API-Key", key).Body.String()
	}
	return out
}

func TestGatewaySplitReload_UnrelatedChangesKeepClientsAndState(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 70, 30, 100000, "", ""))
	before := assignments(h, 300)

	sr, _ := h.gw.TrafficSplit("/api")
	require.NoError(t, sr.SetWeights(split.Weights{60, 40}, false))
	after := assignments(h, 300)

	// Reload with changes the split's state doesn't depend on: another
	// route, the response header, an override.
	h.rewrite(t, splitYAML(stable, canary, 70, 30, 100000, `      response_header: X-Variant
      override: {enabled: true, allow: {tiers: [internal]}}`, `
  - path_prefix: "/other"
    target: "http://127.0.0.1:1"
`))
	require.NoError(t, h.gw.Reload())

	sr2, _ := h.gw.TrafficSplit("/api")
	assert.NotSame(t, sr, sr2, "the route was rebuilt")
	assert.Equal(t, split.Weights{60, 40}, sr2.Weights(), "the operator's weights survived")
	assert.True(t, sr2.Status().Manual)
	assert.Equal(t, after, assignments(h, 300), "nobody moved")

	moved := 0
	for i := range before {
		if before[i] != after[i] {
			moved++
			assert.Equal(t, "canary", after[i], "growing the canary only moves clients onto it")
		}
	}
	assert.Positive(t, moved)
}

func TestGatewaySplitReload_NewWeightsMoveOnlyTheClientsTheyMust(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 90, 10, 100000, "", ""))
	before := assignments(h, 600)

	h.rewrite(t, splitYAML(stable, canary, 50, 50, 100000, "", ""))
	require.NoError(t, h.gw.Reload())
	after := assignments(h, 600)
	for i := range before {
		if before[i] == "canary" {
			assert.Equal(t, "canary", after[i], "client %d left the canary", i)
		}
	}
}

func TestGatewaySplitReload_InvalidSplitKeepsTheOldOne(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	good := splitYAML(stable, canary, 90, 10, 100000, "", "")
	h := newSplitHarness(t, good)
	h.rewrite(t, splitYAML(stable, canary, 90, 20, 100000, "", ""))
	err := h.gw.Reload()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must add up to 100, got 110")
	sr, _ := h.gw.TrafficSplit("/api")
	assert.Equal(t, split.Weights{90, 10}, sr.Weights())
}

func TestGatewaySplitReload_InFlightRequestsFinishOnTheirVariant(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "canary")
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	stable := newSplitBackend(t, "stable")
	h := newSplitHarness(t, splitYAMLFor(stable.srv.URL, slow.URL, 0, 100, 100000, "", ""))

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- h.get("/api/x", "10.0.0.1:1", "X-API-Key", "alice") }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the canary")
	}

	// Repoint the canary elsewhere, with no traffic, while it's serving.
	h.rewrite(t, splitYAMLFor(stable.srv.URL, "http://127.0.0.1:9", 100, 0, 100000, "", ""))
	require.NoError(t, h.gw.Reload())
	close(release)

	select {
	case rec := <-done:
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "canary", rec.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never finished")
	}
	assert.Equal(t, "stable", h.get("/api/x", "10.0.0.1:1", "X-API-Key", "alice").Body.String())
}

func TestGatewaySplitReload_RemovingTheSplit(t *testing.T) {
	stable, canary := newSplitBackend(t, "stable"), newSplitBackend(t, "canary")
	h := newSplitHarness(t, splitYAML(stable, canary, 50, 50, 100000, "", ""))
	h.rewrite(t, fmt.Sprintf(`
rate_limit: {tiers: {default: {requests_per_second: 0.0001, burst: 100}}}
routes:
  - path_prefix: "/api"
    target: %q
`, stable.srv.URL))
	require.NoError(t, h.gw.Reload())
	_, ok := h.gw.TrafficSplit("/api")
	assert.False(t, ok)
	for i := range 20 {
		assert.Equal(t, "stable", h.get("/api/x", fmt.Sprintf("10.0.0.%d:1", i)).Body.String())
	}
}
