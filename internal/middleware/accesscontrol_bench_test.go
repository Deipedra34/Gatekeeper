package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"gatekeeper/internal/accesscontrol"
	"gatekeeper/internal/ratelimiter/store"
)

// largeDenyList is n distinct /32s and /24s under 100.64.0.0/10.
func largeDenyList(n int) []string {
	out := make([]string, n)
	for i := range n {
		if i%2 == 0 {
			out[i] = fmt.Sprintf("100.%d.%d.%d", 64+(i>>16)%64, (i>>8)&255, i&255)
		} else {
			out[i] = fmt.Sprintf("100.%d.%d.0/24", 64+(i>>16)%64, (i>>8)&255)
		}
	}
	return out
}

// BenchmarkAccessControl measures what the middleware adds to a request
// with a 10,000-entry deny list: resolving the client address, the
// list lookup, and — with a store — the ban check.
func BenchmarkAccessControl(b *testing.B) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	deny := largeDenyList(10_000)
	run := func(b *testing.B, c *accesscontrol.Controller, remote string) {
		h := AccessControl(c, nil)(ok)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		b.ReportAllocs()
		for b.Loop() {
			h.ServeHTTP(w, req)
		}
	}

	lists, err := accesscontrol.NewController(accesscontrol.Settings{
		Global: accesscontrol.PolicySettings{Mode: accesscontrol.ModeDenylist, Deny: deny},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("allowed/lists_only", func(b *testing.B) { run(b, lists, "203.0.113.7:4711") })
	b.Run("blocked/lists_only", func(b *testing.B) { run(b, lists, "100.64.0.0:4711") })

	st := store.NewMemoryStore()
	defer st.Close()
	withBans, err := accesscontrol.NewController(accesscontrol.Settings{
		Global: accesscontrol.PolicySettings{Mode: accesscontrol.ModeDenylist, Deny: deny},
		Store:  st,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("allowed/lists_and_memory_bans", func(b *testing.B) { run(b, withBans, "203.0.113.7:4711") })
}
