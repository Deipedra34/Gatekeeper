package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString_Defaults(t *testing.T) {
	got := String()

	for _, want := range []string{
		"gatekeeper dev",
		"commit: none",
		"built: unknown",
		"go: " + runtime.Version(),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func TestString_InjectedValues(t *testing.T) {
	oldVersion, oldCommit, oldDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldVersion, oldCommit, oldDate })

	Version, Commit, Date = "2.5.0", "abc1234", "2026-10-27T12:00:00Z"
	got := String()

	for _, want := range []string{
		"gatekeeper 2.5.0",
		"commit: abc1234",
		"built: 2026-10-27T12:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}
