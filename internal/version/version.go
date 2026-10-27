// Package version holds the build metadata reported by `gatekeeper
// -version`. Release builds set the variables below through the linker
// (see .goreleaser.yaml):
//
//	-X gatekeeper/internal/version.Version=2.5.0
//	-X gatekeeper/internal/version.Commit=0e34e8b...
//	-X gatekeeper/internal/version.Date=2026-10-27T12:00:00Z
//
// A plain `go build` leaves them at their defaults.
package version

import (
	"fmt"
	"runtime"
)

// Set via -ldflags "-X ..." at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns the human-readable version report printed by
// `gatekeeper -version`.
func String() string {
	return fmt.Sprintf("gatekeeper %s\ncommit: %s\nbuilt: %s\ngo: %s %s/%s",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
