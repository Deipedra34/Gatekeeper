package fault

import (
	"net/http"
	"strings"
)

// BuiltinExemptPaths are never faulted, whatever any rule says: the
// usual health check paths and the dashboard. The metrics path is added
// from the config; fault_injection.exempt_paths can add more but never
// remove these.
var BuiltinExemptPaths = []string{"/healthz", "/health", "/livez", "/readyz", "/_dashboard"}

// healthCheckAgents are User-Agent prefixes of health check probes —
// load balancers', orchestrators', and Gatekeeper's own active checks —
// which are never faulted on any path.
var healthCheckAgents = []string{
	"gatekeeper-health-check",
	"kube-probe/",
	"ELB-HealthChecker/",
	"GoogleHC/",
	"Consul Health Check",
}

// exemptions decides which requests are never faulted.
type exemptions struct {
	// exact are paths exempt exactly and with anything below them
	// ("/healthz" covers "/healthz/ready"); prefixes are entries ending
	// in "/", exempt as prefixes.
	exact    []string
	prefixes []string
}

func newExemptions(metricsPath string, extra []string) exemptions {
	var e exemptions
	for _, p := range append(append([]string{metricsPath}, BuiltinExemptPaths...), extra...) {
		switch {
		case p == "":
		case strings.HasSuffix(p, "/"):
			e.prefixes = append(e.prefixes, p)
		default:
			e.exact = append(e.exact, p)
		}
	}
	return e
}

// exempt reports whether r must never be faulted.
func (e exemptions) exempt(r *http.Request) bool {
	path := r.URL.Path
	for _, p := range e.exact {
		if path == p || (strings.HasPrefix(path, p) && path[len(p)] == '/') {
			return true
		}
	}
	for _, p := range e.prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	ua := r.Header.Get("User-Agent")
	for _, agent := range healthCheckAgents {
		if strings.HasPrefix(ua, agent) {
			return true
		}
	}
	return false
}
