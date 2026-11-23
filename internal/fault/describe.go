package fault

import (
	"strconv"
	"strings"
	"time"
)

// Summary describes the rule in one line, for log lines: what it
// injects and how it's targeted, e.g. "delay 10% 500ms, abort 5% 503;
// header X-Gatekeeper-Fault=true".
func (r *Rule) Summary() string {
	c := r.Config
	var faults []string
	if d := c.Delay; d != nil {
		how := d.Fixed.Duration.String()
		if d.Fixed.Duration == 0 {
			how = d.Min.Duration.String() + "-" + d.Max.Duration.String()
		}
		faults = append(faults, "delay "+percent(d.Percentage)+" "+how)
	}
	if a := c.Abort; a != nil {
		faults = append(faults, "abort "+percent(a.Percentage)+" "+strconv.Itoa(a.Status))
	}
	if rs := c.ConnectionReset; rs != nil {
		faults = append(faults, "reset "+percent(rs.Percentage))
	}
	out := strings.Join(faults, ", ")

	var targets []string
	m := c.Match
	if h := m.Header; h != nil {
		t := "header " + h.Name
		if h.Value != "" {
			t += "=" + h.Value
		}
		targets = append(targets, t)
	}
	if len(m.PathPrefixes) > 0 {
		targets = append(targets, "paths "+strings.Join(m.PathPrefixes, ","))
	}
	if len(m.Methods) > 0 {
		targets = append(targets, "methods "+strings.Join(m.Methods, ","))
	}
	if len(m.Variants) > 0 {
		targets = append(targets, "variants "+strings.Join(m.Variants, ","))
	}
	if len(m.Backends) > 0 {
		targets = append(targets, "backends "+strings.Join(m.Backends, ","))
	}
	if cl := m.Clients; cl != nil {
		// API keys are secrets: counted, never logged.
		var who []string
		if len(cl.Tiers) > 0 {
			who = append(who, "tiers "+strings.Join(cl.Tiers, ","))
		}
		if len(cl.CIDRs) > 0 {
			who = append(who, "cidrs "+strings.Join(cl.CIDRs, ","))
		}
		if n := len(cl.APIKeys); n > 0 {
			who = append(who, strconv.Itoa(n)+" api key(s)")
		}
		targets = append(targets, "clients "+strings.Join(who, " "))
	}
	if len(targets) == 0 {
		targets = append(targets, "every request")
	}
	out += "; " + strings.Join(targets, "; ")
	if !c.CountsAsBackendFailure() {
		out += "; not counted as backend failures"
	}
	return out
}

// Remaining is how long the rule stays in force after now: 0 once it has
// expired, and -1 when it never expires.
func (r *Rule) Remaining(now time.Time) time.Duration {
	switch {
	case r.Expires.IsZero():
		return -1
	case r.ExpiredAt(now):
		return 0
	}
	return r.Expires.Sub(now)
}

func percent(p float64) string {
	return strconv.FormatFloat(p, 'f', -1, 64) + "%"
}
