package fault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gatekeeper/internal/config"
)

func TestRule_Summary(t *testing.T) {
	no := false
	r := NewRule("r", "/api", SourceConfig, config.RouteFaultConfig{
		Delay: &config.FaultDelay{Percentage: 10, Fixed: dur(500 * time.Millisecond)},
		Abort: &config.FaultAbort{Percentage: 2.5, Status: 503},
		Match: config.FaultMatch{
			Header:  &config.ValueMatch{Name: "X-Gatekeeper-Fault", Value: "true"},
			Clients: &config.FaultClients{Tiers: []string{"internal"}, APIKeys: []string{"secret-key"}},
		},
		CountAsBackendFailure: &no,
	}, time.Now())
	s := r.Summary()
	assert.Equal(t, "delay 10% 500ms, abort 2.5% 503; header X-Gatekeeper-Fault=true; clients tiers internal 1 api key(s); not counted as backend failures", s)
	assert.NotContains(t, s, "secret-key", "API keys are never logged")

	ranged := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Delay:           &config.FaultDelay{Percentage: 100, Min: dur(100 * time.Millisecond), Max: dur(time.Second)},
		ConnectionReset: &config.FaultReset{Percentage: 1},
	}, time.Now())
	assert.Equal(t, "delay 100% 100ms-1s, reset 1%; every request", ranged.Summary())
}

func TestRule_SummaryRedactsCredentialHeaders(t *testing.T) {
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 5, Status: 500},
		Match: config.FaultMatch{Header: &config.ValueMatch{Name: "X-Chaos-Token", Value: "s3cret-value"}},
	}, time.Now())
	assert.Equal(t, "abort 5% 500; header X-Chaos-Token=[REDACTED]", r.Summary())
}

func TestRule_Remaining(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := NewRule("r", "/", SourceConfig, config.RouteFaultConfig{
		Abort:       &config.FaultAbort{Percentage: 1, Status: 500},
		MaxDuration: dur(time.Hour),
	}, start)
	assert.Equal(t, 45*time.Minute, r.Remaining(start.Add(15*time.Minute)))
	assert.Zero(t, r.Remaining(start.Add(time.Hour)))

	forever := NewRule("f", "/", SourceConfig, config.RouteFaultConfig{
		Abort: &config.FaultAbort{Percentage: 1, Status: 500},
	}, start)
	assert.Equal(t, time.Duration(-1), forever.Remaining(start.Add(1000*time.Hour)))
}
