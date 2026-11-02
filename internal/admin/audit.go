package admin

import (
	"encoding/json"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// auditRecord is one line of the admin audit log. It records who did
// what and how it went — never request bodies, headers, or credentials.
type auditRecord struct {
	Time       string  `json:"time"`
	Event      string  `json:"event"`
	SourceIP   string  `json:"source_ip"`
	Identity   string  `json:"identity,omitempty"` // "token:<id>" or "cert:<CN>"; empty when unauthenticated
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Endpoint   string  `json:"endpoint"`
	Status     int     `json:"status"`
	Result     string  `json:"result"`           // "success", "denied", or "error"
	Reason     string  `json:"reason,omitempty"` // why it was denied, or the error code
	DryRun     bool    `json:"dry_run,omitempty"`
	DurationMS float64 `json:"duration_ms"`
	TraceID    string  `json:"trace_id,omitempty"`
}

// auditLog writes audit records as JSON lines, to a dedicated file or,
// without one, to the process log behind an "admin-audit: " prefix.
type auditLog struct {
	mu     sync.Mutex
	file   io.WriteCloser // nil when logging to logger
	logger *log.Logger
}

func newAuditLog(path string, logger *log.Logger) (*auditLog, error) {
	if path == "" {
		return &auditLog{logger: logger}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLog{file: f}, nil
}

func (a *auditLog) write(rec auditRecord) {
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if a.file == nil {
		a.logger.Printf("admin-audit: %s", line)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.file.Write(append(line, '\n'))
}

func (a *auditLog) Close() error {
	if a.file == nil {
		return nil
	}
	return a.file.Close()
}

// auditPath is the request path as it goes in the audit log. A rate
// limit client segment is kept only in a form that can't be a secret —
// an API key fingerprint ("key:..."), a JWT or certificate identity, or
// an IP address — so a raw API key pasted into the URL by mistake is
// never written to the log. Paths that matched no endpoint are cut
// short.
func auditPath(path string, matched bool) string {
	const prefix = "/admin/v1/ratelimits/"
	if rest, ok := strings.CutPrefix(path, prefix); ok {
		client, tail, _ := strings.Cut(rest, "/")
		if !safeClientLabel(client) {
			client = "[redacted]"
		}
		if tail != "" {
			tail = "/" + tail
		}
		return prefix + client + tail
	}
	if !matched && len(path) > 100 {
		return path[:100] + "..."
	}
	return path
}

// safeClientLabel reports whether a client identifier is in one of the
// forms Gatekeeper itself puts in metrics and logs.
func safeClientLabel(s string) bool {
	for _, p := range []string{"key:", "jwt:", "mtls:"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func auditTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
