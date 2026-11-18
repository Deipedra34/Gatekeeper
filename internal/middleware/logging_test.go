package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func logLine(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	var buf bytes.Buffer
	handler := RequestLogger(log.New(&buf, "", 0))(h)
	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.RemoteAddr = "203.0.113.7:4000"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return strings.TrimSpace(buf.String())
}

func TestRequestLogger_AddsTheVariant(t *testing.T) {
	line := logLine(t, func(w http.ResponseWriter, r *http.Request) {
		NoteVariant(r.Context(), "canary")
		w.WriteHeader(http.StatusAccepted)
	})
	assert.True(t, strings.HasPrefix(line, "GET /api/items 202 "), line)
	assert.True(t, strings.HasSuffix(line, " 203.0.113.7:4000 variant=canary"), line)
}

func TestRequestLogger_LineUnchangedWithoutAVariant(t *testing.T) {
	line := logLine(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.NotContains(t, line, "variant=")
	fields := strings.Fields(line)
	assert.Len(t, fields, 5, "method, path, status, duration, address: as before")
	assert.Equal(t, "203.0.113.7:4000", fields[4])
}

func TestNoteVariant_WithoutTheLoggerIsHarmless(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	NoteVariant(req.Context(), "canary") // must not panic
}
