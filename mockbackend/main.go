// Command mockbackend is a minimal HTTP server used as a stand-in
// upstream service in docker-compose.yml, so Gatekeeper has something
// real to proxy requests to when testing the gateway end-to-end.
//
// It has no dependency on the rest of the Gatekeeper codebase and lives
// in its own Go module for that reason.
//
// /ws/echo is a minimal WebSocket echo endpoint for trying out
// Gatekeeper's WebSocket proxying end to end; everything else gets the
// JSON echo below.
//
// For load-balancing demos, several instances can run side by side
// (docker-compose.lb.yml). Each reports its INSTANCE_NAME (default: the
// hostname), serves /health for active health checks, and can be told to
// misbehave:
//
//	POST /_admin/fail     every request (including /health) answers 503
//	POST /_admin/slow?delay=2s   every request waits that long first
//	POST /_admin/recover  back to normal
//	GET  /_admin/status   current mode
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// mode is how this instance currently behaves; see /_admin/*.
var mode = struct {
	sync.Mutex
	failing bool
	delay   time.Duration
}{}

var instance = func() string {
	if name := os.Getenv("INSTANCE_NAME"); name != "" {
		return name
	}
	host, _ := os.Hostname()
	return host
}()

// misbehave applies the current failure mode; it reports whether the
// request has already been answered.
func misbehave(w http.ResponseWriter) bool {
	mode.Lock()
	failing, delay := mode.failing, mode.delay
	mode.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if failing {
		http.Error(w, "mock-backend "+instance+" is failing (POST /_admin/recover to fix)", http.StatusServiceUnavailable)
		return true
	}
	return false
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if misbehave(w) {
		return
	}
	_, _ = io.WriteString(w, "ok "+instance+"\n")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/_admin/")
	if action != "status" && r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	mode.Lock()
	switch action {
	case "fail":
		mode.failing = true
	case "slow":
		d, err := time.ParseDuration(r.URL.Query().Get("delay"))
		if err != nil || d < 0 {
			mode.Unlock()
			http.Error(w, "delay must be a duration like 2s", http.StatusBadRequest)
			return
		}
		mode.delay = d
	case "recover":
		mode.failing, mode.delay = false, 0
	case "status":
	default:
		mode.Unlock()
		http.NotFound(w, r)
		return
	}
	failing, delay := mode.failing, mode.delay
	mode.Unlock()
	if action != "status" {
		log.Printf("mock-backend %s: %s (failing=%t delay=%s)", instance, action, failing, delay)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"instance": instance, "failing": failing, "delay": delay.String()})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	http.HandleFunc("/", handle)
	http.HandleFunc("/ws/echo", handleWebSocketEcho)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/_admin/", handleAdmin)

	addr := ":" + port
	log.Printf("mock-backend %s: listening on %s", instance, addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("mock-backend: %v", err)
	}
}

// handle echoes back the request it received as JSON, so callers can see
// that Gatekeeper actually reached this service (method, path, and the
// headers Gatekeeper forwarded). The W3C trace context Gatekeeper
// propagated is also pulled out into its own fields and logged, so it's
// easy to match a request to its trace.
func handle(w http.ResponseWriter, r *http.Request) {
	if misbehave(w) {
		return
	}
	resp := struct {
		Message     string      `json:"message"`
		Instance    string      `json:"instance"`
		Method      string      `json:"method"`
		Path        string      `json:"path"`
		Host        string      `json:"host"`
		Traceparent string      `json:"traceparent,omitempty"`
		Tracestate  string      `json:"tracestate,omitempty"`
		Baggage     string      `json:"baggage,omitempty"`
		Headers     http.Header `json:"headers"`
		Timestamp   string      `json:"timestamp"`
	}{
		Message:     "hello from mock-backend",
		Instance:    instance,
		Method:      r.Method,
		Path:        r.URL.Path,
		Host:        r.Host,
		Traceparent: r.Header.Get("Traceparent"),
		Tracestate:  r.Header.Get("Tracestate"),
		Baggage:     r.Header.Get("Baggage"),
		Headers:     r.Header,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	if resp.Traceparent != "" {
		log.Printf("mock-backend: %s %s traceparent=%s", r.Method, r.URL.Path, resp.Traceparent)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("mock-backend: encode response: %v", err)
	}
}

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// handleWebSocketEcho upgrades the request to a WebSocket and echoes every
// text/binary message back, answers pings with pongs, and completes the
// closing handshake. It handles one unfragmented frame at a time, which is
// all a demo client sends; it's a test fixture, not a general server.
func handleWebSocketEcho(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "expected a WebSocket upgrade request", http.StatusBadRequest)
		return
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		log.Printf("mock-backend: websocket hijack: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	sum := sha1.Sum([]byte(key + websocketGUID))
	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	if err := brw.Flush(); err != nil {
		return
	}
	log.Printf("mock-backend: websocket connected on %s", r.URL.Path)

	for {
		opcode, payload, err := readFrame(brw.Reader)
		if err != nil {
			log.Printf("mock-backend: websocket closed: %v", err)
			return
		}
		switch opcode {
		case 0x1, 0x2: // text, binary
			if err := writeFrame(conn, opcode, payload); err != nil {
				return
			}
		case 0x9: // ping
			_ = writeFrame(conn, 0xA, payload)
		case 0x8: // close
			_ = writeFrame(conn, 0x8, payload)
			log.Printf("mock-backend: websocket closed by peer")
			return
		}
	}
}

// readFrame reads one client frame and returns its unmasked payload.
func readFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	length := uint64(h[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > 1<<20 {
		return 0, nil, io.ErrShortBuffer
	}
	var mask [4]byte
	if h[1]&0x80 != 0 {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return h[0] & 0x0f, payload, nil
}

// writeFrame writes one unmasked server frame.
func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode, 0}
	switch n := len(payload); {
	case n <= 125:
		header[1] = byte(n)
	case n <= 0xFFFF:
		header[1] = 126
		header = binary.BigEndian.AppendUint16(header, uint16(n))
	default:
		header[1] = 127
		header = binary.BigEndian.AppendUint64(header, uint64(n))
	}
	_, err := w.Write(append(header, payload...))
	return err
}
