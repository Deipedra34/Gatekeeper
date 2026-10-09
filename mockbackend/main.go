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
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	http.HandleFunc("/", handle)
	http.HandleFunc("/ws/echo", handleWebSocketEcho)

	addr := ":" + port
	log.Printf("mock-backend: listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("mock-backend: %v", err)
	}
}

// handle echoes back the request it received as JSON, so callers can see
// that Gatekeeper actually reached this service (method, path, and the
// headers Gatekeeper forwarded).
func handle(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		Message   string      `json:"message"`
		Method    string      `json:"method"`
		Path      string      `json:"path"`
		Host      string      `json:"host"`
		Headers   http.Header `json:"headers"`
		Timestamp string      `json:"timestamp"`
	}{
		Message:   "hello from mock-backend",
		Method:    r.Method,
		Path:      r.URL.Path,
		Host:      r.Host,
		Headers:   r.Header,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
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
