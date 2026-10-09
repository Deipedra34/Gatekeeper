// Command wsclient is a tiny WebSocket client for trying out Gatekeeper's
// WebSocket proxying without installing anything: it connects through
// the gateway, sends each -message (or each line of stdin), prints what
// comes back, and closes the connection cleanly.
//
//	go run ./scripts/wsclient -url ws://localhost:8080/ws/echo -api-key demo-free-key -message hello
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"gatekeeper/internal/websocket/wstest"
)

type messages []string

func (m *messages) String() string     { return fmt.Sprint(*m) }
func (m *messages) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	url := flag.String("url", "ws://localhost:8080/ws/echo", "WebSocket URL to connect to (through the gateway)")
	apiKey := flag.String("api-key", "", "value for the X-API-Key header")
	token := flag.String("token", "", "JWT to send as Authorization: Bearer")
	origin := flag.String("origin", "", "Origin header to send")
	var msgs messages
	flag.Var(&msgs, "message", "message to send (repeatable); reads lines from stdin if none given")
	flag.Parse()

	header := http.Header{}
	if *apiKey != "" {
		header.Set("X-API-Key", *apiKey)
	}
	if *token != "" {
		header.Set("Authorization", "Bearer "+*token)
	}
	if *origin != "" {
		header.Set("Origin", *origin)
	}

	conn, resp, err := wstest.Dial(*url, header)
	if err != nil {
		if resp != nil {
			fmt.Fprintf(os.Stderr, "handshake refused: %s: %s", resp.Status, wstest.ResponseBody(resp))
		} else {
			fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		}
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("connected (%s, X-RateLimit-Remaining: %s)\n", resp.Status, resp.Header.Get("X-Ratelimit-Remaining"))

	send := func(msg string) bool {
		if err := conn.WriteText(msg); err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
			return false
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		op, payload, err := conn.ReadMessage()
		if err != nil {
			fmt.Fprintf(os.Stderr, "receive: %v\n", err)
			return false
		}
		if op == wstest.OpClose {
			code, reason := wstest.CloseCode(payload)
			fmt.Printf("server closed the connection: %d %s\n", code, reason)
			return false
		}
		fmt.Printf("< %s\n", payload)
		return true
	}

	if len(msgs) > 0 {
		for _, m := range msgs {
			if !send(m) {
				return
			}
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if !send(scanner.Text()) {
				return
			}
		}
	}

	_ = conn.WriteClose(1000, "bye")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if op, payload, err := conn.ReadMessage(); err == nil && op == wstest.OpClose {
		code, _ := wstest.CloseCode(payload)
		fmt.Printf("closed cleanly (%d)\n", code)
	}
}
