// Command mockbackend is a minimal HTTP server used as a stand-in
// upstream service in docker-compose.yml, so Gatekeeper has something
// real to proxy requests to when testing the gateway end-to-end.
//
// It has no dependency on the rest of the Gatekeeper codebase and lives
// in its own Go module for that reason.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	http.HandleFunc("/", handle)

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
