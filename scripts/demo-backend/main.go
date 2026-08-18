// Command demo-backend is a trivial HTTP server used only for local
// demos: it stands in for a "real" backend service so Gatekeeper has
// something to proxy requests to without any external dependencies.
package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong from demo backend: " + r.URL.Path))
	})

	log.Println("demo-backend: listening on :9000")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
