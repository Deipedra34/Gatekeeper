package main

import (
	"log"

	"gatekeeper/internal/admin"
	"gatekeeper/internal/config"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
)

// startAdmin starts the admin API on its own listener when cfg enables
// it, and returns nil — opening no port at all — when it doesn't. The
// listener is opened before returning, so a port clash or a broken admin
// TLS setup fails startup instead of surfacing later.
func startAdmin(cfg *config.Config, gw *gateway.Gateway, reload func() error, m *metrics.Metrics) (*admin.Server, error) {
	if !cfg.Admin.Enabled {
		return nil, nil
	}
	srv, err := admin.New(admin.Options{Config: cfg.Admin, Gateway: gw, Reload: reload, Metrics: m, Logger: log.Default()})
	if err != nil {
		return nil, err
	}
	ln, err := srv.Listen()
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if srv.TLSEnabled() {
		scheme = "https"
	}
	log.Printf("gatekeeper: admin API listening on %s (%s)", ln.Addr(), scheme)
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("gatekeeper: admin API server stopped: %v", err)
		}
	}()
	return srv, nil
}
