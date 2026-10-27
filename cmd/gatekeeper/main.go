// Command gatekeeper starts the Gatekeeper API gateway: it loads a YAML
// config file, wires up the configured storage backend and rate-limit
// algorithm, and serves the reverse proxy and Prometheus metrics
// endpoint until it receives a shutdown signal.
//
// Sending the process SIGHUP re-reads the same config file and swaps the
// new routes, rate-limit rules, client tiers, algorithm, auth, and CORS
// settings into the running gateway without dropping in-flight requests.
// An invalid new config is logged and ignored; the gateway keeps running
// on the previous one.
//
// With tls.enabled the gateway serves HTTPS (optionally verifying client
// certificates), and SIGHUP also reloads the server certificate and key;
// they're additionally reloaded whenever their files change on disk.
//
// On SIGINT/SIGTERM the server stops accepting connections, finishes
// in-flight requests, and closes proxied WebSocket connections with a
// Close frame, all within a 10s shutdown window, then flushes any
// buffered trace spans (up to 5s more).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/dashboard"
	"gatekeeper/internal/gateway"
	"gatekeeper/internal/metrics"
	"gatekeeper/internal/ratelimiter/store"
	"gatekeeper/internal/server"
	"gatekeeper/internal/version"
)

// redisHealthCheckInterval controls how often FallbackStore re-probes a
// down Redis backend to see if it has recovered.
const redisHealthCheckInterval = 5 * time.Second

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to YAML config file")
	enableDashboard := flag.Bool("dashboard", false, "serve an interactive HTML dashboard at /_dashboard for local testing/demos")
	showVersion := flag.Bool("version", false, "print version, commit, build date and Go version, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("gatekeeper: %v", err)
	}

	st := buildStore(cfg)
	defer st.Close()

	m := metrics.New()

	gw, err := gateway.New(cfg, *configPath, st, m, log.Default())
	if err != nil {
		log.Fatalf("gatekeeper: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", gw)
	if cfg.Metrics.Enabled {
		mux.Handle(cfg.Metrics.Path, m.Handler())
	}
	if *enableDashboard {
		mux.HandleFunc("/_dashboard", dashboard.Handler)
		log.Printf("gatekeeper: dashboard enabled at /_dashboard")
	}

	srv, err := server.New(cfg, mux, m, log.Default())
	if err != nil {
		log.Fatalf("gatekeeper: %v", err)
	}

	go func() {
		scheme := "http"
		if srv.TLSEnabled() {
			scheme = fmt.Sprintf("https, min TLS %s, client_auth=%s", cfg.TLS.MinVersion, cfg.TLS.ClientAuth)
		}
		log.Printf("gatekeeper: listening on %s (%s; algorithm=%s scope=%s backend=%s)",
			cfg.Server.ListenAddr, scheme, cfg.RateLimit.Algorithm, cfg.RateLimit.Scope, cfg.Storage.Backend)
		if cfg.TLS.Enabled && cfg.TLS.RedirectHTTPPort != 0 {
			log.Printf("gatekeeper: redirecting plain HTTP on port %d to HTTPS", cfg.TLS.RedirectHTTPPort)
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("gatekeeper: server error: %v", err)
		}
	}()

	// SIGHUP triggers an in-place config reload, plus a reload of the TLS
	// certificate. server.*, storage.*, metrics.*, and tls.* (other than
	// the certificate itself) are read only at startup; everything else
	// swaps live.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Println("gatekeeper: SIGHUP received, reloading config")
			certFile, keyFile := "", ""
			if err := gw.Reload(); err != nil {
				log.Printf("gatekeeper: config reload failed, keeping previous config: %v", err)
			} else {
				c := gw.Config()
				log.Printf("gatekeeper: config reloaded (algorithm=%s scope=%s routes=%d)",
					c.RateLimit.Algorithm, c.RateLimit.Scope, len(c.Routes))
				if c.TLS.Enabled {
					certFile, keyFile = c.TLS.CertFile, c.TLS.KeyFile
				}
			}
			// Logged by the reloader; a failure keeps the old certificate.
			_ = srv.ReloadCertificates(certFile, keyFile)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("gatekeeper: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Upgraded WebSocket connections are hijacked, so srv.Shutdown
	// neither waits for nor closes them; the gateway does that itself,
	// alongside draining ordinary requests.
	wsDone := make(chan error, 1)
	go func() { wsDone <- gw.ShutdownWebSockets(shutdownCtx) }()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("gatekeeper: shutdown error: %v", err)
	}
	if err := <-wsDone; err != nil {
		log.Printf("gatekeeper: websocket connections did not close in time and were dropped: %v", err)
	}
	gw.Close() // stop backend health checks

	// Last, once no more requests can start: flush buffered spans to the
	// collector. A dead collector costs at most this timeout, not a hang.
	tracingCtx, cancelTracing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTracing()
	if err := gw.ShutdownTracing(tracingCtx); err != nil {
		log.Printf("gatekeeper: flushing traces on shutdown: %v", err)
	}
}

// buildStore builds the rate-limit storage backend from config. For
// "redis" it checks connectivity up front and wraps the Redis store in a
// FallbackStore, so an unreachable Redis — whether that's at startup or
// partway through a run — just degrades to in-memory limiting with a
// logged warning instead of taking the gateway down.
func buildStore(cfg *config.Config) store.Store {
	if cfg.Storage.Backend != "redis" {
		return store.NewMemoryStore()
	}

	redisStore := store.NewRedisStore(
		cfg.Storage.Redis.Addr,
		cfg.Storage.Redis.Password,
		cfg.Storage.Redis.DB,
		cfg.Storage.Redis.DialTimeout.Duration,
	)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Storage.Redis.DialTimeout.Duration)
	defer cancel()
	if err := redisStore.Ping(ctx); err != nil {
		log.Printf("gatekeeper: WARNING: redis unreachable at %s (%v); starting in in-memory fallback mode", cfg.Storage.Redis.Addr, err)
	} else {
		log.Printf("gatekeeper: using redis store at %s", cfg.Storage.Redis.Addr)
	}

	return store.NewFallbackStore(redisStore, store.NewMemoryStore(), redisHealthCheckInterval, log.Default())
}
