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
package main

import (
	"context"
	"flag"
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
)

// redisHealthCheckInterval controls how often FallbackStore re-probes a
// down Redis backend to see if it has recovered.
const redisHealthCheckInterval = 5 * time.Second

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to YAML config file")
	enableDashboard := flag.Bool("dashboard", false, "serve an interactive HTML dashboard at /_dashboard for local testing/demos")
	flag.Parse()

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

	srv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout.Duration,
		WriteTimeout: cfg.Server.WriteTimeout.Duration,
		IdleTimeout:  cfg.Server.IdleTimeout.Duration,
	}

	go func() {
		log.Printf("gatekeeper: listening on %s (algorithm=%s scope=%s backend=%s)",
			cfg.Server.ListenAddr, cfg.RateLimit.Algorithm, cfg.RateLimit.Scope, cfg.Storage.Backend)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("gatekeeper: server error: %v", err)
		}
	}()

	// SIGHUP triggers an in-place config reload. server.*, storage.*, and
	// metrics.* are read only at startup; everything else swaps live.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Println("gatekeeper: SIGHUP received, reloading config")
			if err := gw.Reload(); err != nil {
				log.Printf("gatekeeper: config reload failed, keeping previous config: %v", err)
				continue
			}
			c := gw.Config()
			log.Printf("gatekeeper: config reloaded (algorithm=%s scope=%s routes=%d)",
				c.RateLimit.Algorithm, c.RateLimit.Scope, len(c.Routes))
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("gatekeeper: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("gatekeeper: shutdown error: %v", err)
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
