// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// guardiand is the Path A sidecar daemon: it answers Angie's auth_request
// subrequests and serves the challenge/denied pages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	httptransport "github.com/melroy89/angie-guardian/transport/http"
)

var version = "dev" // set via -ldflags "-X main.version=..."

func main() {
	configPath := flag.String("config", "", "path to guardian.yaml (required)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("guardiand", version)
		return
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: guardiand -config /etc/guardian/guardian.yaml")
		os.Exit(2)
	}
	if err := run(*configPath); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		return err
	}

	levels := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo,
		"warn": slog.LevelWarn, "error": slog.LevelError,
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levels[cfg.LogLevel]}))
	slog.SetDefault(log)

	var st store.Store
	switch cfg.Store.Backend {
	case "memory":
		st = store.NewMemory()
	case "bbolt":
		st, err = store.NewBolt(cfg.Store.Path)
		if err != nil {
			return fmt.Errorf("open bbolt store %s: %w", cfg.Store.Path, err)
		}
	case "redis":
		password := cfg.Store.Password
		if password == "" {
			password = os.Getenv("REDIS_PASSWORD")
		}
		st, err = store.NewRedis(store.RedisOptions{Addr: cfg.Store.Addr, Password: password, DB: cfg.Store.DB})
		if err != nil {
			return fmt.Errorf("connect redis store %s: %w", cfg.Store.Addr, err)
		}
	}

	m := metrics.New()
	st = store.Instrument(st, m)
	defer st.Close()

	var powMgr *pow.Manager
	if cfg.SigningKeyFile != "" {
		key, err := pow.LoadOrCreateKey(cfg.SigningKeyFile)
		if err != nil {
			return fmt.Errorf("signing key %s: %w", cfg.SigningKeyFile, err)
		}
		previous, err := pow.LoadPreviousKeys(cfg.PreviousKeyDir)
		if err != nil {
			return fmt.Errorf("previous keys %s: %w", cfg.PreviousKeyDir, err)
		}
		powMgr = pow.NewManagerWithKeys(key, previous, st)
		if len(previous) > 0 {
			log.Info("loaded retired signing keys for verification", "count", len(previous))
		}
	} else {
		log.Warn("no signing_key_file configured: proof-of-work challenges are disabled")
	}

	engine, err := core.NewEngine(cfg, st, powMgr, log)
	if err != nil {
		return err
	}
	engine.SetMetrics(m)
	defer engine.Close()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           httptransport.New(engine, cfg, powMgr, st, m, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second, // keep Angie's keepalive conns warm
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("guardiand listening", "addr", cfg.Listen, "store", cfg.Store.Backend, "version", version)
		errCh <- srv.ListenAndServe()
	}()

	// Admin + metrics server on its own listener (loopback / management iface).
	var admin *http.Server
	if cfg.Admin.Listen != "" {
		if cfg.Admin.Token == "" && !isLoopback(cfg.Admin.Listen) {
			return fmt.Errorf("admin.listen %s is not loopback but no admin.token is set; refusing to expose an unauthenticated admin API", cfg.Admin.Listen)
		}
		admin = &http.Server{
			Addr: cfg.Admin.Listen,
			Handler: httptransport.NewAdminServer(engine, cfg, m,
				cfg.Admin.Token, cfg.SigningKeyFile, cfg.PreviousKeyDir, log),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("admin+metrics listening", "addr", cfg.Admin.Listen, "authenticated", cfg.Admin.Token != "")
			errCh <- admin.ListenAndServe()
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if admin != nil {
		_ = admin.Shutdown(ctx)
	}
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

// isLoopback reports whether a listen address binds only to the loopback
// interface, so an admin API without a token there is not remotely reachable.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
