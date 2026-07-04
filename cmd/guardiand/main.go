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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/melroy89/angie-guardian/core"
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
	}
	defer st.Close()

	var powMgr *pow.Manager
	if cfg.SigningKeyFile != "" {
		key, err := pow.LoadOrCreateKey(cfg.SigningKeyFile)
		if err != nil {
			return fmt.Errorf("signing key %s: %w", cfg.SigningKeyFile, err)
		}
		powMgr = pow.NewManager(key, st)
	} else {
		log.Warn("no signing_key_file configured: proof-of-work challenges are disabled")
	}

	engine := core.NewEngine(cfg, st, powMgr, log)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           httptransport.New(engine, cfg, powMgr, st, log),
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
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
