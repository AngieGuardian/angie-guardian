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
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	httptransport "github.com/melroy89/angie-guardian/transport/http"
)

var version = "dev" // set via -ldflags "-X main.version=..."

func main() {
	configPath := flag.String("config", "", "path to guardian.yaml (required)")
	testConfig := flag.Bool("t", false, "test the config: load and validate it, then exit (0 = ok, 1 = error)")
	healthcheck := flag.Bool("healthcheck", false, "probe every configured Guardian listener, then exit")
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
	if *healthcheck {
		if err := checkHealth(*configPath, 1500*time.Millisecond); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *testConfig {
		cfg, err := core.LoadConfig(*configPath)
		if err == nil {
			err = core.ValidateConfigArtifacts(cfg, slog.Default())
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "config %s: FAILED\n%v\n", *configPath, err)
			os.Exit(1)
		}
		fmt.Printf("config %s: ok\n", *configPath)
		return
	}
	if err := run(*configPath); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func checkHealth(configPath string, timeout time.Duration) error {
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return waitListening(context.Background(), cfg, timeout)
}

func run(configPath string) error {
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		return err
	}
	runningStatic := staticConfigFrom(cfg)

	levels := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo,
		"warn": slog.LevelWarn, "error": slog.LevelError,
	}
	// The level lives in a LevelVar so a config reload can adjust it without
	// rebuilding the handler mid-flight.
	level := new(slog.LevelVar)
	level.Set(levels[cfg.LogLevel])
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	var st store.Store
	switch cfg.Store.Backend {
	case "memory":
		st = store.NewMemory()
	case "buntdb":
		st, err = store.NewBuntDB(cfg.Store.Path, store.BuntDBOptions{Sync: cfg.Store.Sync})
		if err != nil {
			return fmt.Errorf("open buntdb store %s: %w", cfg.Store.Path, err)
		}
	case "pebble":
		st, err = store.NewPebble(cfg.Store.Path, store.PebbleOptions{Sync: cfg.Store.Sync})
		if err != nil {
			return fmt.Errorf("open pebble store %s: %w", cfg.Store.Path, err)
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
	// The attack-mode detector observes every store op (latency + errors) for
	// its store-degradation signal, so it must wrap the store alongside the
	// metrics recorder. Constructed before the engine so its posture is live
	// from the first request.
	detector := attackmode.New(cfg.AttackModeSettings(), st, log)
	detector.OnTransition(func(from, to attackmode.Level, reason string) {
		m.AttackTransition(to.String(), reason)
	})
	detector.OnTick(func(level attackmode.Level, extraBits int, sig attackmode.Signals) {
		m.AttackMode(int(level), extraBits)
		m.AttackSignal("challenge_rate", sig.ChallengeRate)
		m.AttackSignal("request_rate", sig.RequestRate)
		m.AttackSignal("solve_ratio", sig.SolveRatio)
		m.AttackSignal("store_error_ratio", sig.StoreErrorRatio)
		m.AttackSignal("store_slow_ratio", sig.StoreSlowRatio)
	})
	st = store.Instrument(st, m, detector)
	defer st.Close()

	var powMgr *pow.Manager
	if cfg.SigningKeyFile != "" {
		powMgr, err = pow.NewManagerFromFiles(cfg.SigningKeyFile, cfg.PreviousKeyDir, st)
		if err != nil {
			return fmt.Errorf("signing keys: %w", err)
		}
		previous, err := pow.LoadPreviousKeys(cfg.PreviousKeyDir)
		if err != nil {
			return fmt.Errorf("previous keys %s: %w", cfg.PreviousKeyDir, err)
		}
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

	// Enforcement offload: the in-process block mirror (always on) and the
	// optional nftables sink. Sink failures degrade to in-daemon enforcement
	// and are never fatal.
	enforcer := enforce.New(cfg.EnforceConfig(), st, m, log)
	engine.SetEnforcer(enforcer)
	enforcer.Start(context.Background())
	defer enforcer.Close()

	// Global attack posture: the detector aggregates hot-path signals and
	// raises PoW difficulty fleet-wide under attack. nil-safe; disabled unless
	// attack_mode.enabled.
	engine.SetAttackDetector(detector)
	detector.Start(context.Background())
	defer detector.Close()

	// reload re-reads guardian.yaml and hot-swaps everything derived from it
	// (domains, lists, thresholds, rule/model/geoip/feed sources, log level).
	// Triggered by SIGHUP and POST /admin/reload. A config that fails to load
	// or validate leaves the running config active. Listener addresses, the
	// store, signing keys and the admin token are fixed at startup.
	var reloadMu sync.Mutex
	reload := func() error {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		next, err := core.LoadConfig(configPath)
		if err != nil {
			return err
		}
		if changed := staticConfigChanges(runningStatic, next); len(changed) > 0 {
			return fmt.Errorf("config changes require a restart: %s", strings.Join(changed, ", "))
		}
		if err := engine.Reload(next); err != nil {
			return err
		}
		level.Set(levels[next.LogLevel])
		return nil
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           httptransport.New(engine, powMgr, st, m, log),
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
		// Establish the bearer token: explicit admin.token (or ADMIN_TOKEN)
		// wins; otherwise load-or-create the persistent token_file; otherwise
		// mint an ephemeral token for this run. Only a loopback bind may fall
		// through to the ephemeral token: exposing the API beyond the box
		// requires a token the operator configured deliberately.
		switch {
		case cfg.Admin.Token != "":
		case cfg.Admin.TokenFile != "":
			token, err := core.LoadOrCreateAdminToken(cfg.Admin.TokenFile)
			if err != nil {
				return fmt.Errorf("admin token %s: %w", cfg.Admin.TokenFile, err)
			}
			cfg.Admin.Token = token
			log.Info("admin token loaded", "file", cfg.Admin.TokenFile)
		case isLoopback(cfg.Admin.Listen):
			token, err := core.GenerateAdminToken()
			if err != nil {
				return err
			}
			cfg.Admin.Token = token
			log.Info("admin token generated for this run (set admin.token_file to persist one)",
				"token", token)
		default:
			return fmt.Errorf("admin.listen %s is not loopback but no admin.token or admin.token_file is set; refusing to expose an unauthenticated admin API", cfg.Admin.Listen)
		}

		admin = &http.Server{
			Addr: cfg.Admin.Listen,
			Handler: httptransport.NewAdminServer(engine, cfg, m,
				cfg.Admin.Token, cfg.SigningKeyFile, cfg.PreviousKeyDir, reload, log),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			log.Info("admin+metrics listening", "addr", cfg.Admin.Listen)
			if cfg.Admin.Dashboard {
				// Never put configured or persistent bearer credentials in
				// process logs. The dashboard prompts for the token and stores
				// it only in this browser tab's sessionStorage.
				log.Info("admin dashboard ready",
					"url", adminDashboardURL(cfg.Admin.Listen))
			}
			errCh <- admin.ListenAndServe()
		}()
	}

	// systemd readiness + watchdog (sd_notify). All no-ops unless the unit is
	// Type=notify and sets $NOTIFY_SOCKET, so this is safe to always run.
	// Signal READY=1 only once both listeners actually answer /healthz, so
	// "active" in systemd means "serving", not merely "process started".
	sd := newNotifier()
	defer sd.Close()
	if sd != nil {
		wdCtx, wdCancel := context.WithCancel(context.Background())
		defer wdCancel()
		go func() {
			if err := signalReadyWhenListening(wdCtx, cfg, 30*time.Second, sd.Ready); err != nil {
				log.Error("readiness probe did not confirm listeners; not signalling ready", "err", err)
				return
			}
			log.Info("systemd notified ready")
			sd.startWatchdog(wdCtx, log)
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
loop:
	for {
		select {
		case err := <-errCh:
			return err
		case sig := <-stop:
			if sig == syscall.SIGHUP {
				if err := reload(); err != nil {
					log.Error("config reload failed, keeping running config", "err", err)
				} else {
					log.Info("config reloaded", "config", configPath)
				}
				continue
			}
			log.Info("shutting down", "signal", sig.String())
			sd.Stopping() // tell systemd a graceful drain is not a hang
			break loop
		}
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

type staticConfig struct {
	listen, signingKeyFile, previousKeyDir string
	trustedProxy                           bool
	admin                                  core.AdminConfig
	store                                  core.StoreConfig
	enforcement                            core.EnforcementConfig
}

func staticConfigFrom(cfg *core.Config) staticConfig {
	return staticConfig{
		listen: cfg.Listen, trustedProxy: cfg.TrustedProxy,
		signingKeyFile: cfg.SigningKeyFile, previousKeyDir: cfg.PreviousKeyDir,
		admin: cfg.Admin, store: cfg.Store, enforcement: cfg.Enforcement,
	}
}

// staticConfigChanges reports reload edits that cannot be applied to the
// already-open listeners, store, key manager or admin server. Rejecting the
// reload keeps Engine.Config an honest view of the running process.
func staticConfigChanges(running staticConfig, next *core.Config) []string {
	var changed []string
	add := func(name string, different bool) {
		if different {
			changed = append(changed, name)
		}
	}
	add("listen", running.listen != next.Listen)
	add("trusted_proxy", running.trustedProxy != next.TrustedProxy)
	add("signing_key_file", running.signingKeyFile != next.SigningKeyFile)
	add("previous_key_dir", running.previousKeyDir != next.PreviousKeyDir)
	add("admin.listen", running.admin.Listen != next.Admin.Listen)
	add("admin.token", running.admin.Token != next.Admin.Token)
	add("admin.token_file", running.admin.TokenFile != next.Admin.TokenFile)
	add("admin.dashboard", running.admin.Dashboard != next.Admin.Dashboard)
	add("admin.angie_api", running.admin.AngieAPI != next.Admin.AngieAPI)
	add("store.backend", running.store.Backend != next.Store.Backend)
	add("store.path", running.store.Path != next.Store.Path)
	add("store.addr", running.store.Addr != next.Store.Addr)
	add("store.password", running.store.Password != next.Store.Password)
	add("store.db", running.store.DB != next.Store.DB)
	// The mirror seed and any netlink/table setup happen at startup, so the
	// whole section is compared as one unit.
	add("enforcement", !reflect.DeepEqual(running.enforcement, next.Enforcement))
	slices.Sort(changed)
	return changed
}

// displayAddr turns a listen address into one a browser on this box can open:
// a wildcard bind (0.0.0.0, ::, or an empty host) becomes 127.0.0.1.
func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "::" {
		return net.JoinHostPort("::1", port)
	}
	if host == "" || host == "0.0.0.0" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

func adminDashboardURL(listen string) string {
	return fmt.Sprintf("http://%s/admin/dashboard", displayAddr(listen))
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
