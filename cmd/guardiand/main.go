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
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/health"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	httptransport "github.com/melroy89/angie-guardian/transport/http"
)

var version = "dev" // set via -ldflags "-X main.version=..."

const (
	// defaultConfigPath is where the packaging installs guardian.yaml.
	defaultConfigPath = "/etc/guardian/guardian.yaml"

	// Guardian's listeners receive a small, fixed protocol from Angie or an
	// operator. Keep enough room for normal proxy metadata while bounding the
	// parser work from repeated header lines well below net/http's default 500.
	maxHeaderValueCount = 64
)

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:                addr,
		Handler:             handler,
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         120 * time.Second, // keep Angie's keepalive conns warm
		MaxHeaderValueCount: maxHeaderValueCount,
	}
}

// resolveConfigPath returns the installed configuration path when -config is
// omitted. Passing -config remains available for foreground evaluations,
// tests, and non-standard installations.
func resolveConfigPath(configPath string) string {
	if configPath != "" {
		return configPath
	}
	return defaultConfigPath
}

func main() {
	configPath := flag.String("config", "", "path to guardian.yaml (default "+defaultConfigPath+")")
	testConfig := flag.Bool("t", false, "test the config: load and validate it, then exit (0 = ok, 1 = error)")
	healthcheck := flag.Bool("healthcheck", false, "probe every configured Guardian listener, then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	profileDir := flag.String("profile-dir", "", "write opt-in runtime and Pebble profiles to this empty directory")
	flag.Parse()

	if *showVersion {
		fmt.Println("guardiand", version)
		return
	}
	cfgPath := resolveConfigPath(*configPath)
	if *healthcheck {
		if err := checkHealth(cfgPath, 1500*time.Millisecond); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *testConfig {
		cfg, err := core.LoadConfig(cfgPath)
		if err == nil {
			err = core.ValidateConfigArtifacts(cfg, slog.Default())
		}
		if err != nil {
			// cfgPath, not *configPath: the operator may have used the default,
			// so the message has to name the file that was tried.
			fmt.Fprintf(os.Stderr, "config %s: FAILED\n%v\n", cfgPath, err)
			os.Exit(1)
		}
		for _, wmsg := range cfg.Warnings() {
			fmt.Fprintf(os.Stderr, "config %s: warning: %s\n", cfgPath, wmsg)
		}
		fmt.Printf("config %s: ok\n", cfgPath)
		return
	}
	if err := run(cfgPath, *profileDir); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func checkHealth(configPath string, timeout time.Duration) error {
	// Only the listen addresses are needed, extracted leniently: a probe of a
	// healthy running daemon must not fail just because the on-disk config was
	// edited into an invalid state (that would crash-loop the service, an
	// availability own-goal for a fail-open product).
	listen, socket, adminListen, err := core.ListenAddrs(configPath)
	if err != nil {
		return fmt.Errorf("read listen addresses: %w", err)
	}
	return waitListening(context.Background(), listen, socket, adminListen, timeout)
}

// openGuardListeners opens the configured auth endpoints before either starts
// serving. A Unix socket is created by the daemon (and therefore owned by the
// service user/group) and tightened to the configured mode before Angie can
// connect. An active socket is never displaced; only an orphan that refuses
// connections is removed after an unclean shutdown.
func openGuardListeners(tcpAddr, socketPath, socketMode string) (listeners []net.Listener, err error) {
	defer func() {
		if err != nil {
			for _, listener := range listeners {
				_ = listener.Close()
			}
		}
	}()
	if tcpAddr != "" {
		listener, listenErr := net.Listen("tcp", tcpAddr)
		if listenErr != nil {
			return nil, fmt.Errorf("listen tcp %s: %w", tcpAddr, listenErr)
		}
		listeners = append(listeners, listener)
	}
	if socketPath != "" {
		if parentErr := core.ValidateSocketParent(socketPath); parentErr != nil {
			return nil, parentErr
		}
		if info, statErr := os.Lstat(socketPath); statErr == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("listen unix %s: refusing to replace existing non-socket file", socketPath)
			}
			conn, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
			if dialErr == nil {
				_ = conn.Close()
				return nil, fmt.Errorf("listen unix %s: socket is already accepting connections", socketPath)
			}
			if !errors.Is(dialErr, syscall.ECONNREFUSED) {
				return nil, fmt.Errorf("listen unix %s: cannot verify existing socket is stale: %w", socketPath, dialErr)
			}
			if removeErr := os.Remove(socketPath); removeErr != nil {
				return nil, fmt.Errorf("listen unix %s: remove stale socket: %w", socketPath, removeErr)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("listen unix %s: %w", socketPath, statErr)
		}

		listener, listenErr := net.Listen("unix", socketPath)
		if listenErr != nil {
			return nil, fmt.Errorf("listen unix %s: %w", socketPath, listenErr)
		}
		unixListener, ok := listener.(*net.UnixListener)
		if ok {
			unixListener.SetUnlinkOnClose(true)
		}
		mode, parseErr := strconv.ParseUint(socketMode, 8, 9)
		if parseErr != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("listen unix %s: parse socket mode %q: %w", socketPath, socketMode, parseErr)
		}
		if chmodErr := os.Chmod(socketPath, os.FileMode(mode)); chmodErr != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("listen unix %s: set mode %s: %w", socketPath, socketMode, chmodErr)
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, errors.New("no auth listener configured")
	}
	return listeners, nil
}

func run(configPath, profileDir string) error {
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
	prof, err := startProfiler(profileDir)
	if err != nil {
		return err
	}
	if prof != nil {
		// These profiles are intentionally enabled only for an explicit profiling
		// run. Leaving their sampling disabled keeps the normal request path
		// exactly as cheap as before.
		runtime.SetMutexProfileFraction(5)
		runtime.SetBlockProfileRate(1)
		defer func() {
			runtime.SetMutexProfileFraction(0)
			runtime.SetBlockProfileRate(0)
			if err := prof.stop(); err != nil {
				log.Error("write profiling artifacts", "err", err)
			}
		}()
	}

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
		if prof != nil {
			prof.attachPebble(st.(*store.Pebble))
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

	m := metrics.New(cfg.Store.Backend)
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
	// The health checker probes this raw handle, not the instrumented one, so
	// its synthetic Set/Get never inflates guardian_store_ops_total or feeds
	// the detector's store error/slow ratios. Probes have their own metrics.
	rawStore := st
	st = store.Instrument(st, m, detector)
	defer st.Close()

	var powMgr *pow.Manager
	if cfg.SigningKeyFile != "" {
		powMgr, err = pow.NewManagerFromFiles(cfg.SigningKeyFile, cfg.PreviousKeyDir, st)
		if err != nil {
			return fmt.Errorf("signing keys: %w", err)
		}
		warnSecretPerms(log, "signing_key_file", cfg.SigningKeyFile)
		previous, err := pow.LoadPreviousKeys(cfg.PreviousKeyDir)
		if err != nil {
			return fmt.Errorf("previous keys %s: %w", cfg.PreviousKeyDir, err)
		}
		if len(previous) > 0 {
			log.Info("loaded retired signing keys for verification", "count", len(previous))
			warnSecretDirPerms(log, "previous_key_dir", cfg.PreviousKeyDir)
		}
	} else {
		log.Warn("no signing_key_file configured: proof-of-work challenges are disabled")
	}

	// Surface valid-but-inert config (e.g. a honeypot enabled with no paths) so
	// a copied example does not sit doing nothing unnoticed. Non-fatal.
	for _, wmsg := range cfg.Warnings() {
		log.Warn(wmsg)
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

	// Store health: the write + read-back probe behind /readyz, the
	// guardian_store_up gauge and the dashboard's degraded-state surface.
	// Only worth running when there is an admin listener, since without one
	// there is no /readyz, no /metrics and no dashboard to observe it — and
	// unobservable periodic writes are just noise. Start runs the first probe
	// synchronously so the gauge exists before the first scrape; a failing
	// store is not fatal (Guardian fails open), it only fails readiness. The
	// deferred Close runs before the store's, so the probe loop always stops
	// first.
	if cfg.Admin.Listen != "" {
		hc := health.New(rawStore, cfg.Store.Backend, m, log)
		engine.SetHealth(hc)
		hc.Start(context.Background())
		defer hc.Close()
	}

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
		for _, wmsg := range next.Warnings() {
			log.Warn(wmsg)
		}
		return nil
	}
	// preflight answers "would SIGHUP apply the on-disk config?" for the admin
	// endpoint: same load and same static-field diff as reload, applying
	// nothing.
	preflight := func() ([]string, error) {
		next, err := core.LoadConfig(configPath)
		if err != nil {
			return nil, err
		}
		return staticConfigChanges(runningStatic, next), nil
	}

	guard := httptransport.New(engine, powMgr, st, m, log)
	srv := newHTTPServer(cfg.Listen, guard)

	listeners, err := openGuardListeners(cfg.Listen, cfg.Socket, cfg.SocketMode)
	if err != nil {
		return err
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()

	errCh := make(chan error, len(listeners)+1)
	for _, listener := range listeners {
		listener := listener
		go func() {
			log.Info("guardiand listening", "network", listener.Addr().Network(), "addr", listener.Addr().String(), "store", cfg.Store.Backend, "version", version)
			errCh <- srv.Serve(listener)
		}()
	}

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
			warnSecretPerms(log, "admin.token_file", cfg.Admin.TokenFile)
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
		if !isLoopback(cfg.Admin.Listen) {
			// The /admin/* API is bearer-gated, but the scrape/probe endpoints
			// deliberately are not; on a routable bind that trade-off must be a
			// visible choice, not a surprise.
			if cfg.Admin.MetricsAuth {
				log.Warn("admin.listen is not loopback: /healthz and /readyz are served without authentication on this interface (/metrics requires the bearer token via admin.metrics_auth)",
					"addr", cfg.Admin.Listen)
			} else {
				log.Warn("admin.listen is not loopback: /metrics, /healthz and /readyz are served without authentication on this interface; restrict reachability at the firewall, scrape via loopback, or set admin.metrics_auth",
					"addr", cfg.Admin.Listen)
			}
		}

		adminHandler := httptransport.NewAdminServer(engine, cfg, m,
			cfg.Admin.Token, cfg.SigningKeyFile, cfg.PreviousKeyDir, reload, log)
		adminHandler.SetPreflight(preflight)
		admin = newHTTPServer(cfg.Admin.Listen, adminHandler)
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
	// Traffic has drained; push the counter caches' unpushed deltas before the
	// deferred store Close runs, so shared/durable backends keep the last
	// windows' counts across the restart. The flushes get their own budget: a
	// slow drain can consume the shutdown context entirely, and an expired
	// context here would silently drop the deltas this step exists to keep.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer flushCancel()
	if err := guard.FlushCounters(flushCtx); err != nil {
		log.Warn("counter flush incomplete at shutdown", "err", err)
	}
	if err := powMgr.FlushCounters(flushCtx); err != nil {
		log.Warn("pow counter flush incomplete at shutdown", "err", err)
	}
	return nil
}

type staticConfig struct {
	listen, socket, socketMode, signingKeyFile, previousKeyDir string
	trustedProxy                                               bool
	admin                                                      core.AdminConfig
	store                                                      core.StoreConfig
	enforcement                                                core.EnforcementConfig
}

func staticConfigFrom(cfg *core.Config) staticConfig {
	return staticConfig{
		listen: cfg.Listen, socket: cfg.Socket, socketMode: cfg.SocketMode, trustedProxy: cfg.TrustedProxy,
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
	add("socket", running.socket != next.Socket)
	add("socket_mode", running.socketMode != next.SocketMode)
	add("trusted_proxy", running.trustedProxy != next.TrustedProxy)
	add("signing_key_file", running.signingKeyFile != next.SigningKeyFile)
	add("previous_key_dir", running.previousKeyDir != next.PreviousKeyDir)
	add("admin.listen", running.admin.Listen != next.Admin.Listen)
	add("admin.token", running.admin.Token != next.Admin.Token)
	add("admin.token_file", running.admin.TokenFile != next.Admin.TokenFile)
	add("admin.dashboard", running.admin.Dashboard != next.Admin.Dashboard)
	add("admin.recent_size", running.admin.RecentSize != next.Admin.RecentSize)
	add("admin.angie_api", running.admin.AngieAPI != next.Admin.AngieAPI)
	add("admin.metrics_auth", running.admin.MetricsAuth != next.Admin.MetricsAuth)
	add("store.backend", running.store.Backend != next.Store.Backend)
	add("store.path", running.store.Path != next.Store.Path)
	add("store.addr", running.store.Addr != next.Store.Addr)
	add("store.password", running.store.Password != next.Store.Password)
	add("store.db", running.store.DB != next.Store.DB)
	add("store.sync", running.store.Sync != next.Store.Sync)
	// The mirror seed and any netlink/table setup happen at startup, so the
	// whole section is compared as one unit.
	add("enforcement", !reflect.DeepEqual(running.enforcement, next.Enforcement))
	slices.Sort(changed)
	return changed
}

// warnSecretPerms flags a secret file readable beyond its owner. Guardian
// creates both the PoW signing key and the admin token 0600, but the file may
// predate that, have been restored from a backup, or been placed by an operator
// or a config-management tool. The consequences are severe and silent — anyone
// who can read the signing key can mint tokens that pass every check, and the
// admin token grants the whole management API — so it is worth one line at
// startup. It is a warning, not a fatal error: refusing to start would take a
// site down over a permission bit on a file Guardian can still read.
func warnSecretPerms(log *slog.Logger, field, path string) {
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return // the caller already loaded it; a stat race is not worth reporting
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		log.Warn("secret file is readable beyond its owner; restrict it with chmod 600",
			"field", field, "path", path, "mode", fmt.Sprintf("%#o", mode))
	}
}

// warnSecretDirPerms is warnSecretPerms for the retired-key archive: every file
// in it is a private key that still verifies live tokens, so the directory and
// its contents deserve the same scrutiny as the current key.
func warnSecretDirPerms(log *slog.Logger, field, dir string) {
	if dir == "" {
		return
	}
	if info, err := os.Stat(dir); err == nil {
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			log.Warn("retired-key directory is accessible beyond its owner; restrict it with chmod 700",
				"field", field, "path", dir, "mode", fmt.Sprintf("%#o", mode))
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		warnSecretPerms(log, field, filepath.Join(dir, e.Name()))
	}
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
