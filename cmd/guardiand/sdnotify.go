// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/melroy89/angie-guardian/core"
)

// sd_notify (sd_notify(3)) lets the daemon tell systemd when it is actually
// ready and keep a watchdog alive, without any dependency: the protocol is a
// datagram of "KEY=VALUE\n" lines to the unix socket in $NOTIFY_SOCKET. When
// the daemon is not run under systemd (or the unit is Type=simple), the env
// var is unset and every call here is a no-op, so this is safe to always call.

// waitListening blocks until every configured HTTP listener answers GET
// /healthz, or ctx/timeout elapses. It is what makes the systemd READY=1
// signal honest: "active" then means the auth hot path (and admin listener,
// if enabled) is actually accepting, not just that the process is alive.
func waitListening(ctx context.Context, listen, socket, adminListen string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type target struct {
		name   string
		client *http.Client
		url    string
	}
	var targets []target
	if listen != "" {
		targets = append(targets, target{
			name:   "tcp " + listen,
			client: &http.Client{Timeout: 2 * time.Second},
			url:    "http://" + displayAddr(listen) + "/healthz",
		})
	}
	if socket != "" {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		}
		defer transport.CloseIdleConnections()
		targets = append(targets, target{
			name:   "unix " + socket,
			client: &http.Client{Transport: transport, Timeout: 2 * time.Second},
			url:    "http://guardian/healthz",
		})
	}
	if adminListen != "" {
		targets = append(targets, target{
			name:   "admin " + adminListen,
			client: &http.Client{Timeout: 2 * time.Second},
			url:    "http://" + displayAddr(adminListen) + "/healthz",
		})
	}

	probe := func(t target) bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.url, nil)
		if err != nil {
			return false
		}
		resp, err := t.client.Do(req)
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	for _, target := range targets {
		for !probe(target) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("listener %s not ready: %w", target.name, ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil
}

// signalReadyWhenListening calls ready only after every configured listener
// answers its health probe. Keeping the callback separate makes the failure
// contract testable without a live systemd notification socket.
func signalReadyWhenListening(ctx context.Context, cfg *core.Config, timeout time.Duration, ready func()) error {
	if err := waitListening(ctx, cfg.Listen, cfg.Socket, cfg.Admin.Listen, timeout); err != nil {
		return err
	}
	ready()
	return nil
}

// notifier sends sd_notify messages to $NOTIFY_SOCKET. A nil *notifier (env
// var unset) makes every method a no-op, so callers never branch.
type notifier struct {
	conn *net.UnixConn
}

// newNotifier connects to $NOTIFY_SOCKET, or returns nil when it is unset
// (not run under a Type=notify unit). An abstract socket ("@name") is
// addressed with a leading NUL, per the systemd convention.
func newNotifier() *notifier {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		// Non-fatal: readiness signalling is best-effort. systemd will fall
		// back to its start timeout if it never hears READY=1.
		return nil
	}
	return &notifier{conn: conn}
}

func (n *notifier) send(state string) {
	if n == nil {
		return
	}
	_, _ = n.conn.Write([]byte(state))
}

// Ready tells systemd the service is up and serving (Type=notify).
func (n *notifier) Ready() { n.send("READY=1\n") }

// Stopping tells systemd a clean shutdown has begun, so the stop timeout does
// not count a graceful drain as a hang.
func (n *notifier) Stopping() { n.send("STOPPING=1\n") }

// Close releases the socket.
func (n *notifier) Close() {
	if n != nil && n.conn != nil {
		_ = n.conn.Close()
	}
}

// startWatchdog pings systemd at half the WatchdogSec interval it set (via
// $WATCHDOG_USEC), so a wedged daemon is restarted instead of looking healthy.
// It runs until ctx is cancelled. A no-op when the watchdog is disabled or the
// process is not the intended watchdog target ($WATCHDOG_PID mismatch).
func (n *notifier) startWatchdog(ctx context.Context, log *slog.Logger) {
	if n == nil {
		return
	}
	usec := os.Getenv("WATCHDOG_USEC")
	if usec == "" {
		return
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return
	}
	us, err := strconv.Atoi(usec)
	if err != nil || us <= 0 {
		return
	}
	// Ping at half the interval so a late schedule never trips the deadline.
	interval := time.Duration(us) * time.Microsecond / 2
	log.Info("systemd watchdog active", "ping_interval", interval)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n.send("WATCHDOG=1\n")
			}
		}
	}()
}
