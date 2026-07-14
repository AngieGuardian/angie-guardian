// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
)

func daemonTestConfig(t *testing.T, body string) *core.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeDaemonTestConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSignalReadyOnlyAfterListenerResponds(t *testing.T) {
	called := false
	cfg := daemonTestConfig(t, "listen: 127.0.0.1:0\n")
	if err := signalReadyWhenListening(context.Background(), cfg, 20*time.Millisecond, func() { called = true }); err == nil {
		t.Fatal("unreachable listener unexpectedly reported ready")
	}
	if called {
		t.Fatal("ready callback ran before a listener was reachable")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = u.Host
	called = false
	if err := signalReadyWhenListening(context.Background(), cfg, time.Second, func() { called = true }); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("ready callback did not run after health check succeeded")
	}
}

func TestHealthcheckProbesEveryConfiguredListener(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := writeDaemonTestConfig(t, "listen: "+u.Host+"\nadmin: { listen: "+u.Host+" }\n")
	if err := checkHealth(path, time.Second); err != nil {
		t.Fatalf("reachable listeners failed healthcheck: %v", err)
	}

	unreachable := writeDaemonTestConfig(t, "listen: "+u.Host+"\nadmin: { listen: 127.0.0.1:0 }\n")
	if err := checkHealth(unreachable, 20*time.Millisecond); err == nil {
		t.Fatal("healthcheck passed while the configured admin listener was unavailable")
	}
}

func TestStaticConfigChanges(t *testing.T) {
	running := daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: memory }\n")
	base := staticConfigFrom(running)
	dynamic := daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: memory }\ndomains: { example.test: {} }\n")
	if got := staticConfigChanges(base, dynamic); len(got) != 0 {
		t.Fatalf("dynamic-only config reported static changes: %v", got)
	}

	changed := daemonTestConfig(t, "listen: 127.0.0.1:9090\nstore: { backend: redis, addr: 127.0.0.1:6379 }\n")
	want := []string{"listen", "store.addr", "store.backend"}
	if got := staticConfigChanges(base, changed); !slices.Equal(got, want) {
		t.Fatalf("static changes = %v, want %v", got, want)
	}
}
