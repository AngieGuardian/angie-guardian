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
	"reflect"
	"slices"
	"strings"
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

// -healthcheck must probe the running daemon even when the on-disk config was
// edited into an invalid state, or a bad edit would crash-loop a healthy,
// fail-open-serving service. checkHealth extracts only the listen addresses,
// which must succeed where full config load fails.
func TestCheckHealthUsesInvalidConfigAddresses(t *testing.T) {
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
	// Valid listen line, but a bogus field elsewhere that fails strict load.
	path := writeDaemonTestConfig(t, "listen: "+u.Host+"\nnonsense_field: true\n")
	if _, err := core.LoadConfig(path); err == nil {
		t.Fatal("expected LoadConfig to reject the invalid config")
	}
	if err := checkHealth(path, time.Second); err != nil {
		t.Fatalf("healthcheck must succeed against a reachable listener despite an invalid config: %v", err)
	}
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

func TestDisplayAddrPreservesWildcardAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"0.0.0.0:8071", "127.0.0.1:8071"},
		{"[::]:8071", "[::1]:8071"},
		{":8071", "127.0.0.1:8071"},
	} {
		if got := displayAddr(tc.in); got != tc.want {
			t.Errorf("displayAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAdminDashboardURLContainsNoCredential(t *testing.T) {
	got := adminDashboardURL("127.0.0.1:8072")
	if got != "http://127.0.0.1:8072/admin/dashboard" {
		t.Fatalf("dashboard URL = %q", got)
	}
	if strings.Contains(got, "token") || strings.Contains(got, "#") {
		t.Fatalf("dashboard URL contains credential material: %q", got)
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

	recentSize := daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: memory }\nadmin: { recent_size: 8192 }\n")
	if got, want := staticConfigChanges(base, recentSize), []string{"admin.recent_size"}; !slices.Equal(got, want) {
		t.Fatalf("recent-size changes = %v, want %v", got, want)
	}

	changed := daemonTestConfig(t, "listen: 127.0.0.1:9090\nstore: { backend: redis, addr: 127.0.0.1:6379 }\n")
	want := []string{"listen", "store.addr", "store.backend"}
	if got := staticConfigChanges(base, changed); !slices.Equal(got, want) {
		t.Fatalf("static changes = %v, want %v", got, want)
	}

	// The store is opened with cfg.Store.Sync at startup; flipping it on reload
	// must be rejected, or the operator would believe they changed durability.
	runningPebble := daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: pebble, path: /tmp/g, sync: false }\n")
	syncFlip := daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: pebble, path: /tmp/g, sync: true }\n")
	if got, want := staticConfigChanges(staticConfigFrom(runningPebble), syncFlip), []string{"store.sync"}; !slices.Equal(got, want) {
		t.Fatalf("sync-flip changes = %v, want %v", got, want)
	}
}

// Every AdminConfig field is consumed once at startup when the admin server is
// built, so every field must appear in staticConfigChanges. A field missing
// from the list makes its reload succeed while changing nothing, with
// Engine.Config then misreporting the running state (this happened to
// metrics_auth). Perturb each field and demand the reload is rejected.
func TestStaticConfigChangesCoversEveryAdminField(t *testing.T) {
	base := staticConfigFrom(daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: memory }\n"))
	// A struct field compares as a unit, so flipping any one leaf inside it
	// proves the whole field participates in the diff.
	var perturb func(v reflect.Value) bool
	perturb = func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.String:
			v.SetString(v.String() + "x")
		case reflect.Bool:
			v.SetBool(!v.Bool())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v.SetInt(v.Int() + 1)
		case reflect.Struct:
			for i := range v.NumField() {
				if perturb(v.Field(i)) {
					return true
				}
			}
			return false
		default:
			return false
		}
		return true
	}
	rt := reflect.TypeFor[core.AdminConfig]()
	for i := range rt.NumField() {
		next := daemonTestConfig(t, "listen: 127.0.0.1:8071\nstore: { backend: memory }\n")
		if !perturb(reflect.ValueOf(&next.Admin).Elem().Field(i)) {
			t.Fatalf("admin field %s has kind %s: teach this test to perturb it", rt.Field(i).Name, rt.Field(i).Type.Kind())
		}
		if got := staticConfigChanges(base, next); len(got) == 0 {
			t.Errorf("changing admin.%s reports no static change: a reload would silently ignore it", rt.Field(i).Name)
		}
	}
}

func TestResolveConfigPath(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configPath string
		testConfig bool
		want       string
		wantOK     bool
	}{
		{"serving without -config is a usage error", "", false, "", false},
		{"serving with -config uses it", "/tmp/x.yaml", false, "/tmp/x.yaml", true},
		{"-t without -config defaults", "", true, defaultConfigPath, true},
		{"-t with -config still wins", "/tmp/x.yaml", true, "/tmp/x.yaml", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveConfigPath(tc.configPath, tc.testConfig)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("resolveConfigPath(%q, %v) = (%q, %v), want (%q, %v)",
					tc.configPath, tc.testConfig, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// The default is only useful if it is where the packaging actually puts the
// file, so pin it against the unit file rather than trusting the constant.
func TestDefaultConfigPathMatchesTheUnitFile(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/guardiand.service")
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	if !strings.Contains(string(unit), "-config "+defaultConfigPath) {
		t.Fatalf("deploy/guardiand.service does not run with -config %s; the -t default now points somewhere the packaging does not use", defaultConfigPath)
	}
}
