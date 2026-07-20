// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/web"
)

// dashboardAdminServer builds an admin server with the dashboard (and thus the
// vendored Chart.js asset) enabled. The shared adminServer helper leaves the
// dashboard off, so the static routes it gates are not registered there.
func dashboardAdminServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.Dashboard = true
	var st store.Store = store.NewMemory()
	t.Cleanup(func() { st.Close() })
	keyPath := filepath.Join(dir, "ed25519.key")
	key, err := pow.LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	st = store.Instrument(st, m)
	engine, err := core.NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMetrics(m)
	t.Cleanup(engine.Close)
	admin := NewAdminServer(engine, cfg, m, adminToken, keyPath, filepath.Join(dir, "previous"), nil, slog.Default())
	ts := httptest.NewServer(admin)
	t.Cleanup(ts.Close)
	return ts
}

// TestChartJSEmbedded: the vendored library is embedded and looks like Chart.js.
// Guards against a broken go:embed pattern or a truncated blob.
func TestChartJSEmbedded(t *testing.T) {
	asset, err := web.FS.ReadFile("vendor/chart.umd.min.js")
	if err != nil {
		t.Fatalf("chart.umd.min.js not embedded: %v", err)
	}
	if len(asset) < 100_000 {
		t.Fatalf("chart.umd.min.js suspiciously small: %d bytes", len(asset))
	}
	if !bytes.Contains(asset[:512], []byte("Chart.js v4")) {
		t.Errorf("blob does not carry the Chart.js v4 banner; wrong or corrupt file")
	}
	if bytes.Contains(asset, []byte("sourceMappingURL")) {
		t.Errorf("sourceMappingURL comment present; the browser would request a .map we do not serve")
	}
}

// TestChartJSServedUnauthenticated: a <script src> fetch carries no Authorization
// header, so the asset must serve without a token (like the dashboard shell),
// with a javascript content type. The URL is fixed, so it revalidates against a
// content ETag rather than caching immutably: a guardiand upgrade that changes
// the blob is picked up instead of pairing a stale library with new dashboard JS.
func TestChartJSServedUnauthenticated(t *testing.T) {
	ts := dashboardAdminServer(t)

	// No Authorization header — exactly how a browser fetches <script src>.
	resp, err := http.Get(ts.URL + "/admin/chart.umd.min.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (must not require auth)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/javascript; charset=utf-8", ct)
	}
	// Must revalidate, never a blind long-lived cache: the fixed URL is reused
	// across versions, so a year-long immutable copy could outlive its blob.
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache (revalidate, not immutable)", cc)
	}
	if resp.Header.Get("ETag") == "" {
		t.Errorf("missing ETag; the asset cannot revalidate without one")
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body[:min(512, len(body))], []byte("Chart.js")) {
		t.Errorf("served body is not Chart.js")
	}
}

// TestChartJSRevalidates: a conditional request carrying the current ETag gets a
// cheap 304, and a stale/absent ETag gets the full body, so a matching browser
// pays nothing while an upgraded blob is always refetched.
func TestChartJSRevalidates(t *testing.T) {
	ts := dashboardAdminServer(t)

	resp, err := http.Get(ts.URL + "/admin/chart.umd.min.js")
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	resp.Body.Close()
	if etag == "" {
		t.Fatal("no ETag on the initial response")
	}

	// Same ETag -> 304, empty body.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/chart.umd.min.js", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("matching ETag: status = %d, want 304", resp2.StatusCode)
	}
	if body, _ := io.ReadAll(resp2.Body); len(body) != 0 {
		t.Errorf("304 response carried a %d-byte body, want empty", len(body))
	}

	// A stale ETag (old vendored version) -> full 200 with the fresh library.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/chart.umd.min.js", nil)
	req3.Header.Set("If-None-Match", `"deadbeefdeadbeefdeadbeefdeadbeef"`)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("stale ETag: status = %d, want 200 (full refetch)", resp3.StatusCode)
	}
}

// TestChartJSGatedOnDashboard: when admin.dashboard is off (the default), the
// static asset route is not registered, so it 404s — no surface beyond the
// opt-in dashboard.
func TestChartJSGatedOnDashboard(t *testing.T) {
	ts, _ := adminServer(t) // dashboard NOT enabled in adminYAML
	resp, err := http.Get(ts.URL + "/admin/chart.umd.min.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when dashboard disabled", resp.StatusCode)
	}
}
