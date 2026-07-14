// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/intel/inteltest"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const adminYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
`

const adminToken = "s3cret-admin-token"

func adminServer(t *testing.T) (*httptest.Server, string) {
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
	return ts, keyPath
}

func adminReq(t *testing.T, ts *httptest.Server, method, path, token string, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return m
}

// TestAdminStatsChallenges: the stats rollup surfaces the PoW lifecycle
// counters (read back from the Prometheus registry) for the dashboard tiles.
func TestAdminStatsChallenges(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	m := metrics.New()
	m.Challenge("issued")
	m.Challenge("issued")
	m.Challenge("solved")
	m.Challenge("failed")
	m.SolveTime(1.0)
	m.SolveTime(3.0)

	ts := httptest.NewServer(NewAdminServer(engine, cfg, m, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)

	stats := decodeJSON(t, adminReq(t, ts, "GET", "/admin/stats", adminToken, ""))
	ch, ok := stats["challenges"].(map[string]any)
	if !ok {
		t.Fatalf("stats has no challenges rollup: %v", stats)
	}
	if ch["issued"] != 2.0 || ch["solved"] != 1.0 || ch["failed"] != 1.0 {
		t.Errorf("challenges = %v, want issued 2 / solved 1 / failed 1", ch)
	}
	if avg, _ := ch["avg_solve_seconds"].(float64); avg != 2.0 {
		t.Errorf("avg_solve_seconds = %v, want 2", ch["avg_solve_seconds"])
	}
}

func TestAdminAuth(t *testing.T) {
	ts, _ := adminServer(t)

	// No token, wrong token → 401.
	if resp := adminReq(t, ts, "GET", "/admin/blocks/1.2.3.4", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", resp.StatusCode)
	}
	if resp := adminReq(t, ts, "GET", "/admin/blocks/1.2.3.4", "wrong", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", resp.StatusCode)
	}
	// Correct token → 200.
	if resp := adminReq(t, ts, "GET", "/admin/blocks/1.2.3.4", adminToken, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("correct token: status = %d, want 200", resp.StatusCode)
	}
	// Metrics and healthz need no token.
	if resp := adminReq(t, ts, "GET", "/healthz", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: status = %d, want 200", resp.StatusCode)
	}
}

// TestAdminReload: POST /admin/reload drives the injected reload func; a
// failing reload keeps the endpoint returning the error, and the adminServer
// helper (no reload func) reports the endpoint unavailable.
func TestAdminReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	calls := 0
	var reloadErr error
	reload := func() error { calls++; return reloadErr }
	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", reload, slog.Default()))
	t.Cleanup(ts.Close)

	if resp := adminReq(t, ts, "POST", "/admin/reload", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", resp.StatusCode)
	}
	m := decodeJSON(t, adminReq(t, ts, "POST", "/admin/reload", adminToken, ""))
	if m["reloaded"] != true || calls != 1 {
		t.Errorf("reload: got %v (calls=%d), want reloaded=true after 1 call", m, calls)
	}

	reloadErr = fmt.Errorf("config invalid: boom")
	resp := adminReq(t, ts, "POST", "/admin/reload", adminToken, "")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("failed reload: status = %d, want 422", resp.StatusCode)
	}
	if m := decodeJSON(t, resp); m["reloaded"] != false || m["error"] == "" {
		t.Errorf("failed reload body: %v", m)
	}

	// No reload func wired (e.g. embedded without a config path) → 503.
	tsNil, _ := adminServer(t)
	if resp := adminReq(t, tsNil, "POST", "/admin/reload", adminToken, ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("nil reload: status = %d, want 503", resp.StatusCode)
	}
}

func TestAdminBlockLifecycle(t *testing.T) {
	ts, _ := adminServer(t)
	ip := "203.0.113.9"

	// Initially not blocked.
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks/"+ip, adminToken, ""))
	if m["blocked"] != false {
		t.Fatalf("initial: blocked = %v, want false", m["blocked"])
	}
	// Block it.
	m = decodeJSON(t, adminReq(t, ts, "PUT", "/admin/blocks/"+ip, adminToken, `{"reason":"manual","ttl":"1h"}`))
	if m["blocked"] != true {
		t.Fatalf("after PUT: blocked = %v, want true", m["blocked"])
	}
	// Now reported blocked with the reason.
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks/"+ip, adminToken, ""))
	if m["blocked"] != true || m["reason"] != "manual" {
		t.Fatalf("after block: %v", m)
	}
	// Unblock.
	adminReq(t, ts, "DELETE", "/admin/blocks/"+ip, adminToken, "")
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks/"+ip, adminToken, ""))
	if m["blocked"] != false {
		t.Fatalf("after DELETE: blocked = %v, want false", m["blocked"])
	}
}

func TestAdminBlockRejectsInvalidInput(t *testing.T) {
	ts, _ := adminServer(t)
	for _, tc := range []struct {
		name, ip, body string
	}{
		{"malformed json", "203.0.113.10", `{"ttl":`},
		{"zero ttl", "203.0.113.11", `{"ttl":"0s"}`},
		{"negative ttl", "203.0.113.12", `{"ttl":"-1s"}`},
		{"unknown field", "203.0.113.13", `{"ttl":"1m","extra":true}`},
		{"trailing json", "203.0.113.14", `{"ttl":"1m"} {"ttl":"2m"}`},
		{"invalid ip", "not-an-ip", `{"ttl":"1m"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := adminReq(t, ts, http.MethodPut, "/admin/blocks/"+tc.ip, adminToken, tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, b)
			}
			if tc.ip != "not-an-ip" {
				status := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/blocks/"+tc.ip, adminToken, ""))
				if status["blocked"] != false {
					t.Fatalf("invalid request changed block state: %v", status)
				}
			}
		})
	}
}

func TestAdminRotateKey(t *testing.T) {
	ts, keyPath := adminServer(t)
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	resp := adminReq(t, ts, "POST", "/admin/rotate-key", adminToken, "")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate: status = %d body = %s", resp.StatusCode, b)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("signing key file unchanged after rotation")
	}
}

func TestAdminRotateKeyRequiresPreviousDirectory(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	keyPath := filepath.Join(dir, "ed25519.key")
	key, err := pow.LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := core.NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	ts := httptest.NewServer(NewAdminServer(engine, cfg, metrics.New(), adminToken, keyPath, "", nil, slog.Default()))
	t.Cleanup(ts.Close)

	resp := adminReq(t, ts, "POST", "/admin/rotate-key", adminToken, "")
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate without previous_key_dir: status = %d body = %s", resp.StatusCode, body)
	}
}

func TestAdminMetricsExposed(t *testing.T) {
	ts, _ := adminServer(t)
	// Place a block so at least one guardian metric has a value.
	adminReq(t, ts, "PUT", "/admin/blocks/203.0.113.1", adminToken, `{"reason":"x"}`)

	resp := adminReq(t, ts, "GET", "/metrics", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// store_ops_total is touched by the block write above; go_goroutines comes
	// from the Go collector. (Counter series only appear once a label
	// combination has been observed, so we assert on metrics we exercised.)
	for _, want := range []string{"guardian_store_ops_total", "go_goroutines"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestAdminScoreNoModel(t *testing.T) {
	ts, _ := adminServer(t)
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/score?host=x.test&uri=/&ua=curl", adminToken, ""))
	if m["scored"] != false {
		t.Fatalf("score without model: %v, want scored=false", m)
	}
	// Missing host → 400.
	if resp := adminReq(t, ts, "GET", "/admin/score", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing host: status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminConfigView(t *testing.T) {
	ts, _ := adminServer(t)
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/config", adminToken, ""))
	if m["store"] != "memory" {
		t.Fatalf("config view store = %v, want memory", m["store"])
	}
	if _, ok := m["defaults"]; !ok {
		t.Fatal("config view missing defaults")
	}
}

// TestAdminIntel exercises /admin/intel and /admin/intel/{ip} against an
// engine with a real (fixture) country database and one local feed.
func TestAdminIntel(t *testing.T) {
	// The default adminServer has no intel configured.
	ts, _ := adminServer(t)
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/intel", adminToken, ""))
	if m["enabled"] != false {
		t.Fatalf("unconfigured intel: %v, want enabled=false", m)
	}

	// Now one with geoip + a deny feed.
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{"203.0.113.0/24": "RU"})
	feedFile := filepath.Join(dir, "bad.list")
	if err := os.WriteFile(feedFile, []byte("203.0.113.0/26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
store: { backend: memory }
geoip: { country_db: %s }
reputation:
  feeds: [ { name: bad-actors, file: %s } ]
defaults:
  geo: { enabled: true, deny: { countries: [ RU ] } }
  reputation: { enabled: true }
`, countryDB, feedFile)
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	ts2 := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts2.Close)

	m = decodeJSON(t, adminReq(t, ts2, "GET", "/admin/intel", adminToken, ""))
	if m["enabled"] != true {
		t.Fatalf("intel status: %v, want enabled=true", m)
	}
	intelView := m["intel"].(map[string]any)
	if intelView["country_db"] == nil {
		t.Fatal("intel status missing country_db")
	}
	feeds := intelView["feeds"].([]any)
	if len(feeds) != 1 || feeds[0].(map[string]any)["entries"] != float64(1) {
		t.Fatalf("unexpected feeds view: %v", feeds)
	}

	m = decodeJSON(t, adminReq(t, ts2, "GET", "/admin/intel/203.0.113.9", adminToken, ""))
	info := m["info"].(map[string]any)
	if info["country"] != "RU" {
		t.Fatalf("lookup info: %v, want country RU", info)
	}
	hits := m["feeds"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["feed"] != "bad-actors" {
		t.Fatalf("lookup feeds: %v", hits)
	}
	// Outside the feed range but inside the country.
	m = decodeJSON(t, adminReq(t, ts2, "GET", "/admin/intel/203.0.113.99", adminToken, ""))
	if _, ok := m["feeds"]; ok {
		t.Fatalf("no feed hit expected: %v", m)
	}
	// Garbage IP → 400.
	if resp := adminReq(t, ts2, "GET", "/admin/intel/not-an-ip", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad ip: status = %d, want 400", resp.StatusCode)
	}
}
