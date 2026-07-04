// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core"
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
	admin := NewAdminServer(engine, cfg, m, adminToken, keyPath, filepath.Join(dir, "previous"), slog.Default())
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
