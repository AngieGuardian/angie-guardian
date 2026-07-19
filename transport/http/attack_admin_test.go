// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/store"
)

func attackAdminServer(t *testing.T) (*httptest.Server, *attackmode.Detector) {
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
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	d := attackmode.New(cfg.AttackModeSettings(), st, slog.Default())
	engine.SetAttackDetector(d)
	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)
	return ts, d
}

func TestAdminAttackStatusAndPin(t *testing.T) {
	ts, d := attackAdminServer(t)

	if resp := adminReq(t, ts, "GET", "/admin/attack", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", resp.StatusCode)
	}

	// Initially normal.
	resp := adminReq(t, ts, "GET", "/admin/attack", adminToken, "")
	if body := decodeJSON(t, resp); body["level"] != "normal" || body["pinned"] != false {
		t.Fatalf("initial status = %v", body)
	}

	// Pin to attack.
	resp = adminReq(t, ts, "POST", "/admin/attack", adminToken, `{"level":"attack"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pin: %d", resp.StatusCode)
	}
	if d.State().Level != attackmode.Attack {
		t.Fatalf("detector level after pin = %s", d.State().Level)
	}
	resp = adminReq(t, ts, "GET", "/admin/attack", adminToken, "")
	if body := decodeJSON(t, resp); body["level"] != "attack" || body["pinned"] != true {
		t.Fatalf("pinned status = %v", body)
	}

	// Unpin via "auto".
	resp = adminReq(t, ts, "POST", "/admin/attack", adminToken, `{"level":"auto"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unpin: %d", resp.StatusCode)
	}
	if _, pinned := d.Pinned(); pinned {
		t.Fatal("still pinned after auto")
	}

	// Bad level rejected.
	if resp := adminReq(t, ts, "POST", "/admin/attack", adminToken, `{"level":"sideways"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad level: %d, want 400", resp.StatusCode)
	}
}

func TestAdminStatsIncludesAttack(t *testing.T) {
	ts, _ := attackAdminServer(t)
	resp := adminReq(t, ts, "GET", "/admin/stats", adminToken, "")
	body := decodeJSON(t, resp)
	attack, ok := body["attack"].(map[string]any)
	if !ok || attack["level"] != "normal" {
		t.Fatalf("stats attack key = %v", body["attack"])
	}
}
