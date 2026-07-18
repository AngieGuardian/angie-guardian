// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/store"
)

// offloadServer builds an admin server whose engine has the enforcement
// offload wired and seeded, the way guardiand runs it.
func offloadServer(t *testing.T) (*httptest.Server, *enforce.Manager) {
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
	enf := enforce.New(cfg.EnforceConfig(), st, nil, slog.Default())
	t.Cleanup(func() { enf.Close() })
	engine.SetEnforcer(enf)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	enf.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !enf.Status().Mirror.Seeded {
		if time.Now().After(deadline) {
			t.Fatal("mirror never seeded")
		}
		time.Sleep(2 * time.Millisecond)
	}
	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)
	return ts, enf
}

func TestAdminOffloadStatus(t *testing.T) {
	ts, _ := offloadServer(t)

	if resp := adminReq(t, ts, "GET", "/admin/offload", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: got %d", resp.StatusCode)
	}

	// Place a block through the engine-independent admin route so the mirror
	// count is visible in the offload status.
	resp := adminReq(t, ts, "PUT", "/admin/blocks/203.0.113.9", adminToken, `{"reason":"test"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("block: got %d", resp.StatusCode)
	}
	resp = adminReq(t, ts, "GET", "/admin/offload", adminToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("offload status: got %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	mirror, ok := body["mirror"].(map[string]any)
	if !ok {
		t.Fatalf("no mirror object in %v", body)
	}
	if mirror["mode"] != "authoritative" || mirror["seeded"] != true {
		t.Fatalf("mirror status = %v", mirror)
	}
	if n, _ := mirror["entries"].(float64); n != 1 {
		t.Fatalf("mirror entries = %v, want 1", mirror["entries"])
	}
}

func TestAdminOffloadReconcile(t *testing.T) {
	ts, enf := offloadServer(t)
	first := enf.Status().Mirror.LastReconcile
	resp := adminReq(t, ts, "POST", "/admin/offload/reconcile", adminToken, "")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("reconcile: got %d", resp.StatusCode)
	}
	// The forced scan actually runs: the reconcile timestamp advances well
	// before the 10s ticker could.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if enf.Status().Mirror.LastReconcile.After(first) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forced reconcile never ran")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestAdminOffloadWithoutEnforcer(t *testing.T) {
	// The plain adminServer helper wires no enforcer: status degrades to a
	// disabled report and reconcile is a conflict, never a panic.
	ts, _ := adminServer(t)
	resp := adminReq(t, ts, "GET", "/admin/offload", adminToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("offload status: got %d", resp.StatusCode)
	}
	if body := decodeJSON(t, resp); body["enabled"] != false {
		t.Fatalf("body = %v, want enabled:false", body)
	}
	if resp := adminReq(t, ts, "POST", "/admin/offload/reconcile", adminToken, ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("reconcile without enforcer: got %d", resp.StatusCode)
	}
}
