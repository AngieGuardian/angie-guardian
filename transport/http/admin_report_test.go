// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/store"
)

// reportYAML denylists a range so Evaluate produces deny decisions the
// report endpoints can serve, and enables the dashboard page.
const reportYAML = `
store: { backend: memory }
admin: { dashboard: true }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
  denylist:
    ips: [ "203.0.113.0/24" ]
`

func reportServer(t *testing.T, yaml string) (*httptest.Server, *core.Engine) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "guardian.yaml")
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
	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)
	return ts, engine
}

func TestAdminBlockList(t *testing.T) {
	ts, _ := reportServer(t, reportYAML)

	// Empty store → empty list, count 0.
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks", adminToken, ""))
	if m["count"] != float64(0) {
		t.Fatalf("initial list count = %v, want 0", m["count"])
	}

	// Two blocks (one TTL'd, one via the admin PUT default) → listed sorted with reasons.
	adminReq(t, ts, "PUT", "/admin/blocks/203.0.113.9", adminToken, `{"reason":"manual abuse","ttl":"2h"}`)
	adminReq(t, ts, "PUT", "/admin/blocks/198.51.100.4", adminToken, `{"reason":"scanner"}`)

	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks", adminToken, ""))
	if m["count"] != float64(2) {
		t.Fatalf("list count = %v, want 2", m["count"])
	}
	blocks := m["blocks"].([]any)
	first := blocks[0].(map[string]any)
	if first["ip"] != "198.51.100.4" || first["reason"] != "scanner" {
		t.Fatalf("first block = %v, want 198.51.100.4/scanner (key-sorted)", first)
	}
	if first["expires_at"] == nil {
		t.Error("TTL'd block should carry expires_at")
	}
}

func TestAdminDecisionsAndStats(t *testing.T) {
	ts, engine := reportServer(t, reportYAML)
	ctx := context.Background()

	// Drive real pipeline decisions: three denies (denylisted range). The
	// allow must NOT appear in the feed.
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		d := engine.Evaluate(ctx, &core.RequestContext{
			Host: "site.test", Method: "GET", URI: "/probe?x=1", RemoteAddr: ip, UserAgent: "curl/8",
		})
		if d.Action != core.ActionDeny {
			t.Fatalf("setup: expected deny for %s, got %s", ip, d.Action)
		}
	}
	engine.Evaluate(ctx, &core.RequestContext{
		Host: "site.test", Method: "GET", URI: "/fine", RemoteAddr: "198.51.100.9", UserAgent: "curl/8",
	})

	// Newest first, allow excluded.
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions", adminToken, ""))
	if m["count"] != float64(3) {
		t.Fatalf("decisions count = %v, want 3 (allow must not be recorded)", m["count"])
	}
	ds := m["decisions"].([]any)
	if newest := ds[0].(map[string]any); newest["ip"] != "203.0.113.3" || newest["reason"] != "denylist:ip" {
		t.Fatalf("newest decision = %v, want ip=203.0.113.3 reason=denylist:ip", newest)
	}

	// limit + filters.
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?limit=2", adminToken, ""))
	if m["count"] != float64(2) {
		t.Fatalf("limit=2 count = %v, want 2", m["count"])
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?action=challenge", adminToken, ""))
	if m["count"] != float64(0) {
		t.Fatalf("action=challenge count = %v, want 0", m["count"])
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?reason=denylist", adminToken, ""))
	if m["count"] != float64(3) {
		t.Fatalf("reason=denylist count = %v, want 3", m["count"])
	}
	if resp := adminReq(t, ts, "GET", "/admin/decisions?limit=bogus", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad limit: status = %d, want 400", resp.StatusCode)
	}

	// Stats roll the same window up by action and reason category.
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/stats", adminToken, ""))
	recent := m["recent"].(map[string]any)
	if recent["total"] != float64(3) {
		t.Fatalf("stats recent.total = %v, want 3", recent["total"])
	}
	if byAction := recent["by_action"].(map[string]any); byAction["deny"] != float64(3) {
		t.Fatalf("stats by_action = %v, want deny:3", byAction)
	}
	if byReason := recent["by_reason"].(map[string]any); byReason["denylist"] != float64(3) {
		t.Fatalf("stats by_reason = %v, want denylist:3 (category, not full reason)", byReason)
	}
}

func TestAdminDashboardGate(t *testing.T) {
	// Enabled: served without a token (static shell; data endpoints stay guarded).
	ts, _ := reportServer(t, reportYAML)
	resp := adminReq(t, ts, "GET", "/admin/dashboard", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard enabled: status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("dashboard content-type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Guardian dashboard") {
		t.Error("dashboard page missing its title")
	}

	// Disabled (the default): the route does not exist.
	off, _ := reportServer(t, "store: { backend: memory }\n")
	if resp := adminReq(t, off, "GET", "/admin/dashboard", "", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("dashboard disabled: status = %d, want 404", resp.StatusCode)
	}
}
