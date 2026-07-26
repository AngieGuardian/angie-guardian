// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/intel/inteltest"
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

type scanCountingStore struct {
	store.Store
	scans atomic.Int64
}

func (s *scanCountingStore) Scan(ctx context.Context, prefix string) ([]store.KV, error) {
	s.scans.Add(1)
	return s.Store.Scan(ctx, prefix)
}

func (s *scanCountingStore) ScanLimit(ctx context.Context, prefix string, limit int) ([]store.KV, bool, error) {
	s.scans.Add(1)
	if limited, ok := s.Store.(store.LimitedScanner); ok {
		return limited.ScanLimit(ctx, prefix, limit)
	}
	kvs, err := s.Store.Scan(ctx, prefix)
	return kvs, true, err
}

func reportServer(t *testing.T, yaml string) (*httptest.Server, *core.Engine) {
	t.Helper()
	cfg := loadAdminReportConfig(t, yaml)
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

func loadAdminReportConfig(t testing.TB, yaml string) *core.Config {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func BenchmarkRecentAdmin(b *testing.B) {
	const benchmarkYAML = `
store: { backend: memory }
defaults:
  denylist:
    ips: [ "0.0.0.0/0" ]
`
	for _, size := range []int{512, 4096, 16384, 65536} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			cfg := loadAdminReportConfig(b, benchmarkYAML)
			// Include one deliberately over-cap size to show the cost curve. The
			// engine constructor accepts an already-finalized Config; production
			// config loading still enforces the cap.
			cfg.Admin.RecentSize = size
			st := store.NewMemory()
			defer st.Close()
			engine, err := core.NewEngine(cfg, st, nil, slog.Default())
			if err != nil {
				b.Fatal(err)
			}
			defer engine.Close()
			ctx := context.Background()
			for i := 0; i < size; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
				engine.Evaluate(ctx, &core.RequestContext{
					Host: "protected.example", Method: "GET",
					URI:        fmt.Sprintf("/wp-login.php?attempt=%d&source=distributed-scan", i),
					RemoteAddr: ip,
					UserAgent:  "Mozilla/5.0 (compatible; GuardianBenchmarkBot/1.0; +https://example.invalid/bot)",
				})
			}
			handler := NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default())
			for _, tc := range []struct {
				name string
				path string
			}{
				{name: "stats", path: "/admin/stats"},
				{name: "offenders", path: "/admin/offenders"},
				{name: "decisions-detailed-512", path: "/admin/decisions?limit=512"},
				{name: "decisions-compact-all", path: "/admin/decisions?view=compact&limit=all"},
			} {
				b.Run(tc.name, func(b *testing.B) {
					b.ReportAllocs()
					var responseBytes int64
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						req := httptest.NewRequest(http.MethodGet, tc.path, nil)
						req.Header.Set("Authorization", "Bearer "+adminToken)
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)
						if rec.Code != http.StatusOK {
							b.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
						}
						responseBytes += int64(rec.Body.Len())
					}
					b.StopTimer()
					b.ReportMetric(float64(responseBytes)/float64(b.N), "B/response")
				})
			}
		})
	}
}

func TestAdminBlockList(t *testing.T) {
	ts, _ := reportServer(t, reportYAML)

	// Empty store → empty list, count 0.
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks", adminToken, ""))
	if m["count"] != float64(0) {
		t.Fatalf("initial list count = %v, want 0", m["count"])
	}
	if m["complete"] != true {
		t.Fatalf("initial list complete = %v, want true", m["complete"])
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

	// The endpoint is bounded and reports truncation instead of materializing
	// an attacker-inflated store in the daemon and dashboard.
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks?limit=1", adminToken, ""))
	if m["count"] != float64(1) || m["complete"] != false {
		t.Fatalf("bounded list = %v, want count=1 complete=false", m)
	}
	if resp := adminReq(t, ts, "GET", "/admin/blocks?limit=10001", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized limit status = %d, want 400", resp.StatusCode)
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
	window := m["window"].(map[string]any)
	if window["available"] != float64(3) || window["capacity"] != float64(4096) || window["full"] != false {
		t.Fatalf("decision window = %v, want 3/4096 not-full", window)
	}
	if window["started_at"] == nil || window["oldest"] == nil || window["newest"] == nil {
		t.Fatalf("decision window lacks coverage timestamps: %v", window)
	}
	if newest := ds[0].(map[string]any); newest["ip"] != "203.0.113.3" || newest["reason"] != "denylist:ip" {
		t.Fatalf("newest decision = %v, want ip=203.0.113.3 reason=denylist:ip", newest)
	}
	for _, key := range []string{"country", "city", "subdivision", "accuracy_radius_km", "asn", "as_org"} {
		if value, ok := ds[0].(map[string]any)[key]; ok {
			t.Errorf("%s present without a configured GeoIP/ASN database: %v", key, value)
		}
	}

	// limit + filters.
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?limit=2", adminToken, ""))
	if m["count"] != float64(2) {
		t.Fatalf("limit=2 count = %v, want 2", m["count"])
	}
	if m["truncated"] != true {
		t.Fatalf("limit=2 truncated = %v, want true", m["truncated"])
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?view=compact&limit=all", adminToken, ""))
	if m["count"] != float64(3) || m["truncated"] != false {
		t.Fatalf("compact decisions = %v, want all 3 untruncated", m)
	}
	compact := m["decisions"].([]any)[0].(map[string]any)
	for _, key := range []string{"time", "action", "reason"} {
		if _, ok := compact[key]; !ok {
			t.Errorf("compact decision missing %s: %v", key, compact)
		}
	}
	for _, key := range []string{"host", "ip", "method", "uri", "ua", "country", "asn"} {
		if value, ok := compact[key]; ok {
			t.Errorf("compact decision unexpectedly contains %s=%v", key, value)
		}
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?action=challenge", adminToken, ""))
	if m["count"] != float64(0) {
		t.Fatalf("action=challenge count = %v, want 0", m["count"])
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?reason=denylist", adminToken, ""))
	if m["count"] != float64(3) {
		t.Fatalf("reason=denylist count = %v, want 3", m["count"])
	}
	// ?ip= is an exact match after canonicalisation, so the dashboard's IP
	// lookup covers the full ring rather than a substring of a page of it.
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?ip=203.0.113.2", adminToken, ""))
	if m["count"] != float64(1) {
		t.Fatalf("ip=203.0.113.2 count = %v, want 1", m["count"])
	}
	if got := m["decisions"].([]any)[0].(map[string]any)["ip"]; got != "203.0.113.2" {
		t.Fatalf("ip filter returned %v, want 203.0.113.2", got)
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/decisions?ip=::ffff:203.0.113.2", adminToken, ""))
	if m["count"] != float64(1) {
		t.Fatalf("IPv4-mapped ip filter count = %v, want 1 (must canonicalise)", m["count"])
	}
	if resp := adminReq(t, ts, "GET", "/admin/decisions?ip=not-an-ip", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad ip: status = %d, want 400", resp.StatusCode)
	}
	if resp := adminReq(t, ts, "GET", "/admin/decisions?limit=bogus", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad limit: status = %d, want 400", resp.StatusCode)
	}
	if resp := adminReq(t, ts, "GET", "/admin/decisions?view=verbose", adminToken, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad view: status = %d, want 400", resp.StatusCode)
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

func TestAdminDecisionsGeoDetail(t *testing.T) {
	dir := t.TempDir()
	cityDB := inteltest.WriteCityDB(t, dir, map[string]inteltest.CityRecord{
		"203.0.113.10/32": {Country: "NL", City: "Schagen", Subdivision: "NH", AccuracyRadiusKM: 10},
		"203.0.113.11/32": {Country: "US", AccuracyRadiusKM: 1000},
	})
	asnDB := inteltest.WriteASNDB(t, dir, map[string]uint32{"203.0.113.10/32": 64500})
	yaml := reportYAML + "geoip: { location_db: " + cityDB + ", asn_db: " + asnDB + " }\n"
	ts, engine := reportServer(t, yaml)

	for _, ip := range []string{"203.0.113.10", "203.0.113.11"} {
		engine.Evaluate(context.Background(), &core.RequestContext{
			Host: "site.test", Method: "GET", URI: "/probe",
			RemoteAddr: ip, UserAgent: "curl/8",
		})
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/decisions", adminToken, ""))
	rows := map[string]map[string]any{}
	for _, value := range out["decisions"].([]any) {
		row := value.(map[string]any)
		rows[row["ip"].(string)] = row
	}

	full := rows["203.0.113.10"]
	if full["country"] != "NL" || full["city"] != "Schagen" || full["subdivision"] != "NH" {
		t.Errorf("city decision = %v, want Schagen, NH, NL", full)
	}
	if full["accuracy_radius_km"] != float64(10) || full["asn"] != float64(64500) || full["as_org"] != "Test AS" {
		t.Errorf("decision intelligence = %v, want radius 10, AS64500/Test AS", full)
	}

	partial := rows["203.0.113.11"]
	if partial["country"] != "US" || partial["accuracy_radius_km"] != float64(1000) {
		t.Errorf("country-only decision = %v, want US with radius 1000", partial)
	}
	for _, key := range []string{"city", "subdivision", "asn", "as_org"} {
		if value, ok := partial[key]; ok {
			t.Errorf("%s should be omitted when unavailable, got %v", key, value)
		}
	}

	compact := decodeJSON(t, adminReq(t, ts, http.MethodGet,
		"/admin/decisions?view=compact&limit=all", adminToken, ""))
	for _, value := range compact["decisions"].([]any) {
		row := value.(map[string]any)
		for _, key := range []string{"ip", "country", "city", "subdivision", "accuracy_radius_km", "asn", "as_org"} {
			if got, ok := row[key]; ok {
				t.Errorf("compact GeoIP decision unexpectedly contains %s=%v", key, got)
			}
		}
	}
}

func TestAdminDecisionWindowWrapsAtConfiguredSize(t *testing.T) {
	yaml := strings.Replace(reportYAML, "admin: { dashboard: true }",
		"admin: { dashboard: true, recent_size: 2 }", 1)
	ts, engine := reportServer(t, yaml)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		engine.Evaluate(context.Background(), &core.RequestContext{
			Host: "site.test", Method: "GET", URI: "/probe", RemoteAddr: ip, UserAgent: "curl/8",
		})
	}
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet,
		"/admin/decisions?view=compact&limit=all", adminToken, ""))
	if out["count"] != float64(2) || out["truncated"] != false {
		t.Fatalf("wrapped response = %v, want two retained rows and no response truncation", out)
	}
	window := out["window"].(map[string]any)
	if window["available"] != float64(2) || window["capacity"] != float64(2) || window["full"] != true {
		t.Fatalf("wrapped window = %v, want available=capacity=2 full=true", window)
	}
}

func TestAdminStatsNeverFallsBackToStoreScan(t *testing.T) {
	cfg := loadAdminReportConfig(t, reportYAML)
	base := store.NewMemory()
	st := &scanCountingStore{Store: base}
	t.Cleanup(func() { base.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)

	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/stats", adminToken, ""))
	if got := st.scans.Load(); got != 0 {
		t.Fatalf("stats performed %d store scans", got)
	}
	if m["blocks_active"] != float64(-1) || m["blocks_complete"] != false {
		t.Fatalf("unseeded block status = %v", m)
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

// TestDashboardReloadControlContract pins what the page's reload button needs
// from this server: the preflight route it asks first, the reload route it
// posts to, and the restart_required field it names the offending keys from.
// Renaming any of them server-side would leave the button posting blind, which
// is the one thing this control exists to avoid.
func TestDashboardReloadControlContract(t *testing.T) {
	ts, _ := reportServer(t, reportYAML)
	body, _ := io.ReadAll(adminReq(t, ts, "GET", "/admin/dashboard", "", "").Body)
	page := string(body)
	for _, want := range []string{"/admin/reload/preflight", "/admin/reload", "restart_required"} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard does not reference %q", want)
		}
	}
	// Ships hidden: an embedded build with no reload closure answers 503 on the
	// preflight, and the page only reveals the button after that probe passes.
	if !strings.Contains(page, `<button id="reload" hidden`) {
		t.Error("reload button is not hidden by default; a daemon without a reload closure would show a button that can only fail")
	}
}
