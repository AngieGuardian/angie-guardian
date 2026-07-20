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
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// metricsAdminServer builds an admin server and returns the metrics handle so a
// test can seed histograms/counters, then read them back through the endpoint.
func metricsAdminServer(t *testing.T) (*httptest.Server, *metrics.Metrics) {
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
	return ts, m
}

// TestDistributionsRequiresAuth: the endpoint reads internal metrics, so like
// every other /admin API it must reject an unauthenticated request.
func TestDistributionsRequiresAuth(t *testing.T) {
	ts, _ := adminServer(t)
	resp := adminReq(t, ts, http.MethodGet, "/admin/distributions", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}
}

// TestDistributionsEmptyShape: with nothing recorded, the endpoint still returns
// a well-formed, zero-valued payload (so the dashboard renders empty charts, not
// an error).
func TestDistributionsEmptyShape(t *testing.T) {
	ts, _ := metricsAdminServer(t)
	resp := adminReq(t, ts, http.MethodGet, "/admin/distributions", adminToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeJSON(t, resp)
	for _, key := range []string{"solve_time", "anomaly"} {
		h, ok := out[key].(map[string]any)
		if !ok {
			t.Fatalf("%s missing or not an object: %v", key, out[key])
		}
		if _, ok := h["buckets"].([]any); !ok {
			t.Errorf("%s.buckets is not an array: %v", key, h["buckets"])
		}
		if _, ok := h["sum"]; !ok {
			t.Errorf("%s.sum missing", key)
		}
		if _, ok := h["count"]; !ok {
			t.Errorf("%s.count missing", key)
		}
	}
	if _, ok := out["per_domain"].(map[string]any); !ok {
		t.Errorf("per_domain is not an object: %v", out["per_domain"])
	}
}

// TestDistributionsBuckets: after seeding known solve-times, anomaly scores and
// per-domain decisions, the endpoint reports per-bucket (non-cumulative) counts
// and per-domain totals. Guards the cumulative→per-bucket conversion.
func TestDistributionsBuckets(t *testing.T) {
	ts, m := metricsAdminServer(t)

	// Solve-time buckets are {0.05,0.1,0.25,0.5,1,2,5,10,30}. Record one obs in
	// distinct buckets: 0.2 (→ le=0.25), 0.7 (→ le=1), 3 (→ le=5).
	m.SolveTime(0.2)
	m.SolveTime(0.7)
	m.SolveTime(3)
	// Anomaly scores across two domains, summed into one distribution.
	m.AnomalyScore("shop.test", 0.15)
	m.AnomalyScore("shop.test", 0.85)
	m.AnomalyScore("api.test", 0.45)
	// Per-domain decisions, allow-inclusive.
	m.Decision("allow", "default", "shop.test")
	m.Decision("allow", "default", "shop.test")
	m.Decision("challenge", "pow", "shop.test")
	m.Decision("deny", "waf", "api.test")

	resp := adminReq(t, ts, http.MethodGet, "/admin/distributions", adminToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeJSON(t, resp)

	// Solve-time: 3 observations total, and the per-bucket counts must sum to 3
	// (proving we de-cumulated correctly rather than double-counting).
	st := out["solve_time"].(map[string]any)
	if got := st["count"].(float64); got != 3 {
		t.Errorf("solve_time.count = %v, want 3", got)
	}
	var bucketSum float64
	for _, b := range st["buckets"].([]any) {
		bucketSum += b.(map[string]any)["count"].(float64)
	}
	if bucketSum != 3 {
		t.Errorf("solve_time per-bucket counts sum to %v, want 3 (cumulative not de-cumulated?)", bucketSum)
	}

	// Anomaly: 3 observations summed across the two domains.
	an := out["anomaly"].(map[string]any)
	if got := an["count"].(float64); got != 3 {
		t.Errorf("anomaly.count = %v, want 3 (domains not merged?)", got)
	}

	// Per-domain, allow-inclusive.
	pd := out["per_domain"].(map[string]any)
	shop := pd["shop.test"].(map[string]any)
	if shop["allow"].(float64) != 2 || shop["challenge"].(float64) != 1 {
		t.Errorf("shop.test totals = %v, want allow=2 challenge=1", shop)
	}
	api := pd["api.test"].(map[string]any)
	if api["deny"].(float64) != 1 {
		t.Errorf("api.test deny = %v, want 1", api["deny"])
	}
}
