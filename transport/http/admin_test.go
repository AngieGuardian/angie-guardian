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
signing_key_file: test-signing.key
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
domains:
  shop.test:
    pow: { enabled: true, base_difficulty: 5 }
    paths:
      "/api/":
        pow: { enabled: false }
`

const adminRulesYAML = `
rules:
  - id: probe
    keywords: [ "/.env" ]
  - id: scanner
    targets: [ ua ]
    keywords: [ "sqlmap" ]
`

const adminToken = "s3cret-admin-token"

func adminServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(adminRulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	// adminServer's config additionally carries a keywords domain with a rule
	// exclusion, so the config view can be asserted end to end (the other
	// adminYAML users construct their engines without a rules file on disk).
	cfgYAML := adminYAML + fmt.Sprintf(`  waf.test:
    waf:
      keywords: { enabled: true, rules_file: %q, disabled_rule_ids: [ probe ] }
`, rulesPath)
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
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
	m := metrics.New("memory")
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

	m := metrics.New("memory")
	m.Challenge("issued")
	m.Challenge("issued")
	m.Challenge("solved")
	m.Challenge("failed")
	// Two domains on purpose: solve time is a labelled histogram, so the mean
	// has to be computed over the whole family. Averaging inside the per-series
	// loop would report whichever domain the registry yielded last (1 or 3
	// here) and nothing else would fail.
	m.SolveTime("shop.test", 1.0)
	m.SolveTime("api.test", 3.0)

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
		t.Errorf("avg_solve_seconds = %v, want 2 (the mean across both domains)",
			ch["avg_solve_seconds"])
	}
}

// Outcome rows (solves and failed redemptions) share the ring with verdicts
// but are not verdicts: stats must keep them out of total/by_reason (every
// pow:* reason collapses to "pow" and would pin the top-reason tile) while
// by_action, documented as the ring's full contents, still counts them; and
// offenders must rank neither a client that paid its proof of work nor one
// whose VPN flapped mid-challenge.
func TestAdminStatsAndOffendersSkipOutcomeRows(t *testing.T) {
	const yaml = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  denylist: { ips: [ "203.0.113.9" ] }
domains:
  shop.test:
    pow: { enabled: true, base_difficulty: 5 }
`
	dir := t.TempDir()
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

	// One of each kind: a real deny verdict through the pipeline, then the two
	// outcome rows via the same entry points the transport uses.
	if d := engine.Evaluate(t.Context(), &core.RequestContext{
		Host: "shop.test", Method: "GET", URI: "/admin.php",
		RemoteAddr: "203.0.113.9", UserAgent: "curl/8",
	}); d.Action != core.ActionDeny {
		t.Fatalf("denylisted IP evaluated to %s, want deny", d.Action)
	}
	engine.RecordSolve(core.SolveRecord{Host: "shop.test", IP: "198.51.100.7", URI: "/", UA: "Mozilla/5.0", Bits: 20})
	engine.RecordRedeemFailure("shop.test", "198.51.100.44", "Mozilla/5.0", core.ReasonBindingMismatch)

	ts := httptest.NewServer(NewAdminServer(engine, cfg, metrics.New("memory"), adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)

	stats := decodeJSON(t, adminReq(t, ts, "GET", "/admin/stats", adminToken, ""))
	recent, ok := stats["recent"].(map[string]any)
	if !ok {
		t.Fatalf("stats has no recent rollup: %v", stats)
	}
	if recent["total"] != 1.0 {
		t.Errorf("recent.total = %v, want 1 (the deny; outcome rows are not verdicts)", recent["total"])
	}
	byAction, _ := recent["by_action"].(map[string]any)
	if byAction["deny"] != 1.0 || byAction[core.ActionSolve] != 1.0 || byAction[core.ActionRedeemFail] != 1.0 {
		t.Errorf("by_action = %v, want deny/solve/redeem_fail 1 each (the ring's full contents)", byAction)
	}
	byReason, _ := recent["by_reason"].(map[string]any)
	if len(byReason) != 1 || byReason["denylist"] != 1.0 {
		t.Errorf("by_reason = %v, want only denylist:1", byReason)
	}

	off := decodeJSON(t, adminReq(t, ts, "GET", "/admin/offenders", adminToken, ""))
	if off["window"] != 1.0 {
		t.Errorf("offenders window = %v, want 1", off["window"])
	}
	ips, _ := off["ips"].([]any)
	if len(ips) != 1 {
		t.Fatalf("offender ips = %v, want exactly the denied IP", off["ips"])
	}
	if row, _ := ips[0].(map[string]any); row["ip"] != "203.0.113.9" {
		t.Errorf("offender = %v, want 203.0.113.9", row)
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
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/blocks/1.2.3.4", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "xxxxxxx"+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong auth scheme: status = %d, want 401", resp.StatusCode)
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

// GET /admin/reload/preflight tells a reloadable on-disk edit from one SIGHUP
// would reject, without applying anything.
func TestAdminReloadPreflight(t *testing.T) {
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

	var changed []string
	var preflightErr error
	admin := NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default())
	admin.SetPreflight(func() ([]string, error) { return changed, preflightErr })
	ts := httptest.NewServer(admin)
	t.Cleanup(ts.Close)

	if resp := adminReq(t, ts, "GET", "/admin/reload/preflight", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", resp.StatusCode)
	}

	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/reload/preflight", adminToken, ""))
	if m["reloadable"] != true {
		t.Errorf("clean preflight: %v, want reloadable=true", m)
	}
	if fields, ok := m["restart_required"].([]any); !ok || len(fields) != 0 {
		t.Errorf("clean preflight restart_required = %v, want an empty list (not null)", m["restart_required"])
	}

	changed = []string{"listen", "store.backend"}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/reload/preflight", adminToken, ""))
	if m["reloadable"] != false {
		t.Errorf("static-change preflight: %v, want reloadable=false", m)
	}
	if fields, _ := m["restart_required"].([]any); len(fields) != 2 {
		t.Errorf("restart_required = %v, want both changed fields", m["restart_required"])
	}

	// An unloadable on-disk config is reported as the reason SIGHUP would fail.
	changed, preflightErr = nil, fmt.Errorf("parse guardian.yaml: boom")
	resp := adminReq(t, ts, "GET", "/admin/reload/preflight", adminToken, "")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("broken config preflight: status = %d, want 422", resp.StatusCode)
	}
	if m := decodeJSON(t, resp); m["reloadable"] != false || m["error"] == "" {
		t.Errorf("broken config preflight body: %v", m)
	}

	// Not wired → 503, like reload.
	tsNil, _ := adminServer(t)
	if resp := adminReq(t, tsNil, "GET", "/admin/reload/preflight", adminToken, ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("nil preflight: status = %d, want 503", resp.StatusCode)
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
	// Unblock. It also clears the counters that could re-block the IP, and
	// reports what it addressed.
	m = decodeJSON(t, adminReq(t, ts, "DELETE", "/admin/blocks/"+ip, adminToken, ""))
	reset, ok := m["reset"].(map[string]any)
	if !ok {
		t.Fatalf("DELETE response has no reset object: %v", m)
	}
	if reset["backoff_reset"] != true {
		t.Errorf("backoff_reset = %v, want true by default", reset["backoff_reset"])
	}
	if n, _ := reset["event_keys"].(float64); n == 0 {
		t.Errorf("event_keys = %v, want the configured thresholds to be addressed", reset["event_keys"])
	}
	if reset["incomplete"] != nil {
		t.Errorf("incomplete = %v against a healthy store", reset["incomplete"])
	}
	m = decodeJSON(t, adminReq(t, ts, "GET", "/admin/blocks/"+ip, adminToken, ""))
	if m["blocked"] != false {
		t.Fatalf("after DELETE: blocked = %v, want false", m["blocked"])
	}

	// reset_backoff=false keeps the repeat-offender ladder.
	adminReq(t, ts, "PUT", "/admin/blocks/"+ip, adminToken, `{"reason":"manual"}`)
	m = decodeJSON(t, adminReq(t, ts, "DELETE", "/admin/blocks/"+ip+"?reset_backoff=false", adminToken, ""))
	if reset, _ := m["reset"].(map[string]any); reset["backoff_reset"] != false {
		t.Errorf("reset_backoff=false: backoff_reset = %v, want false", reset["backoff_reset"])
	}

	// Anything that is not a boolean is a client error, not a silent default.
	resp := adminReq(t, ts, "DELETE", "/admin/blocks/"+ip+"?reset_backoff=maybe", adminToken, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reset_backoff=maybe: status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminBlockCanonicalizesIPv6(t *testing.T) {
	ts, _ := adminServer(t)
	raw := "2001:0DB8:0:0:0:0:0:1"
	canonical := "2001:db8::1"
	m := decodeJSON(t, adminReq(t, ts, http.MethodPut, "/admin/blocks/"+raw, adminToken, `{"reason":"ipv6"}`))
	if m["ip"] != canonical || m["blocked"] != true {
		t.Fatalf("PUT response = %v, want canonical blocked IP", m)
	}
	m = decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/blocks/"+canonical, adminToken, ""))
	if m["ip"] != canonical || m["blocked"] != true || m["reason"] != "ipv6" {
		t.Fatalf("canonical GET response = %v", m)
	}
	m = decodeJSON(t, adminReq(t, ts, http.MethodDelete, "/admin/blocks/"+raw, adminToken, ""))
	if m["ip"] != canonical || m["blocked"] != false {
		t.Fatalf("expanded DELETE response = %v", m)
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
		{"oversized ttl", "203.0.113.15", `{"ttl":"8761h"}`},
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
	ts := httptest.NewServer(NewAdminServer(engine, cfg, metrics.New("memory"), adminToken, keyPath, "", nil, slog.Default()))
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

// admin.metrics_auth puts /metrics behind the bearer token while /healthz and
// /readyz stay open for orchestrators that hold no secret.
func TestAdminMetricsAuthOptIn(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	yaml := "admin: { metrics_auth: true }\n" + adminYAML
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var st store.Store = store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(dir, "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New("memory")
	engine, err := core.NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	ts := httptest.NewServer(NewAdminServer(engine, cfg, m, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)

	if resp := adminReq(t, ts, "GET", "/metrics", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics without token: status = %d, want 401", resp.StatusCode)
	}
	if resp := adminReq(t, ts, "GET", "/metrics", "wrong-token", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics with wrong token: status = %d, want 401", resp.StatusCode)
	}
	if resp := adminReq(t, ts, "GET", "/metrics", adminToken, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("metrics with token: status = %d, want 200", resp.StatusCode)
	}
	if resp := adminReq(t, ts, "GET", "/healthz", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz must stay unauthenticated: status = %d, want 200", resp.StatusCode)
	}
	// No health checker is attached here, so /readyz reports not-ready (503);
	// what matters is that it never demands the bearer token.
	if resp := adminReq(t, ts, "GET", "/readyz", "", ""); resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("/readyz must stay unauthenticated: status = %d", resp.StatusCode)
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

func TestAdminAnomalyHealthWithoutConfiguredModel(t *testing.T) {
	ts, _ := adminServer(t)
	m := decodeJSON(t, adminReq(t, ts, "GET", "/admin/anomaly", adminToken, ""))
	if models, ok := m["models"].([]any); !ok || len(models) != 0 {
		t.Fatalf("models = %v, want empty array", m["models"])
	}
	scopes, ok := m["scopes"].([]any)
	if !ok || len(scopes) == 0 {
		t.Fatalf("scopes = %v, want configured scopes", m["scopes"])
	}
	for _, scope := range scopes {
		if mode := scope.(map[string]any)["mode"]; mode != "off" {
			t.Fatalf("anomaly mode = %v, want off", mode)
		}
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

	// Path overlays are visible, with the fields they override.
	shop, ok := m["domains"].(map[string]any)["shop.test"].(map[string]any)
	if !ok {
		t.Fatalf("config view missing shop.test: %v", m["domains"])
	}
	if shop["pow_enabled"] != true || shop["pow_base_difficulty"] != 5.0 {
		t.Errorf("shop.test view = %v, want pow enabled at base 5", shop)
	}
	api, ok := shop["paths"].(map[string]any)["/api/"].(map[string]any)
	if !ok {
		t.Fatalf("shop.test view missing /api/ overlay: %v", shop["paths"])
	}
	if api["pow_enabled"] != false {
		t.Errorf("/api/ overlay pow_enabled = %v, want false", api["pow_enabled"])
	}
	if _, nested := api["paths"]; nested {
		t.Error("path overlay view must not carry a nested paths field")
	}

	// The effective rules file and its exclusions are inspectable together.
	waf, ok := m["domains"].(map[string]any)["waf.test"].(map[string]any)
	if !ok {
		t.Fatalf("config view missing waf.test: %v", m["domains"])
	}
	if waf["waf_keywords"] != true {
		t.Errorf("waf.test waf_keywords = %v, want true", waf["waf_keywords"])
	}
	if file, _ := waf["waf_rules_file"].(string); !strings.HasSuffix(file, "rules.yaml") {
		t.Errorf("waf.test waf_rules_file = %v, want the configured rules file", waf["waf_rules_file"])
	}
	ids, ok := waf["waf_disabled_rule_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != "probe" {
		t.Errorf("waf.test waf_disabled_rule_ids = %v, want [probe]", waf["waf_disabled_rule_ids"])
	}
	// Scopes without exclusions omit the field instead of showing null.
	if _, present := shop["waf_disabled_rule_ids"]; present {
		t.Error("shop.test must omit waf_disabled_rule_ids")
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
geoip: { location_db: %s }
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
	if intelView["location_db"] == nil {
		t.Fatal("intel status missing location_db")
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
