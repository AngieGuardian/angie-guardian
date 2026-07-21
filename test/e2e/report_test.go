// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The "WAF report" surface Guardian exposes is Prometheus /metrics plus the
// admin API JSON. These tests drive a known action and assert the relevant
// counter moved (deltas, so they're order-independent), and that the admin API
// reflects live state.

// TestMetricsDecisionsCounter drives a WAF deny through Angie and asserts the
// guardian_decisions_total{action="deny"} counter incremented by at least the
// requests we made.
func TestMetricsDecisionsCounter(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)

	before := metric(t, "guardian_decisions_total", `action="deny"`)

	// A deny (not block, to avoid poisoning): two wp-login probes.
	for range 2 {
		if r := get(t, "/wp-login.php", powHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 deny, got %d", r.StatusCode)
		}
	}

	after := metric(t, "guardian_decisions_total", `action="deny"`)
	if after < before+2 {
		t.Fatalf("guardian_decisions_total{action=deny}: %v → %v, want +2 or more", before, after)
	}
}

// TestMetricsChallengeLifecycle drives a full challenge→solve through Angie and
// asserts both the "issued" and "solved" challenge outcomes are counted.
func TestMetricsChallengeLifecycle(t *testing.T) {
	issuedBefore := metric(t, "guardian_challenges_total", `outcome="issued"`)
	solvedBefore := metric(t, "guardian_challenges_total", `outcome="solved"`)

	// One complete solve through Angie bumps issued (the /challenge fetch) and
	// solved (the successful /pass).
	_ = solvePoWThroughAngie(t, "/metrics-solve", powHost, browserUA+" m")

	if got := metric(t, "guardian_challenges_total", `outcome="issued"`); got < issuedBefore+1 {
		t.Errorf("challenges issued: %v → %v, want +1", issuedBefore, got)
	}
	if got := metric(t, "guardian_challenges_total", `outcome="solved"`); got < solvedBefore+1 {
		t.Errorf("challenges solved: %v → %v, want +1", solvedBefore, got)
	}
}

// TestMetricsBlocksPlaced drives a WAF `block` and asserts the blocks-placed
// counter incremented.
func TestMetricsBlocksPlaced(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	before := metric(t, "guardian_blocks_placed_total")
	if r := get(t, "/.env", powHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("/.env: status %d, want 403", r.StatusCode)
	}
	if after := metric(t, "guardian_blocks_placed_total"); after < before+1 {
		t.Fatalf("guardian_blocks_placed_total: %v → %v, want +1", before, after)
	}
}

// TestAdminConfigReflectsDomains asserts the admin /admin/config view reflects
// the per-domain policy the harness config declares: PoW on for localhost, off
// for api.localhost.
func TestAdminConfigReflectsDomains(t *testing.T) {
	resp := adminReq(t, http.MethodGet, "/admin/config", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/config: status %d, want 200", resp.StatusCode)
	}
	var cfg struct {
		Store   string `json:"store"`
		Domains map[string]struct {
			PoWEnabled bool `json:"pow_enabled"`
			Keywords   bool `json:"waf_keywords"`
		} `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode /admin/config: %v", err)
	}
	if cfg.Store != "pebble" {
		t.Errorf("store = %q, want pebble (harness config)", cfg.Store)
	}
	if d, ok := cfg.Domains["localhost"]; !ok || !d.PoWEnabled {
		t.Errorf("localhost pow_enabled = %+v, want present and true", d)
	}
	if d, ok := cfg.Domains["api.localhost"]; !ok || d.PoWEnabled {
		t.Errorf("api.localhost pow_enabled = %+v, want present and false", d)
	}
}

// TestAdminAuthRequired confirms the admin API rejects an unauthenticated
// request (defense-in-depth for the internal listener).
func TestAdminAuthRequired(t *testing.T) {
	resp, err := noRedirect.Get(admin + "/admin/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/admin/config without token: status %d, want 401", resp.StatusCode)
	}
}

// TestAdminAngieRelaysZones drives real traffic through Angie, then asserts
// GET /admin/angie relays Angie's own status zones (the dashboard's real-traffic
// panel). Proves the end-to-end proxy against a real Angie API, not a mock.
func TestAdminAngieRelaysZones(t *testing.T) {
	// Generate traffic so Angie's per-host status_zone has non-zero counters.
	// A handful of requests through the protected site is enough.
	for range 3 {
		_ = solvePoWThroughAngie(t, "/angie-zone", powHost, browserUA+" z")
	}

	resp := adminReq(t, http.MethodGet, "/admin/angie", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/angie: status %d, want 200", resp.StatusCode)
	}
	var out struct {
		Enabled     bool            `json:"enabled"`
		Error       string          `json:"error"`
		ServerZones json.RawMessage `json:"server_zones"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /admin/angie: %v", err)
	}
	if !out.Enabled {
		t.Fatalf("enabled = false, want true (angie_api configured in guardian.e2e.yaml)")
	}
	if out.Error != "" {
		t.Fatalf("angie api error: %q (is the api listener up in angie.docker.conf?)", out.Error)
	}
	// server_zones must be a non-empty object carrying the protected host.
	var zones map[string]json.RawMessage
	if err := json.Unmarshal(out.ServerZones, &zones); err != nil {
		t.Fatalf("server_zones is not an object: %v", err)
	}
	if len(zones) == 0 {
		t.Fatalf("server_zones is empty; expected at least one status_zone with traffic")
	}
}

// TestAdminAngieDegradesGracefully: the report endpoint always answers 200 with
// an enabled flag, so a misconfigured or down Angie API never breaks the
// dashboard render. (Here the API is up, so we just assert the contract shape.)
func TestAdminAngieContract(t *testing.T) {
	resp := adminReq(t, http.MethodGet, "/admin/angie", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/angie: status %d, want 200 always", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := out["enabled"]; !ok {
		t.Errorf("response missing the 'enabled' flag: %v", out)
	}
}

// TestDecisionLogsAreStructured asserts guardiand emits structured decision log
// lines (the audit trail a log pipeline / SIEM ingests): a deny should appear
// with its reason in the container logs.
func TestDecisionLogsAreStructured(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)

	// Drive a distinctive deny, then look for it in the logs.
	if r := get(t, "/xmlrpc.php", powHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("/xmlrpc.php: status %d, want 403", r.StatusCode)
	}
	logs := guardiandLogs(t)
	if !strings.Contains(logs, "decision") || !strings.Contains(logs, "waf:wp-probe") {
		t.Errorf("expected a structured decision log line mentioning waf:wp-probe; recent logs:\n%s",
			tail(logs, 2000))
	}
}

// tail returns the last n bytes of s (for readable failure output).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// TestAdminBlockListAndDecisions covers the dashboard's data endpoints: after a
// WAF `block`, GET /admin/blocks lists the blocked source IP and GET
// /admin/decisions shows the deny, and /admin/stats rolls both up.
func TestAdminBlockListAndDecisions(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	// One instant-block probe (dotfile-probe) through Angie.
	if r := get(t, "/.git/config", powHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("/.git/config: status %d, want 403", r.StatusCode)
	}

	// /admin/blocks lists the gateway IP with the rule as reason and a TTL.
	resp := adminReq(t, http.MethodGet, "/admin/blocks", nil)
	var bl struct {
		Count  int `json:"count"`
		Blocks []struct {
			IP        string  `json:"ip"`
			Reason    string  `json:"reason"`
			ExpiresAt *string `json:"expires_at"`
		} `json:"blocks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bl); err != nil {
		t.Fatalf("decode /admin/blocks: %v", err)
	}
	if bl.Count < 1 {
		t.Fatal("/admin/blocks lists nothing after a WAF block")
	}
	var found bool
	for _, b := range bl.Blocks {
		if strings.Contains(b.Reason, "dotfile-probe") {
			found = true
			if b.ExpiresAt == nil {
				t.Error("behavioural block should carry expires_at")
			}
		}
	}
	if !found {
		t.Fatalf("no dotfile-probe block in %+v", bl.Blocks)
	}

	// /admin/decisions has the deny, newest first, with the request details.
	resp = adminReq(t, http.MethodGet, "/admin/decisions?action=deny&reason=waf&limit=10", nil)
	var dl struct {
		Count     int `json:"count"`
		Decisions []struct {
			URI    string `json:"uri"`
			Reason string `json:"reason"`
			Action string `json:"action"`
		} `json:"decisions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dl); err != nil {
		t.Fatalf("decode /admin/decisions: %v", err)
	}
	if dl.Count < 1 || !strings.Contains(dl.Decisions[0].URI, "/.git/config") {
		t.Fatalf("decisions = %+v, want the /.git/config deny first", dl.Decisions)
	}

	// /admin/stats reflects the same activity.
	resp = adminReq(t, http.MethodGet, "/admin/stats", nil)
	var st struct {
		BlocksActive int `json:"blocks_active"`
		Recent       struct {
			Total    int            `json:"total"`
			ByAction map[string]int `json:"by_action"`
		} `json:"recent"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode /admin/stats: %v", err)
	}
	if st.BlocksActive < 1 || st.Recent.ByAction["deny"] < 1 {
		t.Fatalf("stats = %+v, want ≥1 active block and ≥1 recent deny", st)
	}
}

// TestDashboardServed confirms the reporting page is up (the harness enables
// admin.dashboard) and is the static shell: no token required for the shell,
// while its data endpoints stay guarded (TestAdminAuthRequired).
func TestDashboardServed(t *testing.T) {
	resp := req(t, http.MethodGet, admin+"/admin/dashboard", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/dashboard: status %d, want 200", resp.StatusCode)
	}
	body := bodyOf(t, resp)
	if !strings.Contains(body, "Guardian dashboard") || !strings.Contains(body, "/admin/stats") {
		t.Fatalf("dashboard page content unexpected:\n%s", tail(body, 500))
	}
}

// TestReadinessAndStoreHealth walks the operator surface issue #13 added,
// through the real stack: the open readiness endpoint, the store_up gauge and
// the probe counter. It also pins the two invariants that make the background
// probe safe to run: readiness must stay distinct from liveness, and the
// synthetic probe traffic must not inflate the operational store counters.
func TestReadinessAndStoreHealth(t *testing.T) {
	// /readyz is open like /healthz: a load balancer or an orchestrator probes
	// it without a bearer token.
	resp := req(t, http.MethodGet, admin+"/readyz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200 against a healthy stack", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("/readyz Cache-Control = %q, want no-store", got)
	}
	var ready struct {
		Ready bool `json:"ready"`
		Store struct {
			Probed  bool   `json:"probed"`
			Up      bool   `json:"up"`
			Backend string `json:"backend"`
		} `json:"store"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ready); err != nil {
		t.Fatalf("decode /readyz: %v", err)
	}
	if !ready.Ready || !ready.Store.Up || !ready.Store.Probed {
		t.Fatalf("/readyz body = %+v, want a probed, up store", ready)
	}
	if ready.Store.Backend != "pebble" {
		t.Errorf("store backend = %q, want pebble (guardian.e2e.yaml)", ready.Store.Backend)
	}

	// The gauge the shipped GuardianStoreDown alert rule fires on.
	if got := metric(t, "guardian_store_up", `backend="pebble"`); got != 1 {
		t.Errorf("guardian_store_up{backend=pebble} = %v, want 1", got)
	}
	if got := metric(t, "guardian_store_probe_total", `backend="pebble"`, `status="ok"`); got < 1 {
		t.Errorf("guardian_store_probe_total{status=ok} = %v, want at least one completed probe", got)
	}
	if got := metric(t, "guardian_store_probe_total", `backend="pebble"`, `status="error"`); got != 0 {
		t.Errorf("guardian_store_probe_total{status=error} = %v, want 0 against a healthy store", got)
	}

	// The checker probes the raw store, not the instrumented wrapper, so its
	// periodic Set/Get must never show up here. Without that separation the
	// probe would add a steady ~12 ops/min of synthetic traffic to every
	// operational store panel and to the attack detector's error/slow ratios.
	//
	// Scoped to the two ops the probe actually performs. Other background loops
	// legitimately keep touching the instrumented store while we wait (the
	// enforcement reconcile scans on its own ticker), so a total-ops assertion
	// would be measuring them, not the probe.
	probeOps := func() float64 {
		return metric(t, "guardian_store_ops_total", `op="get"`) +
			metric(t, "guardian_store_ops_total", `op="set"`)
	}
	beforeOps := probeOps()
	beforeProbes := metric(t, "guardian_store_probe_total", `backend="pebble"`)
	deadline := time.Now().Add(45 * time.Second)
	for metric(t, "guardian_store_probe_total", `backend="pebble"`) < beforeProbes+2 {
		if time.Now().After(deadline) {
			t.Fatalf("probe counter did not advance past %v; the probe loop is not running", beforeProbes)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// No request traffic is driven here and a /metrics scrape does no store
	// I/O, so any growth would be the probe leaking into these counters.
	if after := probeOps(); after != beforeOps {
		t.Errorf("guardian_store_ops_total{op=get|set} moved %v → %v across two health "+
			"probes; the checker is probing the instrumented store", beforeOps, after)
	}

	// Liveness must not follow the store, or a store outage would kill
	// containers that are still (fail-open) serving.
	if r := req(t, http.MethodGet, admin+"/healthz", nil, nil); r.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", r.StatusCode)
	}
}

// TestAdminStatsHealthObject: the authenticated rollup carries the detail the
// dashboard needs and /readyz deliberately withholds.
func TestAdminStatsHealthObject(t *testing.T) {
	resp := adminReq(t, http.MethodGet, "/admin/stats", nil)
	var stats struct {
		Health struct {
			Store struct {
				Probed  bool    `json:"probed"`
				Up      bool    `json:"up"`
				Backend string  `json:"backend"`
				Latency float64 `json:"latency_ms"`
			} `json:"store"`
			StoreOps map[string]float64 `json:"store_ops"`
			Shed     map[string]float64 `json:"shed"`
			Fallback map[string]float64 `json:"pow_fallback"`
		} `json:"health"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode /admin/stats: %v", err)
	}
	h := stats.Health
	if !h.Store.Probed || !h.Store.Up || h.Store.Backend != "pebble" {
		t.Errorf("health.store = %+v, want a probed, up pebble store", h.Store)
	}
	if h.StoreOps == nil || h.Shed == nil || h.Fallback == nil {
		t.Errorf("health is missing a counter block: %+v", h)
	}
	if _, ok := h.StoreOps["total"]; !ok {
		t.Errorf("health.store_ops = %v, want a total", h.StoreOps)
	}
}
