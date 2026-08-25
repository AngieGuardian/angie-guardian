// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"encoding/json/v2"
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
// vendored static assets) enabled. The shared adminServer helper leaves the
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

func TestDashboardUsesWAFRulesConfigFields(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, field := range []string{"waf_rules", "waf_rules_files", "waf_rules_disabled_ids"} {
		if !bytes.Contains(page, []byte(field)) {
			t.Errorf("dashboard does not consume /admin/config field %q", field)
		}
	}
}

// TestChartGeoEmbedded: the map module is embedded, self-contained and paired
// with a real atlas. chartjs-chart-geo ships no geometry, so the atlas is not
// optional decoration: without it the choropleth has nothing to draw.
func TestChartGeoEmbedded(t *testing.T) {
	geo, err := web.FS.ReadFile("vendor/chart-geo.umd.min.js")
	if err != nil {
		t.Fatalf("chart-geo.umd.min.js not embedded: %v", err)
	}
	if len(geo) < 50_000 {
		t.Fatalf("chart-geo.umd.min.js suspiciously small: %d bytes", len(geo))
	}
	// The UMD factory assigns this global; the dashboard drives it by name.
	if !bytes.Contains(geo, []byte("ChartGeo")) {
		t.Errorf("blob does not define the ChartGeo global; wrong or corrupt file")
	}
	// topojson is re-exported by the bundle, which is why no second library is
	// vendored to decode the atlas. If a future version drops it, the dashboard
	// breaks at runtime, so pin it here.
	if !bytes.Contains(geo, []byte("topojson")) {
		t.Errorf("bundle no longer re-exports topojson; the atlas cannot be decoded")
	}
	if bytes.Contains(geo, []byte("sourceMappingURL")) {
		t.Errorf("sourceMappingURL comment present; the browser would request a .map we do not serve")
	}

	atlas, err := web.FS.ReadFile("vendor/countries-110m.json")
	if err != nil {
		t.Fatalf("countries-110m.json not embedded: %v", err)
	}
	var topo struct {
		Type    string `json:"type"`
		Objects struct {
			Countries struct {
				Geometries []struct {
					ID any `json:"id"`
				} `json:"geometries"`
			} `json:"countries"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(atlas, &topo); err != nil {
		t.Fatalf("atlas is not valid JSON: %v", err)
	}
	if topo.Type != "Topology" {
		t.Errorf("atlas type = %q, want Topology", topo.Type)
	}
	if n := len(topo.Objects.Countries.Geometries); n < 150 {
		t.Errorf("atlas has %d country geometries, want ~177; wrong or truncated file", n)
	}
}

// TestChartZoomEmbedded guards the map interaction pair. The zoom UMD build
// expects Hammer as a global at load time, so both blobs are required and their
// order in dashboard.html is part of the runtime contract.
func TestChartZoomEmbedded(t *testing.T) {
	hammer, err := web.FS.ReadFile("vendor/hammer.min.js")
	if err != nil {
		t.Fatalf("hammer.min.js not embedded: %v", err)
	}
	if len(hammer) < 15_000 || !bytes.Contains(hammer[:256], []byte("Hammer.JS")) {
		t.Errorf("hammer.min.js is wrong or truncated: %d bytes", len(hammer))
	}

	zoom, err := web.FS.ReadFile("vendor/chartjs-plugin-zoom.min.js")
	if err != nil {
		t.Fatalf("chartjs-plugin-zoom.min.js not embedded: %v", err)
	}
	if len(zoom) < 10_000 || !bytes.Contains(zoom[:256], []byte("chartjs-plugin-zoom v2.2.0")) {
		t.Errorf("chartjs-plugin-zoom.min.js is wrong or truncated: %d bytes", len(zoom))
	}
	if bytes.Contains(hammer, []byte("sourceMappingURL")) || bytes.Contains(zoom, []byte("sourceMappingURL")) {
		t.Error("zoom dependency carries a sourceMappingURL; browser would request an unserved map")
	}

	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	ordered := []string{
		"chart.umd.min.js", "chart-geo.umd.min.js", "hammer.min.js",
		"chartjs-plugin-zoom.min.js",
	}
	last := -1
	for _, name := range ordered {
		at := bytes.Index(page, []byte("src=\""+name+"\""))
		if at < 0 {
			t.Fatalf("dashboard does not load %s", name)
		}
		if at <= last {
			t.Fatalf("dashboard script %s loads out of dependency order", name)
		}
		last = at
	}
}

// TestAssetsServedUnauthenticated: a <script src> or atlas fetch carries no
// Authorization header, so the assets must serve without a token (like the
// dashboard shell), with the right content type. The URLs are fixed, so they
// revalidate against a content ETag rather than caching immutably: a guardiand
// upgrade that changes a blob is picked up instead of pairing a stale library
// with new dashboard JS.
func TestAssetsServedUnauthenticated(t *testing.T) {
	ts := dashboardAdminServer(t)

	for _, tc := range []struct{ route, contentType, needle string }{
		{"/admin/chart.umd.min.js", "text/javascript; charset=utf-8", "Chart.js"},
		{"/admin/chart-geo.umd.min.js", "text/javascript; charset=utf-8", "ChartGeo"},
		{"/admin/hammer.min.js", "text/javascript; charset=utf-8", "Hammer.JS"},
		{"/admin/chartjs-plugin-zoom.min.js", "text/javascript; charset=utf-8", "chartjs-plugin-zoom"},
		{"/admin/countries-110m.json", "application/json; charset=utf-8", "Topology"},
	} {
		t.Run(tc.route, func(t *testing.T) {
			// No Authorization header — exactly how a browser fetches these.
			resp, err := http.Get(ts.URL + tc.route)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (must not require auth)", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != tc.contentType {
				t.Errorf("Content-Type = %q, want %q", ct, tc.contentType)
			}
			// Must revalidate, never a blind long-lived cache: the fixed URL is
			// reused across versions, so a year-long immutable copy could
			// outlive its blob.
			if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
				t.Errorf("Cache-Control = %q, want no-cache (revalidate, not immutable)", cc)
			}
			if resp.Header.Get("ETag") == "" {
				t.Errorf("missing ETag; the asset cannot revalidate without one")
			}
			body, _ := io.ReadAll(resp.Body)
			if !bytes.Contains(body, []byte(tc.needle)) {
				t.Errorf("served body does not contain %q; wrong asset served", tc.needle)
			}
		})
	}
}

// TestAssetsHaveDistinctETags: each asset must revalidate against its own
// content hash. A shared ETag would 304 one asset against another's hash and
// serve the browser a stale (or wrong) blob.
func TestAssetsHaveDistinctETags(t *testing.T) {
	ts := dashboardAdminServer(t)
	seen := map[string]string{}
	for route := range dashboardAssets {
		resp, err := http.Get(ts.URL + route)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Fatalf("%s: no ETag", route)
		}
		if other, dup := seen[etag]; dup {
			t.Errorf("%s and %s share ETag %s; one would 304 against the other", route, other, etag)
		}
		seen[etag] = route
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

// TestAssetsGatedOnDashboard: when admin.dashboard is off (the default), the
// static asset routes are not registered, so they 404 — no surface beyond the
// opt-in dashboard.
func TestAssetsGatedOnDashboard(t *testing.T) {
	ts, _ := adminServer(t) // dashboard NOT enabled in adminYAML
	for route := range dashboardAssets {
		resp, err := http.Get(ts.URL + route)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 when dashboard disabled", route, resp.StatusCode)
		}
	}
}

// TestDashboardHealthSurface pins the degraded-state surface the enriched
// /admin/stats payload feeds: the banner, the Store KPI tile and the System
// health card. The IDs are the contract between dashboard.html's markup and
// its script, so a rename in one half must not pass silently.
func TestDashboardHealthSurface(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, id := range []string{
		"health-banner", // "store unreachable, failing open" / amber degradation
		"t-store-tile",  // the Store KPI tile wrapper (hidden on an old server)
		"t-store",       // up / DOWN
		"t-store-sub",   // backend + how long ago it was checked
		"health-h2",     // System health heading
		"health-card",   // the card itself
		"health-rows",   // one row per component
	} {
		if !bytes.Contains(page, []byte(`id="`+id+`"`)) {
			t.Errorf("dashboard is missing the %q element the health surface renders into", id)
		}
		if !bytes.Contains(page, []byte(`$("`+id+`")`)) {
			t.Errorf("dashboard markup declares %q but no script reads it", id)
		}
	}

	// Against a server that predates this payload the three surfaces must hide
	// rather than throw, the same defensive style as the dist/offenders fetches.
	if !bytes.Contains(page, []byte("const h = stats.health;")) ||
		!bytes.Contains(page, []byte("if (!h) {")) {
		t.Error("dashboard does not guard on an absent stats.health payload")
	}

	// The health payload can carry a raw backend error, so it must never reach
	// the DOM as markup. The whole page is textContent-only by policy.
	if bytes.Contains(page, []byte("innerHTML")) {
		t.Error("dashboard uses innerHTML; health details must land via textContent")
	}

	// GET /admin/blocks is the only fetch on this page that reaches the store,
	// so it 500s during exactly the outage the health surface exists to report.
	// If it is allowed to reject the refresh, the whole dashboard blanks and
	// the banner, tile and card are never drawn. It must be caught.
	blocks := bytes.Index(page, []byte(`api("/admin/blocks?limit=1000")`))
	if blocks < 0 {
		t.Fatal("dashboard no longer fetches /admin/blocks; update this guard")
	}
	if !bytes.Contains(page[blocks:min(blocks+700, len(page))], []byte("blocksStale = true")) {
		t.Error("the /admin/blocks fetch is not caught; a store outage would blank the " +
			"dashboard instead of showing the health banner")
	}
}

func TestDashboardRecentWindowSurface(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, needle := range []string{
		`id="chart-window"`,
		`value="5m"`, `value="15m"`, `value="30m"`, `value="1h"`, `value="all"`,
		`id="chart-decisions-window"`, `id="chart-reasons-window"`,
		`api("/admin/decisions?limit=1024")`,
		`api("/admin/decisions?view=compact&limit=all")`,
		// The ring-wide fall-through behind an empty whole-IP search: without
		// it, an IP whose rows aged past the fetch window reads as never seen.
		`const probeRingForIP`,
		`"/admin/decisions?view=compact&limit=all&ip=" + encodeURIComponent(needle)`,
		`const bucketize = (records, keyFn, series, nBuckets, lo, hi)`,
		`const n = nBuckets`,
		`sessionStorage.setItem(CHART_WINDOW_KEY, chartWindow)`,
	} {
		if !bytes.Contains(page, []byte(needle)) {
			t.Errorf("dashboard recent-window surface missing %q", needle)
		}
	}
	for _, stale := range []string{
		`Math.min(...times)`,
		`api("/admin/decisions?limit=4096")`,
	} {
		if bytes.Contains(page, []byte(stale)) {
			t.Errorf("dashboard still contains data-derived/unbounded chart path %q", stale)
		}
	}
}

// Optional endpoint failures must not put old registry/offender data under a
// fresh page timestamp without qualification. The behavioural transitions are
// exercised in web/dashboard_script_test.go; these needles pin the markup and
// the render-loop wiring that make those helpers visible in the shipped page.
func TestDashboardOptionalPanelStaleSurface(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, needle := range []string{
		`id="distributions-stale"`, `id="offenders-stale"`,
		`setOptionalStatus("distributions-stale", "Registry charts", !!dist, !!lastDist)`,
		`setOptionalStatus("offenders-stale", "Offenders", false, haveOffenders)`,
		`if (dist) lastDist = dist`,
		`renderAnomalyHealth(anomaly, dist)`,
	} {
		if !bytes.Contains(page, []byte(needle)) {
			t.Errorf("dashboard optional-panel stale surface missing %q", needle)
		}
	}
	if bytes.Contains(page, []byte(`render(true)`)) {
		t.Error("a post-action handler bypasses the refresh coordinator with render(true)")
	}
	if got := bytes.Count(page, []byte(`refreshAfterAction();`)); got != 5 {
		t.Errorf("post-action refresh bindings = %d, want 5 (reload plus two block and two unblock paths)", got)
	}
	if bytes.Contains(page, []byte(`const misses = lastDist ?`)) {
		t.Error("the current anomaly banner still consumes retained distribution counters")
	}
}

// TestDashboardOffenderSurface pins the six-card markup and API bindings. The
// server tests own the counts; this catches a response-field or DOM-ID rename
// that would otherwise leave a shipped table silently blank.
func TestDashboardOffenderSurface(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, id := range []string{
		"off-ips", "off-reasons", "off-paths", "off-countries",
		"off-user-agents", "off-hosts",
	} {
		if !bytes.Contains(page, []byte(`id="`+id+`"`)) {
			t.Errorf("dashboard is missing offender table %q", id)
		}
		if !bytes.Contains(page, []byte(`fill("`+id+`"`)) {
			t.Errorf("dashboard declares offender table %q but does not render it", id)
		}
	}
	for _, needle := range []string{
		`data.user_agents || []`, `data.hosts || []`, `r.key || "(empty)"`,
		`new Intl.DisplayNames(["en"], { type: "region" })`, `countryName(r.key)`,
		`grid-template-columns: repeat(3, minmax(0, 1fr))`,
	} {
		if !bytes.Contains(page, []byte(needle)) {
			t.Errorf("dashboard offender surface missing %q", needle)
		}
	}
}

// The per-domain bar measure. A fleet's busiest domain can outweigh its
// quietest by orders of magnitude, so the card offers each domain's own action
// mix as well as raw counts.
func TestDashboardPerDomainModeSurface(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, needle := range []string{
		`id="domains-mode"`, `$("domains-mode")`,
		`<option value="count" selected>count</option>`,
		`<option value="share">share</option>`,
		`sessionStorage.setItem(DOMAINS_MODE_KEY, domainsMode)`,
		// Covered behaviourally in web/dashboard_script_test.go, pinned here so
		// the renderer keeps calling the helper those tests exercise.
		`const domainBars = (perDomain, actions, mode)`,
		`domainBars(perDomain, actions, domainsMode)`,
		// Share mode has to keep the count reachable, not replace it.
		`counts: s.counts`,
	} {
		if !bytes.Contains(page, []byte(needle)) {
			t.Errorf("dashboard per-domain mode surface missing %q", needle)
		}
	}
}

// The solve surface: the column that makes a slow proof of work attributable,
// the filter that isolates those rows, and the two cards that answer "whose
// puzzle is too hard" and "which kind of client is struggling". Pinned because
// all four are wired to field names the Go side owns; a rename that misses the
// dashboard would leave the page silently blank rather than failing a build.
func TestDashboardSolveSurface(t *testing.T) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("dashboard.html not embedded: %v", err)
	}
	for _, needle := range []string{
		`id="dec-solve"`, `id="lu-dec-solve"`,
		`<option value="solve">solve</option>`,
		`<option value="redeem_fail">redeem_fail</option>`,
		`.chip.redeem_fail::before`,
		`d.action !== "solve"`,
		`Number(d.solve_ms)`, `d.round_trip_ms`, `d.bits`,
		`id="card-solve-domains"`, `id="card-solve-clients"`,
		`lastDist.solve_time_by_domain`,
	} {
		if !bytes.Contains(page, []byte(needle)) {
			t.Errorf("dashboard solve surface missing %q", needle)
		}
	}
	// Outcome rows share the ring with the decisions, so the charts must drop
	// them: an outcome is the consequence of a challenge already in the
	// stacked area, and its reason would swamp the band that shows pow token
	// failures.
	if !bytes.Contains(page, []byte(`if (d.action === "solve" || d.action === "redeem_fail") return false;`)) {
		t.Error("the chart feed no longer filters outcome rows out; both charts would double-count")
	}
}
