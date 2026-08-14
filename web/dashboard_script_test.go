// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// The dashboard carries real logic in its inline script (UA classification,
// bucket quantiles, rollups over the decisions feed) and until now the only
// coverage was string needles in transport/http/admin_assets_test.go, which
// prove a line exists and nothing about what it does. These tests lift named
// top-level declarations out of dashboard.html and run them in goja, a pure-Go
// JS interpreter, so the behaviour is testable without a browser, a headless
// Chrome or a node binary in CI.
//
// Only self-contained declarations can be lifted: anything reaching for the
// network, Chart.js or a real DOM stays out of scope. What the harness stubs
// (the $ / el / row / td builders) it stubs faithfully enough that the lifted
// code is unmodified.

// jsDecl returns the source of the top-level `const NAME = ...` declaration
// from the dashboard's IIFE, which is uniformly indented by two spaces. A
// declaration therefore ends either on its own line (`const X = 5;`) or at the
// first following line whose closing bracket sits back at that indent. Failing
// loudly on a miss is the point: renaming one of these in dashboard.html must
// break the test rather than silently stop covering it.
func jsDecl(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n  const "+name+" = ")
	if start < 0 {
		t.Fatalf("dashboard.html no longer declares %q at the top level of its script", name)
	}
	lines := strings.Split(src[start+1:], "\n")
	if strings.HasSuffix(strings.TrimSpace(lines[0]), ";") {
		return lines[0]
	}
	for i := 1; i < len(lines); i++ {
		trimmed := strings.TrimLeft(lines[i], " ")
		indent := len(lines[i]) - len(trimmed)
		if indent == 2 && (strings.HasPrefix(trimmed, "}") || strings.HasPrefix(trimmed, "]")) {
			return strings.Join(lines[:i+1], "\n")
		}
	}
	t.Fatalf("could not find the end of %q in dashboard.html", name)
	return ""
}

// jsConstNames lists the top-level SCREAMING_CASE constants whose names
// contain word, so a test can lift "whatever thresholds the solve rollup
// currently has" without being coupled to how they are spelled or how many
// there are.
func jsConstNames(src, word string) []string {
	re := regexp.MustCompile(`(?m)^  const ([A-Z][A-Z0-9_]*` + word + `[A-Z0-9_]*) = `)
	var names []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		names = append(names, m[1])
	}
	return names
}

// dashboardSource reads the page out of the same embedded FS the admin server
// serves, so a test can never pass against a copy that is not shipped.
func dashboardSource(t *testing.T) string {
	t.Helper()
	b, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDashboardDeepLinkWaitsForInitialRender keeps a refresh-time IP lookup
// from scrolling against the short pre-render document. A button click starts
// after layout already exists, but a ?ip= navigation does not.
func TestDashboardDeepLinkWaitsForInitialRender(t *testing.T) {
	src := dashboardSource(t)
	linked := strings.Index(src, `const linked = new URLSearchParams(location.search).get("ip");`)
	deferred := strings.Index(src, `tick().finally(() => { if (linked) openLookup(linked); });`)
	if linked < 0 || deferred < 0 || deferred < linked {
		t.Fatal("dashboard deep link must open only after the initial tick settles")
	}
}

// jsRuntime builds a goja runtime holding the DOM stubs plus the named
// declarations, in the order given (they are hoisted as consts, so order is
// dependency order).
func jsRuntime(t *testing.T, decls ...string) *goja.Runtime {
	t.Helper()
	src := dashboardSource(t)
	vm := goja.New()
	// Minimal stand-ins for the page's DOM builders. A node records what the
	// renderers assign to it; replaceChildren keeps the rows so a test can read
	// the rendered table back as data.
	const stubs = `
	  var nodes = {};
	  var $ = function (id) {
	    if (!nodes[id]) {
	      nodes[id] = {
	        id: id, hidden: false, textContent: "", title: "", children: [],
	        getContext: function () { return {}; },
	        replaceChildren: function () { this.children = Array.prototype.slice.call(arguments); },
	      };
	    }
	    return nodes[id];
	  };
	  var el = function (tag, cls, text) {
	    return {
	      tag: tag, cls: cls || "", className: cls || "",
	      text: text === undefined ? "" : String(text), title: "", children: [],
	      appendChild: function (child) { this.children.push(child); },
	    };
	  };
	  var row = function () { return { tag: "tr", cells: Array.prototype.slice.call(arguments) }; };
	  var td = function (cls, text) { return el("td", cls, text); };
	  var lastDecisions = [];
	  var lastDist = null;
	  var reset = function () { nodes = {}; lastDecisions = []; lastDist = null; };
	`
	if _, err := vm.RunString(stubs); err != nil {
		t.Fatalf("harness stubs: %v", err)
	}
	for _, name := range decls {
		code := jsDecl(t, src, name)
		if _, err := vm.RunString(code); err != nil {
			t.Fatalf("running %s from dashboard.html: %v", name, err)
		}
	}
	return vm
}

// TestRefreshCoordinatorQueuesPostActionRefresh pins the distinction between
// timer ticks and operator actions. A timer overlap is expendable, but a block,
// unblock or reload must run once the older render finishes or that older
// response can land last and roll the dashboard back to pre-action data.
func TestRefreshCoordinatorQueuesPostActionRefresh(t *testing.T) {
	vm := jsRuntime(t, "makeRefreshCoordinator")
	if _, err := vm.RunString(`
	  var calls = [], pending = [], active = 0, maxActive = 0, errors = [];
	  var coordinator = makeRefreshCoordinator(function (refreshBlocks) {
	    calls.push(refreshBlocks);
	    active++;
	    maxActive = Math.max(maxActive, active);
	    return new Promise(function (resolve) {
	      pending.push(function () { active--; resolve(); });
	    });
	  }, function (err) { errors.push(String(err)); });
	  coordinator.scheduled();
	  coordinator.scheduled(); // overlapping timer tick: drop it
	  coordinator.forced(false);
	  coordinator.forced(true); // coalesce and preserve refreshBlocks=true
	`); err != nil {
		t.Fatal(err)
	}

	var during struct {
		Calls     []bool `json:"calls"`
		Pending   int    `json:"pending"`
		MaxActive int    `json:"maxActive"`
	}
	call(t, vm, `({ calls: calls, pending: pending.length, maxActive: maxActive })`, &during)
	if fmt.Sprint(during.Calls) != "[false]" || during.Pending != 1 || during.MaxActive != 1 {
		t.Fatalf("overlapping requests were not coalesced: %+v", during)
	}

	if _, err := vm.RunString(`pending.shift()();`); err != nil {
		t.Fatal(err)
	}
	var queued struct {
		Calls     []bool `json:"calls"`
		Pending   int    `json:"pending"`
		MaxActive int    `json:"maxActive"`
	}
	call(t, vm, `({ calls: calls, pending: pending.length, maxActive: maxActive })`, &queued)
	if fmt.Sprint(queued.Calls) != "[false true]" || queued.Pending != 1 || queued.MaxActive != 1 {
		t.Fatalf("forced follow-up did not run serially with block refresh: %+v", queued)
	}
}

func TestOptionalStatusDistinguishesUnavailableAndStale(t *testing.T) {
	vm := jsRuntime(t, "setOptionalStatus")
	var got struct {
		Hidden bool   `json:"hidden"`
		Text   string `json:"text"`
	}
	call(t, vm, `(function () {
	  setOptionalStatus("state", "Registry charts", false, false);
	  return { hidden: $("state").hidden, text: $("state").textContent };
	})()`, &got)
	if got.Hidden || got.Text != "Registry charts could not be loaded" {
		t.Errorf("initial failure status = %+v", got)
	}
	call(t, vm, `(function () {
	  setOptionalStatus("state", "Registry charts", false, true);
	  return { hidden: $("state").hidden, text: $("state").textContent };
	})()`, &got)
	if got.Hidden || got.Text != "Registry charts could not be refreshed; showing last known data" {
		t.Errorf("stale status = %+v", got)
	}
	call(t, vm, `(function () {
	  setOptionalStatus("state", "Registry charts", true, true);
	  return { hidden: $("state").hidden, text: $("state").textContent };
	})()`, &got)
	if !got.Hidden || got.Text != "" {
		t.Errorf("recovered status = %+v", got)
	}
}

// The registry charts may deliberately retain lastDist through a failed
// /admin/distributions tick. The global anomaly banner is a current alert,
// though, so it must take miss counters only from that tick's payload while
// continuing to report current missing-scope health from /admin/anomaly.
func TestAnomalyBannerDoesNotUseStaleDistributionMisses(t *testing.T) {
	vm := jsRuntime(t, "renderAnomalyHealth")
	type banner struct {
		Hidden bool   `json:"hidden"`
		Text   string `json:"text"`
	}
	var got banner
	call(t, vm, `(function () {
	  var current = { anomaly_misses: { "example.test": 7 } };
	  lastDist = current;
	  renderAnomalyHealth({ scopes: [], models: [] }, current);
	  return { hidden: $("anomaly-banner").hidden, text: $("anomaly-banner").textContent };
	})()`, &got)
	if got.Hidden || !strings.Contains(got.Text, "7 request(s)") {
		t.Fatalf("current miss banner = %+v", got)
	}

	call(t, vm, `(function () {
	  renderAnomalyHealth({ scopes: [], models: [] }, null);
	  return { hidden: $("anomaly-banner").hidden, text: $("anomaly-banner").textContent };
	})()`, &got)
	if !got.Hidden {
		t.Errorf("stale lastDist escaped into banner: %+v", got)
	}

	call(t, vm, `(function () {
	  renderAnomalyHealth({
	    scopes: [{ mode: "enforce", scope: "defaults", coverage: "missing", model: "missing.json" }],
	    models: [],
	  }, null);
	  return { hidden: $("anomaly-banner").hidden, text: $("anomaly-banner").textContent };
	})()`, &got)
	if got.Hidden || !strings.Contains(got.Text, "1 configured scope(s) missing a baseline") ||
		strings.Contains(got.Text, "request(s)") {
		t.Errorf("current anomaly health was not isolated from stale misses: %+v", got)
	}
}

// The offenders renderer deliberately keeps populated tables and the map when
// its optional endpoint has one bad tick. Before any success, however, six
// empty tables would look like a valid zero result, so they stay hidden.
func TestOffendersFailureRetainsOnlyLastKnownData(t *testing.T) {
	vm := jsRuntime(t, "setOptionalStatus", "renderOffenders")
	if _, err := vm.RunString(`
	  var haveOffenders = false;
	  var hasGeoInfo = function () { return false; };
	  var ipCell = function (ip) { return td("num", ip); };
	  var geoCell = function () { return td("wrap", ""); };
	  var countryName = function (code) { return code; };
	  var renderGeoMap = function () {};
	`); err != nil {
		t.Fatal(err)
	}

	var got struct {
		TablesHidden bool   `json:"tablesHidden"`
		Status       string `json:"status"`
		Rows         int    `json:"rows"`
	}
	call(t, vm, `(function () {
	  renderOffenders(null);
	  return {
	    tablesHidden: $("offenders").hidden,
	    status: $("offenders-stale").textContent,
	    rows: $("off-reasons").children.length,
	  };
	})()`, &got)
	if !got.TablesHidden || got.Status != "Offenders could not be loaded" || got.Rows != 0 {
		t.Fatalf("initial offender failure = %+v", got)
	}

	call(t, vm, `(function () {
	  renderOffenders({ window: 1, ips: [], reasons: [{key:"pow", count:3}] });
	  renderOffenders(null);
	  return {
	    tablesHidden: $("offenders").hidden,
	    status: $("offenders-stale").textContent,
	    rows: $("off-reasons").children.length,
	  };
	})()`, &got)
	if got.TablesHidden || got.Status != "Offenders could not be refreshed; showing last known data" || got.Rows != 1 {
		t.Errorf("stale offender render = %+v", got)
	}
}

// TestChartLegendVisibilitySurvivesRefresh covers the dashboard's five-second
// update boundary. Chart.js keeps a legend click in metadata associated with
// the current dataset objects; upsertChart replaces those objects, so the page
// must carry the choice forward by stable label. The second chart proves that
// identical labels do not leak visibility between cards, while removing and
// restoring a series covers the dynamic reason chart.
func TestChartLegendVisibilitySurvivesRefresh(t *testing.T) {
	vm := jsRuntime(t, "charts", "chartVisibility", "ITEM_LEGEND_TYPES", "legendKey",
		"rememberChartVisibility", "applyChartVisibility", "upsertChart")
	if _, err := vm.RunString(`
	  var themeColors = function () { return {}; };
	  var Chart = function (ctx, cfg) {
	    this.config = { type: cfg.type };
	    this.data = cfg.data;
	    this.options = cfg.options;
	    this.datasetVisibility = {};
	    this.dataVisibility = {};
	    this.isDatasetVisible = function (i) {
	      return Object.prototype.hasOwnProperty.call(this.datasetVisibility, i)
	        ? this.datasetVisibility[i]
	        : !this.data.datasets[i].hidden;
	    };
	    this.setDatasetVisibility = function (i, visible) { this.datasetVisibility[i] = visible; };
	    this.getDataVisibility = function (i) { return this.dataVisibility[i] !== false; };
	    this.toggleDataVisibility = function (i) { this.dataVisibility[i] = !this.getDataVisibility(i); };
	    // Replacing dataset objects makes Chart.js build fresh metadata during
	    // update; visibility must therefore come from each new dataset.hidden.
	    this.update = function () { this.datasetVisibility = {}; };
	  };
	  var lineCfg = function (labels) { return function () { return {
	    type: "line", data: { labels: ["now"], datasets: labels.map(function (label) {
	      return { label: label, data: [1] };
	    }) }, options: {}
	  }; }; };
	`); err != nil {
		t.Fatal(err)
	}

	var got struct {
		FirstDeny      bool `json:"firstDeny"`
		FirstChallenge bool `json:"firstChallenge"`
		SecondDeny     bool `json:"secondDeny"`
		RestoredDeny   bool `json:"restoredDeny"`
	}
	call(t, vm, `(function () {
	  upsertChart("first", lineCfg(["deny", "challenge"]));
	  upsertChart("second", lineCfg(["deny", "challenge"]));
	  charts.first.setDatasetVisibility(0, false); // the user's legend click
	  upsertChart("first", lineCfg(["challenge"]));
	  upsertChart("first", lineCfg(["challenge", "deny"]));
	  upsertChart("second", lineCfg(["deny", "challenge"]));
	  return {
	    firstDeny: charts.first.data.datasets[1].hidden === true,
	    firstChallenge: charts.first.data.datasets[0].hidden !== true,
	    secondDeny: charts.second.data.datasets[0].hidden === true,
	    restoredDeny: charts.first.isDatasetVisible(1),
	  };
	})()`, &got)
	if !got.FirstDeny || !got.FirstChallenge {
		t.Errorf("first chart lost or misapplied hidden series: %+v", got)
	}
	if got.SecondDeny {
		t.Errorf("hidden state leaked into another chart: %+v", got)
	}
	if got.RestoredDeny {
		t.Errorf("returning deny series is visible, want hidden: %+v", got)
	}
}

// Doughnut legends toggle individual data items rather than whole datasets.
// Keep that separate Chart.js contract covered as the response-mix card uses
// it and upsertChart deliberately supports every dashboard legend.
func TestChartItemLegendVisibilitySurvivesRefresh(t *testing.T) {
	vm := jsRuntime(t, "charts", "chartVisibility", "ITEM_LEGEND_TYPES", "legendKey",
		"rememberChartVisibility", "applyChartVisibility", "upsertChart")
	if _, err := vm.RunString(`
	  var themeColors = function () { return {}; };
	  var Chart = function (ctx, cfg) {
	    this.config = { type: cfg.type };
	    this.data = cfg.data;
	    this.options = cfg.options;
	    this.dataVisibility = {};
	    this.getDataVisibility = function (i) { return this.dataVisibility[i] !== false; };
	    this.toggleDataVisibility = function (i) { this.dataVisibility[i] = !this.getDataVisibility(i); };
	    this.update = function () {};
	  };
	  var doughnutCfg = function (labels) { return function () { return {
	    type: "doughnut", data: { labels: labels, datasets: [{ data: labels.map(function () { return 1; }) }] },
	    options: {}
	  }; }; };
	`); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Moved4xx bool `json:"moved4xx"`
		New2xx   bool `json:"new2xx"`
	}
	call(t, vm, `(function () {
	  upsertChart("mix", doughnutCfg(["2xx", "4xx"]));
	  charts.mix.toggleDataVisibility(1); // hide 4xx
	  upsertChart("mix", doughnutCfg(["4xx", "2xx"]));
	  return {
	    moved4xx: charts.mix.getDataVisibility(0),
	    new2xx: charts.mix.getDataVisibility(1),
	  };
	})()`, &got)
	if got.Moved4xx || !got.New2xx {
		t.Errorf("item legend state not preserved by label: %+v", got)
	}
}

// call evaluates an expression and decodes it as JSON, so assertions are made
// against Go values rather than goja handles.
func call(t *testing.T, vm *goja.Runtime, expr string, out any) {
	t.Helper()
	v, err := vm.RunString("JSON.stringify(" + expr + ")")
	if err != nil {
		t.Fatalf("evaluating %s: %v", expr, err)
	}
	if err := json.Unmarshal([]byte(v.String()), out); err != nil {
		t.Fatalf("decoding %s (%s): %v", expr, v.String(), err)
	}
}

// TestDashboardUAClass pins the taxonomy behind the "Solve time by client"
// card. It lives here rather than as a needle because the ordering of the
// table is the whole design: bots are tested before the browsers they
// impersonate, and mobile before desktop, since an Android User-Agent also
// says "Linux".
func TestDashboardUAClass(t *testing.T) {
	vm := jsRuntime(t, "UA_CLASSES", "uaClass")
	cases := []struct {
		ua, want string
	}{
		// A current Firefox on desktop Linux. Reported as unclassified, which
		// it is not: X11 puts it in desktop.
		{"Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0", "desktop"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36", "desktop"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", "desktop"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36", "desktop"},
		// Mobile wins over the desktop platform tokens these also carry.
		{"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36", "mobile"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "mobile"},
		// Bots win over everything, including the browser strings they copy.
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/141.0", "bot"},
		{"curl/8.9.1", "bot"},
		{"", "none"},
		{"my-internal-healthcheck/1.2", "other"},
	}
	for _, c := range cases {
		var got string
		call(t, vm, fmt.Sprintf("uaClass(%s)", mustJSON(t, c.ua)), &got)
		if got != c.want {
			t.Errorf("uaClass(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

// solveClientsRender is the rendered "Solve time by client" card, read back
// out of the stub nodes.
type solveClientsRender struct {
	Hidden bool       `json:"hidden"`
	Meta   string     `json:"meta"`
	Rows   [][]string `json:"rows"`
	Titles []string   `json:"titles"`
}

// renderSolveClients feeds decisions to the real renderer and returns what it
// put on the page.
func renderSolveClients(t *testing.T, decisions ...map[string]any) solveClientsRender {
	t.Helper()
	// 0 means "the histogram knows of no more solves than the sample holds",
	// which is the ordinary case and leaves the coverage note off.
	return renderSolveClientsCard(t, 0, decisions)
}

// renderSolveClientsCard is renderSolveClients plus the /admin/distributions
// count of every timed solve since daemon start, which the card compares its
// own sample against.
func renderSolveClientsCard(t *testing.T, timedSolves int, decisions []map[string]any) solveClientsRender {
	t.Helper()
	if decisions == nil {
		decisions = []map[string]any{} // the page keeps an empty array, never null
	}
	decls := append([]string{"millis", "UA_CLASSES", "uaClass"},
		jsConstNames(dashboardSource(t), "SOLVE")...)
	vm := jsRuntime(t, append(decls, "renderSolveClients")...)
	var got solveClientsRender
	call(t, vm, `(function () {
	  reset();
	  lastDecisions = `+mustJSON(t, decisions)+`;
	  lastDist = { solve_time: { count: `+fmt.Sprint(timedSolves)+` } };
	  renderSolveClients();
	  var card = $("card-solve-clients"), body = $("solve-clients");
	  return {
	    hidden: card.hidden,
	    meta: $("chart-solve-clients-n").textContent,
	    rows: body.children.map(function (r) { return r.cells.map(function (c) { return c.text; }); }),
	    titles: body.children.map(function (r) { return r.cells[0].title; }),
	  };
	})()`, &got)
	return got
}

// solve builds one solve row as the admin decisions feed serves it.
func solve(ua string, solveMS int) map[string]any {
	return map[string]any{
		"time": "2026-07-30T12:00:00Z", "host": "mail.melroy.org", "ip": "203.0.113.7",
		"uri": "/", "ua": ua, "action": "solve", "reason": "pow:solved",
		"solve_ms": solveMS, "round_trip_ms": solveMS + 400, "bits": 18,
	}
}

const (
	firefoxLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0"
	macSafari    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Safari/605.1.15"
	// A Kindle Fire HD, Amazon's Silk browser. It reports Android, so it is
	// mobile, and it is the slowest real client seen so far by a factor of
	// seven.
	kindleSilk = "Mozilla/5.0 (Linux; Android 5.1.1; KFSUWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/108.18.4 like Chrome/108.0.5359.220 Safari/537.36"
)

// TestSolveClientsSurfacesTheOutlier replays a real ring, taken from a live
// deployment where the card looked wrong: seven solves at 22 bits, six of them
// between 0.6 s and 3.8 s on desktops, and one Kindle Fire at 27 s. That one
// row is the entire reason the card exists, and it was the one row the
// five-sample rule withheld, leaving a card that agreed with itself and
// undercounted the per-domain card next to it by exactly the finding.
func TestSolveClientsSurfacesTheOutlier(t *testing.T) {
	got := renderSolveClientsCard(t, 7, []map[string]any{
		solve(firefoxLinux, 151), solve(macSafari, 614), solve(kindleSilk, 27014),
		solve(firefoxLinux, 1132), solve(firefoxLinux, 1800),
		solve(firefoxLinux, 3770), solve(firefoxLinux, 878),
	})
	want := [][]string{
		{"mobile", "1", "27.0 s", "27.0 s"},
		{"desktop", "6", "1.1 s", "3.8 s"},
	}
	if fmt.Sprint(got.Rows) != fmt.Sprint(want) {
		t.Fatalf("rows = %v, want %v", got.Rows, want)
	}
	if got.Titles[0] != "thin sample: 1 solve" {
		t.Errorf("mobile row title = %q, want the thin-sample note", got.Titles[0])
	}
	if got.Titles[1] != "" {
		t.Errorf("desktop row flagged thin at six samples: %q", got.Titles[1])
	}
	// Every solve is in the sample, so the card must not imply otherwise.
	if got.Meta != "sample of recent solves" {
		t.Errorf("meta = %q, want the plain sample note", got.Meta)
	}
}

// TestSolveClientsShowsASingleSolve is the reported bug: one real desktop
// solve in the ring, "Solve time by domain" lists it, and "Solve time by
// client" is not on the page at all. Hiding a class until it had five samples
// made the card indistinguishable from a broken one on any deployment quiet
// enough to need it.
func TestSolveClientsShowsASingleSolve(t *testing.T) {
	got := renderSolveClients(t, solve(firefoxLinux, 878))
	if got.Hidden {
		t.Fatalf("card hidden with one timed solve; want it shown: %+v", got)
	}
	want := [][]string{{"desktop", "1", "878 ms", "878 ms"}}
	if fmt.Sprint(got.Rows) != fmt.Sprint(want) {
		t.Errorf("rows = %v, want %v", got.Rows, want)
	}
	// A one-sample median is not a finding, so the row has to say so itself
	// now that it is no longer withheld.
	if !strings.Contains(got.Titles[0], "1") {
		t.Errorf("thin sample not flagged on the row: title = %q", got.Titles[0])
	}
}

// TestSolveClientsStaysEmptyWithoutTimedSolves keeps the card honest in the
// other direction: no timed solves means nothing to say, not a table of zeroes.
func TestSolveClientsStaysEmptyWithoutTimedSolves(t *testing.T) {
	for _, c := range []struct {
		name string
		rows []map[string]any
	}{
		{"nothing at all", nil},
		{"only decisions", []map[string]any{{"action": "deny", "reason": "pow:missing", "ua": firefoxLinux}}},
		{"only untimed solves", []map[string]any{solve(firefoxLinux, 0)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := renderSolveClients(t, c.rows...)
			if !got.Hidden || len(got.Rows) != 0 {
				t.Errorf("want an empty hidden card, got %+v", got)
			}
		})
	}
}

// TestSolveClientsGroupsAndRanks covers the rollup itself: one row per class,
// slowest median first, and a sample big enough not to be flagged as thin.
func TestSolveClientsGroupsAndRanks(t *testing.T) {
	const android = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36"
	var rows []map[string]any
	for _, ms := range []int{1000, 1100, 1200, 1300, 9000} {
		rows = append(rows, solve(android, ms))
	}
	for _, ms := range []int{100, 200, 300, 400, 500} {
		rows = append(rows, solve(firefoxLinux, ms))
	}
	// A no-JS redemption reported no time and must not count as instant.
	rows = append(rows, solve(firefoxLinux, 0))
	got := renderSolveClients(t, rows...)
	want := [][]string{
		{"mobile", "5", "1.2 s", "9.0 s"},
		{"desktop", "5", "300 ms", "500 ms"},
	}
	if fmt.Sprint(got.Rows) != fmt.Sprint(want) {
		t.Fatalf("rows = %v, want %v", got.Rows, want)
	}
	for i, title := range got.Titles {
		if title != "" {
			t.Errorf("row %d flagged thin at five samples: %q", i, title)
		}
	}
}

// TestSolveClientsStatesItsCoverage pins the answer to "why does this card
// total less than the one next to it?". The per-domain card is metric-backed
// and counts every timed solve since the daemon started; this one samples the
// most recent decisions the page fetched, so on a busy site the older solves
// have already been pushed out of the ring. Whenever the two disagree the card
// has to say so itself.
func TestSolveClientsStatesItsCoverage(t *testing.T) {
	sample := []map[string]any{
		solve(firefoxLinux, 400), solve(firefoxLinux, 500), solve(firefoxLinux, 600),
	}
	got := renderSolveClientsCard(t, 6, sample)
	if got.Meta != "3 of 6 solves sampled" {
		t.Errorf("meta = %q, want the coverage stated", got.Meta)
	}
	// Nothing missing, nothing to explain.
	got = renderSolveClientsCard(t, 3, sample)
	if got.Meta != "sample of recent solves" {
		t.Errorf("meta = %q, want the plain sample note", got.Meta)
	}
}

// solveTimeBuckets mirrors the bounds of guardian_challenge_solve_seconds in
// core/metrics/metrics.go. Kept here rather than imported because the literal
// there is inline and unexported; if the two ever drift, the bound strings
// asserted below stop matching what the dashboard is handed.
var solveTimeBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30}

// solveHistogram builds the /admin/distributions shape (per-bucket counts, a
// "+Inf" overflow, sum, count) out of observed seconds, so the tests below
// start from real solve times rather than hand-tallied buckets and would catch
// the bucket walk being off by one.
func solveHistogram(seconds ...float64) map[string]any {
	counts := make([]float64, len(solveTimeBuckets)+1)
	var sum float64
	for _, s := range seconds {
		sum += s
		i := len(solveTimeBuckets) // the +Inf slot
		for j, le := range solveTimeBuckets {
			if s <= le {
				i = j
				break
			}
		}
		counts[i]++
	}
	buckets := make([]map[string]any, 0, len(counts))
	for i, le := range solveTimeBuckets {
		buckets = append(buckets, map[string]any{"le": strconv.FormatFloat(le, 'g', -1, 64), "count": counts[i]})
	}
	buckets = append(buckets, map[string]any{"le": "+Inf", "count": counts[len(solveTimeBuckets)]})
	return map[string]any{"buckets": buckets, "sum": sum, "count": float64(len(seconds))}
}

// TestLooksLikeIP pins the gate on the ring-wide search fall-through: only a
// whole IP address triggers the server-side ?ip= probe behind an empty text
// search, because ?ip= is an exact match and anything else must stay a plain
// local miss. Too loose and every typo fires admin API requests; too tight and
// the exact confusion the probe exists to solve ("0 of N" for an IP that IS in
// the ring) comes back.
func TestLooksLikeIP(t *testing.T) {
	vm := jsRuntime(t, "looksLikeIP")
	cases := []struct {
		needle string
		want   bool
	}{
		{"203.0.113.127", true},
		{"2001:db8::1", true},
		{"::ffff:198.51.100.7", true},
		{"2001:0db8:0e2e:0000:0000:0000:0000:0bad", true},
		// Fragments and everything else search locally only.
		{"203.0.113.", false},
		{"1.2.3.4.5", false},
		{"shop.example.com", false},
		{"redeem_fail", false},
		{"pow:bad_solution", false},
		{"", false},
	}
	for _, tc := range cases {
		v, err := vm.RunString(fmt.Sprintf("looksLikeIP(%q)", tc.needle))
		if err != nil {
			t.Fatalf("looksLikeIP(%q): %v", tc.needle, err)
		}
		if v.ToBoolean() != tc.want {
			t.Errorf("looksLikeIP(%q) = %v, want %v", tc.needle, v.ToBoolean(), tc.want)
		}
	}
}

// TestBucketQuantile pins the p90 column on the per-domain card. A Prometheus
// histogram keeps bucket counts and nothing else, so the card reports the bound
// a quantile falls in and must never interpolate a precision that is not there.
func TestBucketQuantile(t *testing.T) {
	vm := jsRuntime(t, "millis", "bucketQuantile")
	cases := []struct {
		name    string
		seconds []float64
		want    string
	}{
		// The three domains from a live deployment, whose card read
		// "≤ 1.0 s", "≤ 5.0 s" and "≤ 30.0 s".
		{"one sub-second solve", []float64{0.878}, "≤ 1.0 s"},
		{"one solve at 3.8 s", []float64{3.77}, "≤ 5.0 s"},
		{"four fast and one 27 s", []float64{0.151, 0.614, 27.014, 1.132, 1.800}, "≤ 30.0 s"},
		// A p90 tracks the bulk and does not chase one outlier: nine of ten
		// solves finished inside 100 ms, so that is the answer even though one
		// visitor waited 12 s. Reading the tail is the Slowest column's job on
		// the client card, and the distribution chart's.
		{"nine fast, one slow", []float64{0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 12}, "≤ 100 ms"},
		// One more fast solve and the 90th percentile crosses into the tail.
		{"eight fast, two slow", []float64{0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 12, 12}, "≤ 30.0 s"},
		// Past the last finite bound, naming infinity would be useless.
		{"beyond the last bucket", []float64{45}, "> 30.0 s"},
		{"no observations", nil, "–"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got string
			call(t, vm, "bucketQuantile("+mustJSON(t, solveHistogram(c.seconds...))+", 0.9)", &got)
			if got != c.want {
				t.Errorf("bucketQuantile = %q, want %q", got, c.want)
			}
		})
	}
}

// TestRenderSolveDomains reproduces the "Solve time by domain" card from a live
// deployment, from the raw solve times up: worst mean first, the mean formatted
// against the same scale as everything else on the page, and a bucket-bound p90.
func TestRenderSolveDomains(t *testing.T) {
	vm := jsRuntime(t, "millis", "bucketQuantile", "renderSolveDomains")
	byDomain := map[string]any{
		"melroy.org":      solveHistogram(0.151, 0.614, 27.014, 1.132, 1.800),
		"blog.melroy.org": solveHistogram(3.77),
		"mail.melroy.org": solveHistogram(0.878),
		// A configured domain that has never issued a solved challenge must not
		// take up a row saying "0".
		"idle.melroy.org": solveHistogram(),
	}
	var got struct {
		Hidden bool       `json:"hidden"`
		Rows   [][]string `json:"rows"`
	}
	call(t, vm, `(function () {
	  reset();
	  renderSolveDomains(`+mustJSON(t, byDomain)+`);
	  return {
	    hidden: $("card-solve-domains").hidden,
	    rows: $("solve-domains").children.map(function (r) {
	      return r.cells.map(function (c) { return c.text; });
	    }),
	  };
	})()`, &got)
	want := [][]string{
		{"melroy.org", "5", "6.1 s", "≤ 30.0 s"},
		{"blog.melroy.org", "1", "3.8 s", "≤ 5.0 s"},
		{"mail.melroy.org", "1", "878 ms", "≤ 1.0 s"},
	}
	if got.Hidden || fmt.Sprint(got.Rows) != fmt.Sprint(want) {
		t.Errorf("rows = %v (hidden %v), want %v", got.Rows, got.Hidden, want)
	}
}

// TestRenderSolveDomainsHidesWhenNothingSolved keeps the card off the page
// rather than showing an empty table, including when domains are present but
// have no observations.
func TestRenderSolveDomainsHidesWhenNothingSolved(t *testing.T) {
	vm := jsRuntime(t, "millis", "bucketQuantile", "renderSolveDomains")
	for name, byDomain := range map[string]map[string]any{
		"no domains":        {},
		"domain, no solves": {"melroy.org": solveHistogram()},
	} {
		t.Run(name, func(t *testing.T) {
			var hidden bool
			call(t, vm, `(function () {
			  reset();
			  renderSolveDomains(`+mustJSON(t, byDomain)+`);
			  return $("card-solve-domains").hidden;
			})()`, &hidden)
			if !hidden {
				t.Error("card shown with nothing to report")
			}
		})
	}
}

// TestSolveCell covers the Solve column in the decisions feed and the per-IP
// lookup: which of the three numbers is displayed, when the row is coloured as
// slow, and that a client which reported nothing is never rendered as instant.
func TestSolveCell(t *testing.T) {
	vm := jsRuntime(t, "millis", "SLOW_SOLVE_MS", "solveCell")
	type cell struct {
		Cls   string `json:"cls"`
		Text  string `json:"text"`
		Title string `json:"title"`
	}
	cases := []struct {
		name string
		row  map[string]any
		want cell
	}{
		{
			// Every non-solve row in the feed gets a blank cell, not a dash:
			// the question does not apply to a deny.
			name: "a deny has no solve time",
			row:  map[string]any{"action": "deny", "reason": "pow:missing", "solve_ms": 0},
			want: cell{Cls: "", Text: "", Title: ""},
		},
		{
			name: "a fast solve",
			row:  solve(firefoxLinux, 878),
			want: cell{Cls: "num", Text: "878 ms",
				Title: "client-reported 878 ms · issued to redeemed 1.3 s · 18 difficulty bits"},
		},
		{
			// Over the 2 s bucket bound, so the cell is flagged.
			name: "a slow solve",
			row:  solve(firefoxLinux, 3770),
			want: cell{Cls: "num slow", Text: "3.8 s",
				Title: "client-reported 3.8 s · issued to redeemed 4.2 s · 18 difficulty bits"},
		},
		{
			// The Kindle Fire. Over 10 s, the histogram's next bound.
			name: "the outlier",
			row:  solve(kindleSilk, 27014),
			want: cell{Cls: "num veryslow", Text: "27.0 s",
				Title: "client-reported 27.0 s · issued to redeemed 27.4 s · 18 difficulty bits"},
		},
		{
			// millis(0) would render "0", which reads as an instant solve.
			name: "no time reported",
			row:  solve(firefoxLinux, 0),
			want: cell{Cls: "num", Text: "–",
				Title: "solve time not reported (no-JS redemption, or a value that could not be true) · issued to redeemed 400 ms · 18 difficulty bits"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got cell
			call(t, vm, "solveCell("+mustJSON(t, c.row)+")", &got)
			if got != c.want {
				t.Errorf("solveCell =\n  %+v\nwant\n  %+v", got, c.want)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// barActions is the action set the per-domain chart plots, in stack order.
var barActions = []string{"allow", "challenge", "refuse", "deny", "shed"}

type domainBars struct {
	Domains []string           `json:"domains"`
	Totals  map[string]float64 `json:"totals"`
	Share   bool               `json:"share"`
	Series  []struct {
		Action string    `json:"action"`
		Counts []float64 `json:"counts"`
		Values []float64 `json:"values"`
	} `json:"series"`
}

// values returns one action's plotted values keyed by domain, which is what the
// assertions are actually about; the array order is covered separately.
func (b domainBars) values(t *testing.T, action string) map[string]float64 {
	t.Helper()
	for _, s := range b.Series {
		if s.Action != action {
			continue
		}
		if len(s.Values) != len(b.Domains) {
			t.Fatalf("%s: %d values for %d domains", action, len(s.Values), len(b.Domains))
		}
		out := map[string]float64{}
		for i, d := range b.Domains {
			out[d] = s.Values[i]
		}
		return out
	}
	t.Fatalf("no %q series; the chart plots %v", action, barActions)
	return nil
}

func callDomainBars(t *testing.T, perDomain map[string]map[string]int, mode string) domainBars {
	t.Helper()
	vm := jsRuntime(t, "domainBars")
	var got domainBars
	call(t, vm, `domainBars(`+mustJSON(t, perDomain)+`, `+
		mustJSON(t, barActions)+`, `+mustJSON(t, mode)+`)`, &got)
	return got
}

// The shape that prompted the mode: one busy domain, one middling, one quiet,
// spanning nearly two orders of magnitude, which is a small fleet rather than an
// extreme one.
var barFleet = map[string]map[string]int{
	"melroy.org":      {"allow": 5200, "challenge": 25, "refuse": 3, "deny": 22},
	"mail.melroy.org": {"allow": 490},
	"blog.melroy.org": {"allow": 140, "challenge": 35, "deny": 8},
}

func TestDomainBarsCountModePlotsRawCounts(t *testing.T) {
	got := callDomainBars(t, barFleet, "count")
	if got.Share {
		t.Error("count mode reported itself as share mode")
	}
	want := map[string]float64{"melroy.org": 25, "mail.melroy.org": 0, "blog.melroy.org": 35}
	if diff := fmt.Sprint(got.values(t, "challenge")); diff != fmt.Sprint(want) {
		t.Errorf("challenge counts = %v, want %v", diff, want)
	}
	// The stacked total has to stay the domain's real traffic, since the axis is
	// read as a count in this mode.
	if got.Totals["melroy.org"] != 5250 {
		t.Errorf("melroy.org total = %v, want 5250", got.Totals["melroy.org"])
	}
}

// TestDomainBarsShareModeMeasuresEachDomainAgainstItself is the point of the
// mode. blog.melroy.org challenges nearly a fifth of its traffic while
// melroy.org challenges half a percent of far more; in count mode both are a
// few pixels wide and indistinguishable, and here they differ by 40x.
func TestDomainBarsShareModeMeasuresEachDomainAgainstItself(t *testing.T) {
	got := callDomainBars(t, barFleet, "share")
	if !got.Share {
		t.Error("share mode did not report itself as share mode")
	}
	ch := got.values(t, "challenge")
	if d := ch["blog.melroy.org"]; math.Abs(d-19.13) > 0.01 {
		t.Errorf("blog.melroy.org challenge share = %v%%, want 19.13%%", d)
	}
	if d := ch["melroy.org"]; math.Abs(d-0.476) > 0.001 {
		t.Errorf("melroy.org challenge share = %v%%, want 0.476%%", d)
	}
	// Totals stay counts even in share mode: they are what the row label and the
	// tooltip report, and they are the only remaining carrier of volume once
	// every bar is the same length.
	if got.Totals["blog.melroy.org"] != 183 {
		t.Errorf("blog.melroy.org total = %v, want 183", got.Totals["blog.melroy.org"])
	}
}

// TestDomainBarsShareModeFillsEachBar guards the property that makes the bars
// comparable: each domain's segments span the full axis, so no domain is a stub.
func TestDomainBarsShareModeFillsEachBar(t *testing.T) {
	got := callDomainBars(t, barFleet, "share")
	for i, d := range got.Domains {
		sum := 0.0
		for _, s := range got.Series {
			sum += s.Values[i]
		}
		if math.Abs(sum-100) > 1e-9 {
			t.Errorf("%s segments sum to %v%%, want 100%%", d, sum)
		}
	}
}

// TestDomainBarsShareIsNeverNarrowerThanCount states the property the mode was
// added for, in the terms an operator sees: switching to share can only ever
// widen a segment, never narrow one, so the mode is safe to leave on.
//
// The assertion overlaps ShareModeFillsEachBar on purpose. That one pins the
// arithmetic; this one pins the consequence an operator relies on.
func TestDomainBarsShareIsNeverNarrowerThanCount(t *testing.T) {
	counts := callDomainBars(t, barFleet, "count")
	shares := callDomainBars(t, barFleet, "share")
	busiest := 0.0
	for _, total := range counts.Totals {
		busiest = math.Max(busiest, total)
	}
	for _, action := range barActions {
		cv, sv := counts.values(t, action), shares.values(t, action)
		for _, d := range counts.Domains {
			if cv[d] == 0 {
				continue
			}
			// What each fraction is worth as a slice of the drawn axis.
			countFrac, shareFrac := cv[d]/busiest*100, sv[d]
			if shareFrac < countFrac-1e-9 {
				t.Errorf("%s %s: share %v%% of the axis is narrower than count mode's %v%%",
					d, action, shareFrac, countFrac)
			}
		}
	}
}

func TestDomainBarsRanksBusiestFirst(t *testing.T) {
	got := callDomainBars(t, barFleet, "count")
	want := []string{"melroy.org", "mail.melroy.org", "blog.melroy.org"}
	if fmt.Sprint(got.Domains) != fmt.Sprint(want) {
		t.Errorf("order = %v, want %v", got.Domains, want)
	}
	// Equal traffic falls back to the name, so the rows do not swap places every
	// five seconds on a fleet of similarly busy domains.
	tied := callDomainBars(t, map[string]map[string]int{
		"b.example": {"allow": 10}, "a.example": {"allow": 10}, "c.example": {"allow": 11},
	}, "share")
	wantTied := []string{"c.example", "a.example", "b.example"}
	if fmt.Sprint(tied.Domains) != fmt.Sprint(wantTied) {
		t.Errorf("tied order = %v, want %v", tied.Domains, wantTied)
	}
}

// TestDomainBarsToleratesATrafficlessDomain covers the one division in the
// helper. A domain counted only under an action this chart does not plot would
// divide by zero, and NaN in a dataset blanks the entire canvas rather than the
// one bar, taking every other domain off the page with it.
func TestDomainBarsToleratesATrafficlessDomain(t *testing.T) {
	got := callDomainBars(t, map[string]map[string]int{
		"real.example":  {"allow": 4},
		"ghost.example": {"solve": 9}, // not a bar segment
	}, "share")
	for _, s := range got.Series {
		for i, v := range s.Values {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("%s value for %s is %v", s.Action, got.Domains[i], v)
			}
		}
	}
	if got.values(t, "allow")["ghost.example"] != 0 {
		t.Error("a domain with no plotted traffic drew a bar")
	}
	if got.values(t, "allow")["real.example"] != 100 {
		t.Error("a domain with only allows is not 100% allow")
	}
}
