// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"fmt"
	"regexp"
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
	        replaceChildren: function () { this.children = Array.prototype.slice.call(arguments); },
	      };
	    }
	    return nodes[id];
	  };
	  var el = function (tag, cls, text) {
	    return { tag: tag, cls: cls || "", text: text === undefined ? "" : String(text), title: "" };
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

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
