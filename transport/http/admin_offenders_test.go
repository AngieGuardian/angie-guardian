// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/intel/inteltest"
)

// TestOffendersRequiresAuth: the endpoint exposes client IPs and paths, so it
// must reject an unauthenticated request like every other /admin API.
func TestOffendersRequiresAuth(t *testing.T) {
	ts, _ := reportServer(t, reportYAML)
	resp := adminReq(t, ts, http.MethodGet, "/admin/offenders", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}
}

// TestOffendersTopK: a skewed distribution of denies produces correctly ranked
// top-IP, top-reason and top-path lists over the recent ring. Also checks that
// paths are query-stripped and that allows never appear.
func TestOffendersTopK(t *testing.T) {
	ts, engine := reportServer(t, reportYAML)
	ctx := context.Background()

	// .10 offends 5x, .11 3x, .12 1x — all denylisted (203.0.113.0/24).
	// Query strings vary but the path collapses to /probe.
	deny := func(ip, uri string) {
		d := engine.Evaluate(ctx, &core.RequestContext{
			Host: "site.test", Method: "GET", URI: uri, RemoteAddr: ip, UserAgent: "curl/8",
		})
		if d.Action != core.ActionDeny {
			t.Fatalf("setup: expected deny for %s, got %s", ip, d.Action)
		}
	}
	for i := 0; i < 5; i++ {
		deny("203.0.113.10", fmt.Sprintf("/probe?n=%d", i))
	}
	for i := 0; i < 3; i++ {
		deny("203.0.113.11", "/login")
	}
	deny("203.0.113.12", "/admin")
	// An allow must NOT be counted (different, non-denylisted IP).
	engine.Evaluate(ctx, &core.RequestContext{
		Host: "site.test", Method: "GET", URI: "/ok", RemoteAddr: "198.51.100.1", UserAgent: "curl/8",
	})
	// Neither must a solve, however many an address racks up: this list is read
	// to decide who to block, and the clients that paid their proof of work are
	// the last ones that belong on it. Loud enough here to top every rollup if
	// it were counted.
	for range 20 {
		engine.RecordSolve(core.SolveRecord{
			Host: "site.test", IP: "198.51.100.2", URI: "/checkout",
			UA: "Mozilla/5.0", SolveMS: 1200, RoundTripMS: 1500, Bits: 20,
		})
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))

	if w := out["window"].(float64); w != 9 { // 5+3+1 denies; allow and solves excluded
		t.Errorf("window = %v, want 9 (allows and solves must not be counted)", w)
	}
	for _, row := range out["ips"].([]any) {
		if key := row.(map[string]any)["key"]; key == "198.51.100.2" {
			t.Errorf("offender list ranks a solving client: %v", row)
		}
	}
	for _, row := range out["paths"].([]any) {
		if key := row.(map[string]any)["key"]; key == "/checkout" {
			t.Errorf("offender paths include a solved page: %v", row)
		}
	}

	ips := out["ips"].([]any)
	if len(ips) < 3 {
		t.Fatalf("want at least 3 offender IPs, got %d", len(ips))
	}
	top := ips[0].(map[string]any)
	if top["ip"] != "203.0.113.10" || top["count"].(float64) != 5 {
		t.Errorf("top IP = %v, want 203.0.113.10 with count 5", top)
	}
	second := ips[1].(map[string]any)
	if second["ip"] != "203.0.113.11" || second["count"].(float64) != 3 {
		t.Errorf("second IP = %v, want 203.0.113.11 with count 3", second)
	}

	// Reasons: all denies are denylist, so it dominates.
	reasons := out["reasons"].([]any)
	topReason := reasons[0].(map[string]any)
	if topReason["key"] != "denylist" || topReason["count"].(float64) != 9 {
		t.Errorf("top reason = %v, want denylist with count 9", topReason)
	}

	// Paths: /probe was hit 5x with varying query strings, all collapsed.
	paths := out["paths"].([]any)
	topPath := paths[0].(map[string]any)
	if topPath["key"] != "/probe" || topPath["count"].(float64) != 5 {
		t.Errorf("top path = %v, want /probe with count 5 (query stripped)", topPath)
	}

	// No GeoIP databases configured here, so no country rollup.
	if _, ok := out["countries"]; ok {
		t.Errorf("countries present without GeoIP databases: %v", out["countries"])
	}
}

// TestOffendersUserAgentsAndHosts verifies that the two textual offender
// dimensions use the same verdict-only window as the existing lists. UAs are
// deliberately exact and case-sensitive; hosts use the same normalization as
// config lookup so spelling, case, a port and a trailing dot do not split one
// virtual host into several rows.
func TestOffendersUserAgentsAndHosts(t *testing.T) {
	ts, engine := reportServer(t, reportYAML)
	ctx := context.Background()
	nextIP := 1
	hit := func(host, ua string) {
		ip := fmt.Sprintf("203.0.113.%d", nextIP)
		nextIP++
		d := engine.Evaluate(ctx, &core.RequestContext{
			Host: host, Method: "GET", URI: "/probe", RemoteAddr: ip, UserAgent: ua,
		})
		if d.Action != core.ActionDeny {
			t.Fatalf("setup: expected deny for %s, got %s", ip, d.Action)
		}
	}
	for range 4 {
		hit("Shop.TEST.:443", "Scanner/1")
	}
	for range 2 {
		hit("shop.test", "scanner/1")
	}
	for range 3 {
		hit("api.test", "")
	}

	// Outcome rows carry both fields in the ring but must not outrank clients
	// that actually received a verdict.
	for range 20 {
		engine.RecordSolve(core.SolveRecord{Host: "solve.test", IP: "198.51.100.2", UA: "Solver/1"})
		engine.RecordRedeemFailure("fail.test", "198.51.100.3", "Failed/1", core.ReasonBindingMismatch)
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	counts := func(field string) map[string]int {
		t.Helper()
		got := map[string]int{}
		for _, item := range out[field].([]any) {
			entry := item.(map[string]any)
			got[entry["key"].(string)] = int(entry["count"].(float64))
		}
		return got
	}

	uas := counts("user_agents")
	if uas["Scanner/1"] != 4 || uas["scanner/1"] != 2 || uas[""] != 3 {
		t.Errorf("user_agents = %v, want exact Scanner/1:4, scanner/1:2 and empty:3", uas)
	}
	if _, present := uas["Solver/1"]; present {
		t.Errorf("user_agents ranks a solving client: %v", uas)
	}
	if _, present := uas["Failed/1"]; present {
		t.Errorf("user_agents ranks a failed redemption: %v", uas)
	}

	hosts := counts("hosts")
	if hosts["shop.test"] != 6 || hosts["api.test"] != 3 {
		t.Errorf("hosts = %v, want normalized shop.test:6 and api.test:3", hosts)
	}
	for _, excluded := range []string{"solve.test", "fail.test"} {
		if _, present := hosts[excluded]; present {
			t.Errorf("hosts ranks outcome-only host %q: %v", excluded, hosts)
		}
	}
}

// TestOffendersUserAgentsAndHostsTopK keeps both new attacker-controlled
// dimensions bounded and confirms equal-count rows use lexical key order.
func TestOffendersUserAgentsAndHostsTopK(t *testing.T) {
	ts, engine := reportServer(t, reportYAML)
	ctx := context.Background()
	for i := range offenderTopK + 5 {
		engine.Evaluate(ctx, &core.RequestContext{
			Host: fmt.Sprintf("h%02d.test", i), Method: "GET", URI: "/probe",
			RemoteAddr: fmt.Sprintf("203.0.113.%d", i+1), UserAgent: fmt.Sprintf("UA/%02d", i),
		})
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	for _, field := range []string{"user_agents", "hosts"} {
		entries := out[field].([]any)
		if len(entries) != offenderTopK {
			t.Fatalf("%s = %d entries, want top %d", field, len(entries), offenderTopK)
		}
		first := entries[0].(map[string]any)["key"].(string)
		want := "UA/00"
		if field == "hosts" {
			want = "h00.test"
		}
		if first != want {
			t.Errorf("%s first equal-count key = %q, want lexical first %q", field, first, want)
		}
	}
}

// TestOffendersCityDetail: with a City-class location_db, offender rows carry
// the locality detail. The second IP has only a country record (~20% of real
// networks), which must omit the city keys rather than emit empty strings, so
// a client can tell "no data" from "" without guessing.
func TestOffendersCityDetail(t *testing.T) {
	dir := t.TempDir()
	cityDB := inteltest.WriteCityDB(t, dir, map[string]inteltest.CityRecord{
		"203.0.113.10/32": {Country: "NL", City: "Schagen", Subdivision: "NH", AccuracyRadiusKM: 10},
		"203.0.113.11/32": {Country: "US", AccuracyRadiusKM: 1000},
	})
	yaml := reportYAML + "geoip: { location_db: " + cityDB + " }\n"
	ts, engine := reportServer(t, yaml)
	ctx := context.Background()

	for _, ip := range []string{"203.0.113.10", "203.0.113.11"} {
		d := engine.Evaluate(ctx, &core.RequestContext{
			Host: "site.test", Method: "GET", URI: "/probe", RemoteAddr: ip, UserAgent: "curl/8",
		})
		if d.Action != core.ActionDeny {
			t.Fatalf("setup: expected deny for %s, got %s", ip, d.Action)
		}
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	rows := map[string]map[string]any{}
	for _, r := range out["ips"].([]any) {
		row := r.(map[string]any)
		rows[row["ip"].(string)] = row
	}

	full := rows["203.0.113.10"]
	if full["city"] != "Schagen" || full["subdivision"] != "NH" {
		t.Errorf("city row = %v, want Schagen/NH", full)
	}
	if full["accuracy_radius_km"].(float64) != 10 {
		t.Errorf("accuracy_radius_km = %v, want 10", full["accuracy_radius_km"])
	}

	// Country-only record: country present, city keys absent entirely.
	partial := rows["203.0.113.11"]
	if partial["country"] != "US" {
		t.Errorf("country = %v, want US", partial["country"])
	}
	for _, k := range []string{"city", "subdivision"} {
		if v, ok := partial[k]; ok {
			t.Errorf("%s should be omitted for a country-only record, got %v", k, v)
		}
	}
	if partial["accuracy_radius_km"].(float64) != 1000 {
		t.Errorf("accuracy_radius_km = %v, want 1000", partial["accuracy_radius_km"])
	}
}

// TestOffendersCountryDBOmitsCityKeys is the degradation guarantee: a Country
// database must produce exactly the response shape it did before city support.
func TestOffendersCountryDBOmitsCityKeys(t *testing.T) {
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{"203.0.113.0/24": "NL"})
	yaml := reportYAML + "geoip: { location_db: " + countryDB + " }\n"
	ts, engine := reportServer(t, yaml)

	engine.Evaluate(context.Background(), &core.RequestContext{
		Host: "site.test", Method: "GET", URI: "/probe",
		RemoteAddr: "203.0.113.10", UserAgent: "curl/8",
	})

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	row := out["ips"].([]any)[0].(map[string]any)
	if row["country"] != "NL" {
		t.Errorf("country = %v, want NL", row["country"])
	}
	for _, k := range []string{"city", "subdivision", "accuracy_radius_km"} {
		if v, ok := row[k]; ok {
			t.Errorf("%s must be absent with a Country database, got %v", k, v)
		}
	}
}

// TestOffendersCountryRollupCoversWholeWindow: the country rollup must count
// every distinct IP in the window, not just the top-K rows. A botnet spreading
// its requests over many addresses would otherwise be ranked below a single
// noisy IP from elsewhere, inverting where the traffic actually came from --
// exactly what the dashboard map draws.
func TestOffendersCountryRollupCoversWholeWindow(t *testing.T) {
	dir := t.TempDir()
	// 203.0.113.0/24 is the denylisted range; split it across two countries.
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{
		"203.0.113.0/25":   "TH", // .1-.126: the distributed swarm
		"203.0.113.128/25": "NL", // .129+:   one loud offender
	})
	yaml := reportYAML + "geoip: { location_db: " + countryDB + " }\n"
	ts, engine := reportServer(t, yaml)
	ctx := context.Background()

	hit := func(ip string) {
		engine.Evaluate(ctx, &core.RequestContext{
			Host: "site.test", Method: "GET", URI: "/probe", RemoteAddr: ip, UserAgent: "curl/8",
		})
	}
	// 40 distinct TH addresses, one request each: individually they rank far
	// below the NL IP, so a top-K-only rollup would nearly erase them.
	for i := 1; i <= 40; i++ {
		hit(fmt.Sprintf("203.0.113.%d", i))
	}
	for i := 0; i < 25; i++ {
		hit("203.0.113.200")
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	got := map[string]int{}
	for _, c := range out["countries"].([]any) {
		e := c.(map[string]any)
		got[e["key"].(string)] = int(e["count"].(float64))
	}
	if got["TH"] != 40 {
		t.Errorf("TH = %d, want 40 (all distinct IPs, not just the top-K rows)", got["TH"])
	}
	if got["NL"] != 25 {
		t.Errorf("NL = %d, want 25", got["NL"])
	}
	// The rollup must account for the whole window, with nothing dropped.
	total := got["TH"] + got["NL"]
	if window := int(out["window"].(float64)); total != window {
		t.Errorf("country counts sum to %d but the window holds %d decisions", total, window)
	}
	// The IP list stays capped; only the rollup is exhaustive.
	if n := len(out["ips"].([]any)); n > offenderTopK {
		t.Errorf("ips = %d rows, want at most the top-K %d", n, offenderTopK)
	}
}

// TestOffendersAllCountriesReturned: the country rollup must not be truncated to
// the top-K used for IPs, reasons and paths. Countries are the one bounded
// dimension (at most one per distinct IP in the ring), so capping them at 15
// would silently omit part of the window from both the map and the table --
// under-reporting exactly the distributed traffic the rollup exists to surface.
func TestOffendersAllCountriesReturned(t *testing.T) {
	// 20 countries, one /29 each, so every one exceeds the top-15 cap. The whole
	// set stays inside the denylisted 203.0.113.0/24 (20 * 8 = 160 addresses).
	codes := []string{
		"TH", "NL", "DE", "FR", "GB", "US", "CA", "BR", "IN", "JP",
		"KR", "AU", "SE", "NO", "PL", "ES", "IT", "PT", "FI", "IE",
	}
	nets := map[string]string{}
	for i, cc := range codes {
		nets[fmt.Sprintf("203.0.113.%d/29", i*8)] = cc
	}
	dir := t.TempDir()
	yaml := reportYAML + "geoip: { location_db: " + inteltest.WriteCountryDB(t, dir, nets) + " }\n"
	ts, engine := reportServer(t, yaml)
	ctx := context.Background()

	// Descending request counts, so a top-K slice would drop the tail (FI, IE...)
	// rather than fail on ordering alone.
	want := map[string]int{}
	for i, cc := range codes {
		n := len(codes) - i
		for j := 0; j < n; j++ {
			engine.Evaluate(ctx, &core.RequestContext{
				Host: "site.test", Method: "GET", URI: "/probe",
				RemoteAddr: fmt.Sprintf("203.0.113.%d", i*8+j%8), UserAgent: "curl/8",
			})
		}
		want[cc] = n
	}

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	entries := out["countries"].([]any)
	if len(entries) != len(codes) {
		t.Errorf("countries = %d entries, want all %d (rollup must not be capped at %d)",
			len(entries), len(codes), offenderTopK)
	}
	got, total, prev := map[string]int{}, 0, 1<<31
	for _, c := range entries {
		e := c.(map[string]any)
		n := int(e["count"].(float64))
		got[e["key"].(string)] = n
		total += n
		if n > prev {
			t.Errorf("countries not sorted descending: %d follows %d", n, prev)
		}
		prev = n
	}
	for _, cc := range codes {
		if got[cc] != want[cc] {
			t.Errorf("%s = %d, want %d", cc, got[cc], want[cc])
		}
	}
	if window := int(out["window"].(float64)); total != window {
		t.Errorf("country counts sum to %d but the window holds %d decisions", total, window)
	}
	// The unbounded, attacker-controlled dimensions keep their cap.
	for _, dim := range []string{"ips", "reasons", "paths", "user_agents", "hosts"} {
		if n := len(out[dim].([]any)); n > offenderTopK {
			t.Errorf("%s = %d rows, want at most the top-K %d", dim, n, offenderTopK)
		}
	}
}

// TestOffendersEmpty: an empty ring yields well-formed empty lists, not an error.
func TestOffendersEmpty(t *testing.T) {
	ts, _ := reportServer(t, reportYAML)
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	if out["window"].(float64) != 0 {
		t.Errorf("window = %v, want 0", out["window"])
	}
	for _, k := range []string{"ips", "reasons", "paths", "user_agents", "hosts"} {
		if _, ok := out[k].([]any); !ok {
			t.Errorf("%s is not an array: %v", k, out[k])
		}
	}
}
