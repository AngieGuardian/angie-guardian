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

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))

	if w := out["window"].(float64); w != 9 { // 5+3+1 denies, allow excluded
		t.Errorf("window = %v, want 9 (allow must not be counted)", w)
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

// TestOffendersEmpty: an empty ring yields well-formed empty lists, not an error.
func TestOffendersEmpty(t *testing.T) {
	ts, _ := reportServer(t, reportYAML)
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/offenders", adminToken, ""))
	if out["window"].(float64) != 0 {
		t.Errorf("window = %v, want 0", out["window"])
	}
	for _, k := range []string{"ips", "reasons", "paths"} {
		if _, ok := out[k].([]any); !ok {
			t.Errorf("%s is not an array: %v", k, out[k])
		}
	}
}
