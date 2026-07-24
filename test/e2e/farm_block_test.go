// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"
)

// farmHost is configured in guardian.e2e.yaml with base == max difficulty
// (escalation pins the ceiling from its first extra bit) and an opt-in
// challenge_farm threshold of 3/min.
const farmHost = "farm.localhost"

// farmChallenge issues a challenge from the direct auth port for farmHost as
// client ip (authChallenge is hardwired to powHost).
func farmChallenge(t *testing.T, ip string) *http.Response {
	t.Helper()
	return req(t, http.MethodGet, auth+"/challenge", map[string]string{
		"X-Guardian-Host": farmHost, "X-Guardian-IP": ip,
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
	}, nil)
}

// TestChallengeFarmingBlocks: an IP that keeps fetching challenges without
// ever solving one is blocked once the opt-in challenge_farm threshold is
// crossed. Uses a synthetic client IP on the direct auth port so the suite's
// shared source IP is never blocked, and a dedicated host so its escalation
// counter (per host+IP) stays isolated from the other tests.
func TestChallengeFarmingBlocks(t *testing.T) {
	const ip = "203.0.113.230"
	t.Cleanup(func() {
		adminReq(t, http.MethodDelete, "/admin/blocks/"+ip, nil)
	})

	// Issuances 1-5 are within the escalation allowance; from the 6th on the
	// pinned ceiling scores one challenge_farm event each (threshold 3/min).
	// The event bucket is window-aligned, so a boundary can split the events;
	// keep farming until the block lands rather than counting to exactly 8.
	blocked, reason := false, ""
	deadline := time.Now().Add(90 * time.Second)
	for !blocked && time.Now().Before(deadline) {
		resp := farmChallenge(t, ip)
		if _, _, difficulty := parseChallenge(t, resp); difficulty != 16 {
			t.Fatalf("difficulty = %d bits, want 16 (base == max: farming cannot raise it)", difficulty)
		}
		blocked, reason = blockStatus(t, ip)
	}
	if !blocked {
		t.Fatal("challenge farming never tripped the challenge_farm threshold")
	}
	if reason != "threshold:challenge_farm" {
		t.Fatalf("block reason = %q, want threshold:challenge_farm", reason)
	}
	if _, ok := activeBlocks()[ip]; !ok {
		t.Fatalf("%s missing from /admin/blocks: %v", ip, activeBlocks())
	}

	// Farming was detected and counted (metric present from the first pinned
	// issuance, whether or not the operator opted in to blocking).
	if metric(t, "guardian_challenges_total", `outcome="farm_detected"`) == 0 {
		t.Error("guardian_challenges_total{outcome=\"farm_detected\"} never incremented")
	}

	// The auth path denies the farmer; an admin unblock restores the ordinary
	// challenge flow (401, challenged again).
	hdrs := map[string]string{
		"X-Guardian-Host": farmHost, "X-Guardian-IP": ip,
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
	}
	if resp := req(t, http.MethodGet, auth+"/auth", hdrs, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked farmer at /auth: status %d, want 403", resp.StatusCode)
	}
	adminReq(t, http.MethodDelete, "/admin/blocks/"+ip, nil)
	if resp := req(t, http.MethodGet, auth+"/auth", hdrs, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unblocked farmer at /auth: status %d, want 401 (challenge again)", resp.StatusCode)
	}
}
