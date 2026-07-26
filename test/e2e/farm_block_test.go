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
	unblock(t, ip, true)
	if resp := req(t, http.MethodGet, auth+"/auth", hdrs, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unblocked farmer at /auth: status %d, want 401 (challenge again)", resp.StatusCode)
	}

	// And it stays unblocked once the reset window has lapsed, which is the
	// part the guard cannot be doing for us: the unblock has to have cleared
	// the counters that placed the block. The pinned escalation and the
	// challenge_farm event bucket both survived it once, so a single further
	// issuance re-blocked the IP within seconds, at twice the TTL.
	time.Sleep(unblockResetWindow)
	for range 3 {
		farmChallenge(t, ip)
	}
	if blocked, reason := blockStatus(t, ip); blocked {
		t.Fatalf("re-blocked (%s) after an unblock: the counters behind the block were not cleared", reason)
	}
}

// TestUnblockResetsOffenses: the unblock's default also clears the 24h
// repeat-offender count, so a later block starts at the base TTL rather than a
// doubled one, and the opt-out keeps that history.
func TestUnblockResetsOffenses(t *testing.T) {
	const ip = "203.0.113.231"
	t.Cleanup(func() { adminReq(t, http.MethodDelete, "/admin/blocks/"+ip, nil) })

	blockIP(t, ip, "manual")
	unblock(t, ip, false)
	if got := offenses(t, ip); got != 0 {
		// Manual blocks do not touch blkct:, so this is the baseline: only
		// automatic threshold blocks build the ladder.
		t.Fatalf("offenses = %d after a manual block, want 0", got)
	}

	// Drive an automatic block so the ladder actually has something on it.
	// Paced, and started only once the unblock's reset window has lapsed: an
	// unpaced loop spinning through that window issues challenges fast enough
	// to trip the GLOBAL attack posture, which then adds its extra bits to
	// every later test's challenge. The detector aggregates issuance rate
	// fleet-wide, so a test that farms has to stay under the threshold.
	time.Sleep(unblockResetWindow)
	blocked := false
	deadline := time.Now().Add(90 * time.Second)
	for !blocked && time.Now().Before(deadline) {
		farmChallenge(t, ip)
		blocked, _ = blockStatus(t, ip)
		time.Sleep(100 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("farming never blocked the IP")
	}
	if got := offenses(t, ip); got == 0 {
		t.Fatal("an automatic block left no offense count")
	}
	unblock(t, ip, false)
	if got := offenses(t, ip); got == 0 {
		t.Fatal("reset_backoff=false cleared the offense history anyway")
	}
	unblock(t, ip, true)
	if got := offenses(t, ip); got != 0 {
		t.Fatalf("offenses = %d after the default unblock, want 0", got)
	}
}
