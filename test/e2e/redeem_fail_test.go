// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json/v2"
	"net/http"
	"testing"
)

// TestRedeemFailureIsAttributable pins the operator-facing contract for a
// failed redemption on a real deployed daemon: the funnel's "failed" count is
// explainable. Each failure must land in /admin/decisions as a redeem_fail row
// naming the client and the reason, increment the per-reason counter that
// splits the funnel's total, and NOT block the IP or rank it as an offender on
// its own (a lone failure is as often a VPN flap as abuse).
//
// Direct auth port on purpose, like the other challenge-flow tests: through
// the Angie glue every request carries the docker gateway as its client IP,
// and scoring pow_fail/tamper against the gateway could block it for the
// whole suite.
func TestRedeemFailureIsAttributable(t *testing.T) {
	const ip = "203.0.113.171" // unused by any other e2e test
	t.Cleanup(func() {
		adminReq(t, http.MethodDelete, "/admin/blocks/"+ip, nil)
	})

	failedBefore := metric(t, "guardian_challenges_total", `outcome="failed"`)

	// Leg 1: a real challenge, redeemed with a nonce that misses the
	// difficulty (the ErrBadSolution path).
	id, challenge, difficulty := parseChallenge(t, authChallenge(t, ip))
	if redeemAuth(t, ip, id, failingNonce(t, challenge, difficulty)) {
		t.Fatal("a deliberately failing nonce was redeemed")
	}

	// Leg 2: a challenge ID nothing ever issued (the ErrChallengeUnknown
	// path, which scores as tamper rather than pow_fail).
	if redeemAuth(t, ip, "e2e-never-issued", "1") {
		t.Fatal("a forged challenge ID was redeemed")
	}

	// The ring: exactly the two rows, newest first, fully attributed. ?ip=
	// covers the whole ring server-side, so suite ordering cannot starve this.
	var dl struct {
		Decisions []struct {
			Host   string `json:"host"`
			IP     string `json:"ip"`
			UA     string `json:"ua"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"decisions"`
	}
	dr := adminReq(t, http.MethodGet, "/admin/decisions?action=redeem_fail&ip="+ip+"&limit=all", nil)
	if err := json.UnmarshalRead(dr.Body, &dl); err != nil {
		t.Fatalf("decode /admin/decisions: %v", err)
	}
	if len(dl.Decisions) != 2 {
		t.Fatalf("redeem_fail rows for %s = %d, want 2: %+v", ip, len(dl.Decisions), dl.Decisions)
	}
	for i, want := range []string{"pow:unknown_challenge", "pow:bad_solution"} {
		d := dl.Decisions[i]
		if d.Reason != want {
			t.Errorf("row %d reason = %q, want %q", i, d.Reason, want)
		}
		if d.Host != powHost || d.IP != ip || d.UA != "Mozilla/5.0" {
			t.Errorf("row %d attribution = %s %s %s, want %s %s Mozilla/5.0", i, d.Host, d.IP, d.UA, powHost, ip)
		}
	}

	// The metrics: the funnel counted both, and the per-reason counter splits
	// them. >= rather than == for the reason totals: other tests also fail
	// redemptions (the ipv6 behaviour-block flood posts bad nonces).
	if delta := metric(t, "guardian_challenges_total", `outcome="failed"`) - failedBefore; delta < 2 {
		t.Errorf("challenges_total{failed} grew by %v, want >= 2", delta)
	}
	if v := metric(t, "guardian_challenge_failures_total", `reason="bad_solution"`); v < 1 {
		t.Errorf(`challenge_failures_total{bad_solution} = %v, want >= 1`, v)
	}
	if v := metric(t, "guardian_challenge_failures_total", `reason="unknown_challenge"`); v < 1 {
		t.Errorf(`challenge_failures_total{unknown_challenge} = %v, want >= 1`, v)
	}

	// One failure of each kind stays far under the 10/min pow_fail and tamper
	// thresholds: the IP must not be blocked for it.
	if blocked, reason := blockStatus(t, ip); blocked {
		t.Errorf("a lone redeem failure blocked %s (%s); thresholds exist for repetition", ip, reason)
	}
}
