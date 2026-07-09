// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"testing"
)

// TestChallengeFarmingEscalation proves the per-IP escalation for clients
// that keep requesting challenges without solving them works through real
// Angie: abandoned interstitials get progressively harder (past a free
// allowance of 4, +1 bit per 2 unsolved), and one successful solve resets
// the IP back to base difficulty.
//
// The whole e2e suite shares one client IP, so this test both starts AND
// ends with a full solve: the first pins the counter to a known zero, the
// last cleans up after the farming so later tests see base difficulty.
func TestChallengeFarmingEscalation(t *testing.T) {
	ua := browserUA + " farmer"

	// Reset the shared IP's counter regardless of what ran before.
	_ = solvePoWThroughAngie(t, "/escalation-reset", powHost, ua)

	// guardian.e2e.yaml: base_difficulty 4 = 16 bits. Farm challenges
	// without solving: the first 5 issuances stay at base, the 6th pays +1.
	for i := 1; i <= 5; i++ {
		if ch := fetchChallenge(t, "/farmed", powHost, ua); ch.Difficulty != 16 {
			t.Fatalf("issuance %d: difficulty = %d bits, want base 16", i, ch.Difficulty)
		}
	}
	if ch := fetchChallenge(t, "/farmed", powHost, ua); ch.Difficulty != 17 {
		t.Fatalf("issuance 6: difficulty = %d bits, want escalated 17", ch.Difficulty)
	}

	// One honest solve (at whatever difficulty is now demanded) resets the
	// counter; the next challenge is back at base.
	_ = solvePoWThroughAngie(t, "/escalation-done", powHost, ua)
	if ch := fetchChallenge(t, "/farmed-after", powHost, ua); ch.Difficulty != 16 {
		t.Fatalf("difficulty after solve = %d bits, want base 16 (counter reset)", ch.Difficulty)
	}
}
