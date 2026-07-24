// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"crypto/sha256"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// The compose bridge is IPv4-only (and the production soak host has IPv6
// disabled on dockerd), so a real v6 socket client is not possible here.
// Instead these tests drive the published auth hot path with a synthetic v6
// client in X-Guardian-IP, exactly like the attack-mode test does with v4:
// trusted_proxy is on, so guardiand treats the header as the client address
// and the full pipeline (PoW, escalation, scoreboard, behaviour block, admin
// canonicalization) runs keyed by the v6 IP.

// TestIPv6PoWSolveAndEscalation: a v6 client can solve a challenge and mint a
// token, and the per-IP challenge-farming escalation is keyed by its address:
// after a solve resets the pair, 5 abandoned issuances stay at base 16 bits
// and the 6th pays +1 (mirroring TestChallengeFarmingEscalation for v4).
func TestIPv6PoWSolveAndEscalation(t *testing.T) {
	const ip = "2001:db8:e2e::50"

	// Full issue-solve-redeem round trip as a v6 client; also pins the
	// escalation counter for this IP to zero.
	token := solveThroughAuth(t, ip)

	// The minted token vouches for the same v6 client on the auth path.
	resp := req(t, http.MethodGet, auth+"/auth", map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": ip,
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
		"X-Guardian-Cookie": "guardian_token=" + token,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("v6 client with fresh token: status %d, want 200", resp.StatusCode)
	}

	// Farm challenges without solving: base for the free allowance, then +1.
	for i := 1; i <= 5; i++ {
		if _, _, difficulty := parseChallenge(t, authChallenge(t, ip)); difficulty != 16 {
			t.Fatalf("issuance %d: difficulty = %d bits, want base 16", i, difficulty)
		}
	}
	if _, _, difficulty := parseChallenge(t, authChallenge(t, ip)); difficulty != 17 {
		t.Fatalf("issuance 6: difficulty = %d bits, want escalated 17 (per-IP counter keyed by v6)", difficulty)
	}
}

// TestIPv6BehaviourBlock: repeated failed PoW redemptions from one IPv6
// client trip the pow_fail threshold even when the client's address arrives
// in varying textual forms (mixed case, expanded zeros). The resulting block
// is stored under the canonical string, visible through the admin API in any
// spelling, enforced on the auth path against yet another spelling, and
// liftable via the admin API.
func TestIPv6BehaviourBlock(t *testing.T) {
	const canonical = "2001:db8:e2e::bad"
	// Two non-canonical spellings of the same address; without key
	// canonicalization their pow_fail events would count separately and the
	// 10/min threshold would never trip.
	forms := []string{"2001:DB8:E2E::BAD", "2001:0db8:0e2e:0000:0000:0000:0000:0bad"}

	t.Cleanup(func() {
		adminReq(t, http.MethodDelete, "/admin/blocks/"+canonical, nil)
	})

	// The pow_fail bucket is minute-aligned, so a boundary can split the
	// events; keep failing until the block lands rather than counting to
	// exactly 10. Fetch and redeem use the same spelling per attempt (the
	// challenge is bound to the IP string), alternating spellings between
	// attempts.
	blocked, reason := false, ""
	deadline := time.Now().Add(90 * time.Second)
	for i := 0; !blocked && time.Now().Before(deadline); i++ {
		form := forms[i%len(forms)]
		resp := authChallenge(t, form)
		if resp.StatusCode == http.StatusForbidden {
			// The block landed between the last redeem and this issuance.
			blocked, reason = blockStatus(t, canonical)
			break
		}
		id, challenge, difficulty := parseChallenge(t, resp)
		if redeemAuth(t, form, id, failingNonce(t, challenge, difficulty)) {
			t.Fatal("a deliberately failing nonce was redeemed")
		}
		blocked, reason = blockStatus(t, canonical)
	}
	if !blocked {
		t.Fatal("pow_fail flood from alternating v6 spellings never tripped the threshold")
	}
	if reason != "threshold:pow_fail" {
		t.Fatalf("block reason = %q, want threshold:pow_fail", reason)
	}

	// The admin block list carries exactly the canonical spelling.
	if _, ok := activeBlocks()[canonical]; !ok {
		t.Fatalf("canonical %s missing from /admin/blocks: %v", canonical, activeBlocks())
	}
	// Admin lookup under a further non-canonical spelling agrees.
	if b, _ := blockStatus(t, "2001:0DB8:0E2E::0BAD"); !b {
		t.Error("admin block lookup must canonicalize the requested IP")
	}

	// The auth path denies the blocked client under yet another spelling.
	resp := req(t, http.MethodGet, auth+"/auth", map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": "2001:db8:E2E:0:0:0:0:bad",
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked v6 client: status %d, want 403", resp.StatusCode)
	}

	// An admin unblock (canonical spelling) lifts it for every form: the
	// client is back to the ordinary challenge flow, not a 403.
	adminReq(t, http.MethodDelete, "/admin/blocks/"+canonical, nil)
	resp = req(t, http.MethodGet, auth+"/auth", map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": forms[0],
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unblocked v6 client: status %d, want 401 (challenge again)", resp.StatusCode)
	}
}

// failingNonce returns a nonce whose hash does NOT meet the difficulty, so a
// redeem attempt reliably scores a pow_fail (never an accidental solve).
func failingNonce(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := 0; n < 1<<20; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		if leadingZeroBits(sum[:]) < difficulty {
			return nonce
		}
	}
	t.Fatal("could not find a failing nonce (difficulty is implausibly low)")
	return ""
}
