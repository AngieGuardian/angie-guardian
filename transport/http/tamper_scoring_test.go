// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"testing"

	"github.com/melroy89/angie-guardian/core"
)

// tamperYAML enables the behavioural scoreboard with a low tamper threshold so
// the block is quick to trigger. No signed_id / uuid_tamper toggle is set:
// forged PoW challenge IDs must be scored out of the box.
const tamperYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m
      thresholds: { tamper: 3/min, pow_fail: 10/min }
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
`

// TestForgedChallengeIDIsScoredAndBlocks drives the real HTTP redeem path with
// an unknown (forged) challenge ID and asserts the IP is behaviourally blocked
// at /auth once the tamper threshold is crossed: the tamper path reaches the
// scoreboard with no feature toggle.
func TestForgedChallengeIDIsScoredAndBlocks(t *testing.T) {
	ts := testServerWithYAML(t, tamperYAML)
	ip, ua := "198.51.100.90", "Mozilla/5.0"

	// Sanity: the IP is allowed to be challenged before any tampering.
	pre := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/", ua), nil)
	if act := pre.Header.Get("X-Guardian-Action"); act == "deny" {
		t.Fatalf("IP blocked before any tamper, action=%q", act)
	}

	// Post 3 forged challenge IDs (never issued): each is a tamper event, and
	// the tamper threshold is 3/min.
	for i := range 3 {
		body, _ := json.Marshal(map[string]any{
			"challenge_id": "forged-does-not-exist",
			"nonce":        "0",
		})
		resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/", ua), body)
		if resp.StatusCode == http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("forged redeem #%d unexpectedly succeeded: %s", i+1, b)
		}
	}

	// The IP must now be denied at the auth endpoint on the tamper threshold.
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("after 3 forged redeems: action=%q status=%d body=%s, want deny", got, resp.StatusCode, b)
	}
	if reason := resp.Header.Get("X-Guardian-Reason"); reason != "behaviour_block:threshold:tamper" {
		t.Fatalf("block reason = %q, want behaviour_block:threshold:tamper", reason)
	}
}

// TestForgedChallengeIDBelowThresholdDoesNotBlock: fewer tamper events than the
// threshold must not block, so honest one-off client errors are tolerated.
func TestForgedChallengeIDBelowThresholdDoesNotBlock(t *testing.T) {
	ts := testServerWithYAML(t, tamperYAML)
	ip, ua := "198.51.100.91", "Mozilla/5.0"

	for range 2 { // threshold is 3
		body, _ := json.Marshal(map[string]any{"challenge_id": "forged", "nonce": "0"})
		do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/", ua), body)
	}
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("blocked after only 2 tamper events (threshold 3): action=%q", got)
	}
}

func TestCrossSiteNoJSFailuresDoNotScore(t *testing.T) {
	ts, h := testServerAndHandler(t, tamperYAML)
	ip, ua := "198.51.100.92", "Mozilla/5.0"
	for i := range 3 {
		headers := guardianHeaders("html.test", ip, "/", ua)
		headers["Sec-Fetch-Site"] = "cross-site"
		headers["Sec-Fetch-Dest"] = "image"
		resp := do(t, "GET", ts.URL+PassPath+"?nojs=1&cid=invalid", headers, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("no-JS request %d: status = %d, want 403", i+1, resp.StatusCode)
		}
	}
	var failures int
	for _, d := range h.engine.RecentDecisions(0) {
		if d.Action == core.ActionRedeemFail {
			failures++
		}
	}
	if failures != 3 {
		t.Errorf("recorded %d failed redemptions, want 3", failures)
	}
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("cross-site no-JS failures blocked visitor: action=%q", got)
	}
}

func TestCrossSiteFormPOSTDoesNotReachScoredRedemption(t *testing.T) {
	ts := testServerWithYAML(t, tamperYAML)
	ip, ua := "198.51.100.93", "Mozilla/5.0"
	for i := range 3 {
		headers := guardianHeaders("html.test", ip, "/", ua)
		headers["Content-Type"] = "text/plain"
		headers["Sec-Fetch-Site"] = "cross-site"
		// A text/plain HTML form can produce a body that parses as JSON.
		resp := do(t, "POST", ts.URL+PassPath, headers, []byte(`{"challenge_id":"invalid","nonce":"x=y"}`))
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("form request %d: status = %d, want 415", i+1, resp.StatusCode)
		}
	}
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("cross-site form requests blocked visitor: action=%q", got)
	}
}
