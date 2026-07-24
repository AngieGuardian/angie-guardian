package httptransport

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// farmYAML opts in to challenge_farm scoring with a low threshold so the block
// is quick to trigger. base == max difficulty pins the escalation at the
// ceiling from its first extra bit (the 6th unsolved issuance: allowance 4,
// step 2), so issuances 6 and 7 are the two scored events.
const farmYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m
      thresholds: { challenge_farm: 2/min }
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 1 }
`

// TestChallengeFarmingBlocks: an IP that keeps fetching challenges without
// ever solving one is scored once its escalation pins the difficulty ceiling,
// and blocked when the configured challenge_farm threshold is crossed.
func TestChallengeFarmingBlocks(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.70", "Mozilla/5.0"

	pre := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/", ua), nil)
	if act := pre.Header.Get("X-Guardian-Action"); act == "deny" {
		t.Fatalf("IP blocked before any farming, action=%q", act)
	}

	// Issuances 1-5 are within the allowance, 6 and 7 are at the pinned
	// ceiling and score one challenge_farm event each (threshold 2/min).
	for range 7 {
		fetchChallenge(t, ts, ip, ua)
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("after 7 farmed challenges: action=%q status=%d body=%s, want deny", got, resp.StatusCode, b)
	}
	if reason := resp.Header.Get("X-Guardian-Reason"); reason != "behaviour_block:threshold:challenge_farm" {
		t.Fatalf("block reason = %q, want behaviour_block:threshold:challenge_farm", reason)
	}
}

// TestChallengeFarmingBelowThresholdDoesNotBlock: one scored event (6
// issuances) is below the threshold of 2, so the IP keeps being challenged.
func TestChallengeFarmingBelowThresholdDoesNotBlock(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.71", "Mozilla/5.0"

	for range 6 {
		fetchChallenge(t, ts, ip, ua)
	}
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("blocked after a single scored event (threshold 2): action=%q", got)
	}
}

// TestChallengeFarmingSolveResets: a successful redemption clears the
// escalation counter, so later issuances are no longer at the ceiling and
// score nothing; the earlier single event stays below the threshold.
func TestChallengeFarmingSolveResets(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.72", "Mozilla/5.0"

	var id, challenge string
	var difficulty int
	for range 6 { // one scored event on the 6th issuance
		id, challenge, difficulty = fetchChallenge(t, ts, ip, ua)
	}
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": solve(t, challenge, difficulty)})
	if resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/", ua), body); resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("redeem: status = %d body = %s", resp.StatusCode, b)
	}

	// Post-solve issuances restart from the allowance: no further events.
	for range 5 {
		fetchChallenge(t, ts, ip, ua)
	}
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("blocked although the solve reset escalation: action=%q", got)
	}
}

// TestChallengeFarmingOffDisables: with the challenge_farm threshold set to
// "off" the detection is metrics-only and farming never blocks, however long
// it goes on (the built-in 80/h default is switched off by the key).
func TestChallengeFarmingOffDisables(t *testing.T) {
	const yaml = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m
      thresholds: { challenge_farm: off }
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 1 }
`
	ts := testServerWithYAML(t, yaml)
	ip, ua := "198.51.100.73", "Mozilla/5.0"

	for range 12 { // 7 issuances at the pinned ceiling, all unscored
		fetchChallenge(t, ts, ip, ua)
	}
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("farming blocked without an opt-in challenge_farm threshold: action=%q", got)
	}
}
