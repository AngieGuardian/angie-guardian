// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

// TestSubresourceChallengeRefusedNotCounted is the /favicon.ico incident: an
// ordinary browser fetching a subresource is handed an interstitial it cannot
// possibly run, and every one of those issuances used to count as an abandoned
// challenge until the IP blocked itself. The request is now refused outright,
// so nothing is issued and nothing is counted: well past the farm threshold
// the client is still unblocked, and a real navigation from the same IP is
// still at base difficulty.
func TestSubresourceChallengeRefusedNotCounted(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.74", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/favicon.ico", ua)
	h["Sec-Fetch-Dest"] = "image"
	// Twenty is far past both the free allowance (4) and the 2/min threshold.
	for i := range 20 {
		resp := do(t, "GET", ts.URL+"/challenge", h, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("subresource challenge %d: status = %d, want 403", i+1, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("subresource refusal Content-Type = %q, want text/plain (never an unusable page)", ct)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("blocked by subresource requests that were never issued a challenge: reason=%q",
			resp.Header.Get("X-Guardian-Reason"))
	}
	// base_difficulty 1 is 4 leading-zero bits (config units are quarter
	// steps), and farmYAML pins max to the same value, so any escalation at all
	// would have shown up as a farm block above rather than as extra bits here.
	if _, _, d := fetchChallenge(t, ts, ip, ua); d != 4 {
		t.Fatalf("difficulty after 20 refused subresource requests = %d, want base 4 (nothing counted)", d)
	}
}

// TestDocumentDestStillFarms pins the other half: the exemption is paired with
// refusing to issue, so claiming a destination is not a way around escalation.
// A farmer that fetches interstitials as documents, which is what the defence
// was built for, is scored exactly as it was before the header was consulted.
func TestDocumentDestStillFarms(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.75", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	h["Sec-Fetch-Dest"] = "document"
	for i := range 7 { // issuances 6 and 7 score at the pinned ceiling
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("document challenge %d: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		t.Fatalf("Sec-Fetch-Dest: document escaped farm scoring: action=%q", got)
	}
}

// TestCrossOriginFrameNotCounted is the weaponized form of the same bug: a
// hostile page framing a protected URL in a loop. The interstitial is served
// frame-ancestors 'self', so the browser refuses to render it and the visitor
// cannot solve it however long the loop runs; counting those issuances used to
// escalate and eventually block the *visitor's* IP (and behind a NAT everyone
// sharing it) from a site the attacker does not control. The challenge is still
// issued, because the metadata cannot prove the frame is really foreign (see
// TestSameOriginFrameViaCrossSiteRedirect), but nothing is scored.
func TestCrossOriginFrameNotCounted(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.77", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/page", ua)
	h["Sec-Fetch-Dest"] = "iframe"
	h["Sec-Fetch-Site"] = "cross-site"
	for i := range 20 {
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("cross-origin frame challenge %d: status = %d, want 200 (issued, just unscored)", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("a third-party page framing a protected URL blocked the visitor: reason=%q",
			resp.Header.Get("X-Guardian-Reason"))
	}
	// The visitor's ordinary browsing is on the other counter and untouched, so
	// being framed by a hostile page costs them nothing at all.
	if _, _, d := fetchChallenge(t, ts, ip, ua); d != 4 {
		t.Fatalf("difficulty of a normal navigation after 20 framed issuances = %d, want base 4", d)
	}
}

// TestFramedEscalationIsNotACheapChallengeExemption: Sec-Fetch-* is forbidden
// to page script but any HTTP client can send it, so the unscored path must not
// become a way to farm unlimited base-difficulty challenges. Withholding the
// challenge_farm BLOCK is what protects framed visitors; withholding the
// difficulty ramp would protect farmers, so the ramp still applies on the
// separate counter.
//
// farmYAML pins base == max, which would hide a difficulty ramp, so this uses
// a domain with headroom.
func TestFramedEscalationIsNotACheapChallengeExemption(t *testing.T) {
	const yaml = `
store: { backend: memory }
signing_key_file: test-signing.key
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 2 }
`
	ts := testServerWithYAML(t, yaml)
	ip, ua := "198.51.100.81", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/page", ua)
	h["Sec-Fetch-Dest"] = "iframe"
	h["Sec-Fetch-Site"] = "cross-site"

	var last struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Difficulty  int    `json:"difficulty_bits"`
	}
	// Allowance 4, step 2: issuances 1-5 at base 4 bits, 6-7 at +1, 8 at +2.
	want := []int{4, 4, 4, 4, 4, 5, 5, 6}
	for i, w := range want {
		resp := do(t, "GET", ts.URL+"/challenge", h, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("framed issuance %d: status = %d, want 200", i+1, resp.StatusCode)
		}
		page, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		m := dataRe.FindSubmatch(page)
		if m == nil {
			t.Fatalf("no challenge payload in issuance %d", i+1)
		}
		if err := json.Unmarshal(m[1], &last); err != nil {
			t.Fatal(err)
		}
		if last.Difficulty != w {
			t.Fatalf("framed issuance %d: difficulty = %d bits, want %d (claiming a frame must not buy cheap challenges)",
				i+1, last.Difficulty, w)
		}
	}

	// The two counters are independent: a farmer cannot raise a bystander's
	// ordinary difficulty, and cannot escape its own by switching contexts.
	if _, _, d := fetchChallenge(t, ts, ip, ua); d != 4 {
		t.Fatalf("unframed difficulty after 8 framed issuances = %d, want base 4 (separate counters)", d)
	}

	// And a solve clears the frame counter too, so the embedded-SSO visitor who
	// does complete a challenge starts over rather than carrying the ramp.
	body, _ := json.Marshal(map[string]any{
		"challenge_id": last.ChallengeID,
		"nonce":        solve(t, last.Challenge, last.Difficulty),
	})
	if r := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/page", ua), body); r.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("redeem: status = %d body = %s", r.StatusCode, b)
	}
	resp := do(t, "GET", ts.URL+"/challenge", h, nil)
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := dataRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no challenge payload after the solve")
	}
	if err := json.Unmarshal(m[1], &last); err != nil {
		t.Fatal(err)
	}
	if last.Difficulty != 4 {
		t.Fatalf("framed difficulty after a solve = %d bits, want base 4 (redemption must clear both counters)", last.Difficulty)
	}
}

// TestSameOriginFrameViaCrossSiteRedirect is the case that forbids refusing
// these outright. Fetch Metadata computes Sec-Fetch-Site over the request's
// whole URL list against the INITIATOR's origin, so an A -> B -> A chain (an
// SSO callback landing back in a same-origin iframe) arrives tagged cross-site
// even though the frame ancestor is still A. frame-ancestors 'self' permits it,
// so the interstitial renders and the visitor can solve it. A 403 here would
// break embedded login flows; the challenge must be issued and solvable.
func TestSameOriginFrameViaCrossSiteRedirect(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.80", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/sso/callback?code=abc", ua)
	h["Sec-Fetch-Dest"] = "iframe"
	h["Sec-Fetch-Site"] = "cross-site" // tainted by the hop through the IdP
	resp := do(t, "GET", ts.URL+"/challenge", h, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redirect-tainted same-origin frame: status = %d, want 200", resp.StatusCode)
	}

	// And the challenge it carries is a real one the visitor can redeem.
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := dataRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no challenge payload in the interstitial:\n%s", page)
	}
	var data struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Difficulty  int    `json:"difficulty_bits"`
	}
	if err := json.Unmarshal(m[1], &data); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"challenge_id": data.ChallengeID,
		"nonce":        solve(t, data.Challenge, data.Difficulty),
	})
	if r := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/sso/callback?code=abc", ua), body); r.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("embedded SSO callback could not redeem its challenge: status = %d body = %s", r.StatusCode, b)
	}
}

// TestSameOriginFrameStillFarms: a site framing its own protected page renders
// and solves the interstitial normally, so it is challenged and escalated
// exactly as before. Without this the exemption would be a bypass of its own,
// farmable by claiming Sec-Fetch-Dest: iframe.
func TestSameOriginFrameStillFarms(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.78", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	h["Sec-Fetch-Dest"] = "iframe"
	h["Sec-Fetch-Site"] = "same-origin"
	for i := range 7 {
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("same-origin frame challenge %d: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		t.Fatalf("Sec-Fetch-Dest: iframe escaped farm scoring same-origin: action=%q", got)
	}
}

// TestCrossSiteNavigationStillChallenged: an inbound link from another site is
// a top-level navigation, never a frame. It must keep being challenged, or
// every visitor arriving from a search engine is refused the page.
func TestCrossSiteNavigationStillChallenged(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.79", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	h["Sec-Fetch-Dest"] = "document"
	h["Sec-Fetch-Site"] = "cross-site"
	if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("cross-site inbound link: status = %d, want 200 (a normal navigation)", resp.StatusCode)
	}
}

// TestUnknownDestStillFarms: a farmer that strips the header, or sends a value
// no standard defines, falls in the unknown bucket and keeps the pre-existing
// behaviour. Absent is covered by every other test in this file, which sends
// no Sec-Fetch-Dest at all.
func TestUnknownDestStillFarms(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.76", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	h["Sec-Fetch-Dest"] = "not-a-real-destination"
	for i := range 7 {
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("unknown-dest challenge %d: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		t.Fatalf("an unrecognized Sec-Fetch-Dest escaped farm scoring: action=%q", got)
	}
}

// TestAnonymousNonNavigationChallengeRefusedNotCounted is the half of the
// /favicon.ico incident that Sec-Fetch-Dest cannot see. The browser's favicon
// service refreshes a known icon URL on a system principal: no cookie, no Fetch
// metadata at all even over HTTPS, and Accept: */*. Every one of those reads as
// unknown to the destination checks, so it used to be issued an interstitial it
// cannot run and scored for abandoning it, and a real deployment reported 73
// farm events against its own operator's workstation inside half an hour.
//
// Accept is the only thing left that distinguishes it, so it decides here and
// only here: after both unforgeable signals have come up empty.
func TestAnonymousNonNavigationChallengeRefusedNotCounted(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.82", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/favicon.ico", ua)
	h["Accept"] = "*/*"
	// Twenty is far past both the free allowance (4) and the 2/min threshold.
	for i := range 20 {
		resp := do(t, "GET", ts.URL+"/challenge", h, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("anonymous non-navigation challenge %d: status = %d, want 403", i+1, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("refusal Content-Type = %q, want text/plain (never an unusable page)", ct)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("blocked by requests that were never issued a challenge: reason=%q",
			resp.Header.Get("X-Guardian-Reason"))
	}
	if _, _, d := fetchChallenge(t, ts, ip, ua); d != 4 {
		t.Fatalf("difficulty after 20 refused requests = %d, want base 4 (nothing counted)", d)
	}
}

// TestDocumentDestWithWildcardAcceptIsStillChallenged pins the composition rule,
// and is the test that fails if anyone later simplifies the refusal to consult
// Accept alone.
//
// Accept is a heuristic: RFC 9110 makes */* formally accept every media type,
// HTML included, and the Fetch standard only says browsers SHOULD send the
// document Accept value for a navigation. Sec-Fetch-Dest is not a heuristic, so
// where the two disagree the destination wins and the request keeps the ordinary
// challenge path, scoring included. Otherwise a visitor whose Accept has been
// customized, or an engine that classifies a navigation differently, is refused
// entry to the site on the weaker of two available signals.
func TestDocumentDestWithWildcardAcceptIsStillChallenged(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.83", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	h["Sec-Fetch-Dest"] = "document"
	h["Accept"] = "*/*"
	for i := range 7 { // issuances 6 and 7 score at the pinned ceiling
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("document challenge %d with Accept: */*: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		t.Fatalf("a document destination escaped farm scoring because of its Accept: action=%q", got)
	}
}

// TestNavigateModeWithWildcardAcceptIsStillChallenged: Sec-Fetch-Mode is the
// second unforgeable navigation signal and exempts on its own, without any
// destination. Costs nothing against the request this was built for, which sends
// no Fetch metadata whatsoever, and covers a client that reports the mode but
// not the destination.
func TestNavigateModeWithWildcardAcceptIsStillChallenged(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.84", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	h["Sec-Fetch-Mode"] = "navigate"
	h["Accept"] = "*/*"
	for i := range 7 {
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("navigate-mode challenge %d with Accept: */*: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		t.Fatalf("Sec-Fetch-Mode: navigate escaped farm scoring: action=%q", got)
	}
}

// TestSubresourceWithHTMLAcceptIsStillRefused: when the two rules disagree, the
// destination wins.
//
// A fetch()/XHR asking for text/html is the case that only #45 can catch: it
// says it accepts HTML, so the Accept heuristic must leave it alone, but
// Sec-Fetch-Dest: empty proves it will never render a document and it would be
// scored for abandoning a challenge it cannot run. The refusal therefore has to
// come from the subresource branch.
//
// So this is the test that fails if anyone concludes the Accept heuristic
// subsumes #45 and removes it: verified by disabling that branch, which turns
// these 403s into issued challenges. Note it does NOT depend on the order of the
// two cases, since the Accept branch cannot fire on a request naming text/html
// whichever position it holds.
func TestSubresourceWithHTMLAcceptIsStillRefused(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.86", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/api/data", ua)
	h["Sec-Fetch-Dest"] = "empty"
	h["Accept"] = "text/html,application/xhtml+xml"
	for i := range 20 {
		resp := do(t, "GET", ts.URL+"/challenge", h, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("subresource %d claiming to accept HTML: status = %d, want 403", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got == "deny" {
		t.Fatalf("blocked by requests that were never issued a challenge: reason=%q",
			resp.Header.Get("X-Guardian-Reason"))
	}
}

// TestSecondAcceptFieldLineExemptsTheRequest: Accept may arrive as several field
// lines, and text/html in any of them is an exemption.
//
// The handler must therefore read Header.Values, not Header.Get, which returns
// only the first line. Nothing else catches that substitution: the predicate's
// own table covers multi-line input, but it is handed a slice by the test rather
// than by the handler, so swapping Values for Get leaves every other test green
// while refusing a client that plainly asked for HTML.
func TestSecondAcceptFieldLineExemptsTheRequest(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.87", "Mozilla/5.0"

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/challenge", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range guardianHeaders("html.test", ip, "/original?q=1", ua) {
		req.Header.Set(k, v)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept", "text/html")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("two Accept field lines, the second naming text/html: status = %d, want 200 interstitial; body=%s",
			resp.StatusCode, b)
	}
}

// TestAbsentAcceptStillFarms: a request carrying no Accept at all keeps the
// ordinary challenge path, exactly as an absent Sec-Fetch-Dest does.
//
// Every other test in this file happens to send no Accept, so this invariant is
// load-bearing everywhere and named nowhere. It is asserted here because the
// tempting "simplification" is to treat absence as evidence of a non-navigation,
// which would refuse a challenge to every HTTP/1.0 client, minimal tool and
// header-stripping proxy on the internet, none of which can be distinguished
// from a browser without the header they did not send.
func TestAbsentAcceptStillFarms(t *testing.T) {
	ts := testServerWithYAML(t, farmYAML)
	ip, ua := "198.51.100.85", "Mozilla/5.0"

	h := guardianHeaders("html.test", ip, "/original?q=1", ua)
	for i := range 7 {
		if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("challenge %d without an Accept header: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if got := resp.Header.Get("X-Guardian-Action"); got != "deny" {
		t.Fatalf("a request with no Accept escaped farm scoring: action=%q", got)
	}
}
