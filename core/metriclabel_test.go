// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import "testing"

// TestReasonCategoryBounded pins the invariant that the `reason` metric label
// stays a small fixed set regardless of what follows the first colon. Reason
// strings carry client- or config-influenced suffixes (rule IDs, feed names,
// bot names, geo detail), and reasonCategory is what keeps those out of the
// Prometheus label: a flood of distinct rule/feed/bot names must not explode
// the series count. If a future stage emits a reason whose prefix embeds
// variable data, this test is where it should fail.
func TestReasonCategoryBounded(t *testing.T) {
	// The full set of prefixes any stage may emit (grep for `Reason:` in the
	// core + stateless packages). Keep this in sync when adding a stage.
	knownPrefixes := map[string]bool{
		"default": true, "allowlist": true, "denylist": true,
		"verified_bot": true, "bot_spoof": true, "behaviour_block": true,
		"honeypot": true, "waf": true, "geo": true, "reputation": true,
		"anomaly": true, "pow": true,
	}

	// Variable, attacker- or config-controlled suffixes must collapse to the
	// static prefix, never leak into the label.
	cases := []string{
		"waf:" + "sqli-" + "attacker-crafted-rule-id-\x00-42",
		"reputation:firehol-level1-with-a-very-long-feed-name",
		"verified_bot:Some-Bot/1.2.3 (+http://evil.example/;drop)",
		"bot_spoof:" + "arbitrary bot name from config",
		"behaviour_block:threshold:signature:extra:colons",
		"geo:asn:64500",
		"honeypot:path",
		"default",
	}
	for _, r := range cases {
		cat := reasonCategory(r)
		if !knownPrefixes[cat] {
			t.Errorf("reasonCategory(%q) = %q, which is not a known bounded prefix; "+
				"a new unbounded metric label value would leak into guardian_decisions_total", r, cat)
		}
	}
}
