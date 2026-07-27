// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// TestUnchallengeableRecordedAsRefused pins the incident this was written for.
// A live deployment logged 93 consecutive `challenge / pow:no_token` decisions
// against the operator's own workstation, which read as a challenge storm. Not
// one of them was a challenge: every one was the browser's favicon service
// fetching /favicon.ico on an anonymous channel, which carries no cookie
// whatever the token's SameSite policy and cannot run the interstitial, so the
// challenge handler refused each one with a 403. The decision record, the
// metric and the wire disagreed on every request, and that disagreement is what
// made the cause take a day to find.
//
// The conversion lives after the stage loop, so it must hold for every stage
// that can challenge, and must not touch any other outcome.
func TestUnchallengeableRecordedAsRefused(t *testing.T) {
	ctx := context.Background()
	e, _ := pathStageEngine(t)
	ua := "Mozilla/5.0 (X11; Linux x86_64)"

	cases := []struct {
		name            string
		req             *RequestContext
		unchallengeable bool
		action          Action
		reason          string
		why             string
	}{
		{"control: challengeable client is still challenged",
			req("shop.test", "198.51.100.11", "/", ua), false,
			ActionChallenge, reasonNoToken,
			"nothing changes for a client that could have solved it"},

		{"pow stage challenge becomes a refusal",
			req("shop.test", "198.51.100.12", "/", ua), true,
			ActionRefuse, reasonUnchallengeable,
			"the favicon case: no cookie was ever going to arrive, so no_token misleads"},

		{"a WAF challenge rule is refused but keeps its own reason",
			req("shop.test", "198.51.100.13", "/union all select", "curl"), true,
			ActionRefuse, "waf:sqli",
			"the action says no puzzle was issued; the reason must still say which " +
				"policy asked for one, or reason-based dashboards undercount the WAF"},

		{"a denial is never softened",
			req("shop.test", "198.51.100.14", "/backup/.env", "curl"), true,
			ActionDeny, "waf:dotfile",
			"unchallengeable says the client cannot solve a puzzle, not that it is harmless"},

		{"an allow is never disturbed",
			req("shop.test", "198.51.100.15", "/api/v1/items", ua), true,
			ActionAllow, "default",
			"a path with pow off issues no challenge, so there is nothing to convert"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Unchallengeable = tc.unchallengeable
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s (%s)",
					d.Action, d.Reason, tc.action, tc.reason, tc.why)
			}
			// A refusal issues no challenge, so it must not advertise a
			// difficulty for Angie to relay to an interstitial that is never
			// served.
			if d.Action == ActionRefuse && d.Difficulty != 0 {
				t.Errorf("refusal carried difficulty %d, want 0", d.Difficulty)
			}
		})
	}
}

const refusalToggleYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
domains:
  on.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
  off.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, refuse_unchallengeable: false }
`

func refusalToggleEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := loadTestConfig(t, refusalToggleYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

// TestRefuseUnchallengeableCanBeDisabled covers the documented rollback, which
// is the case that made this a config key rather than the per-location
// `proxy_set_header Accept "";` lever it replaces. That lever lived only in
// `location @guardian_challenge`, so with it applied the auth hop still saw the
// client's real headers and recorded a refusal while the challenge hop, seeing
// the cleared header, issued a real puzzle. The record then claimed a challenge
// was withheld from a client that had just been handed one, which is the
// mirror image of the bug this file exists to prevent.
//
// Both hops now read this one key for the same host and path, so the rollback
// restores the old behaviour on both at once. Asserting the difficulty is part
// of it: a challenge is only genuinely restored if it carries the bits Angie
// relays to the interstitial.
func TestRefuseUnchallengeableCanBeDisabled(t *testing.T) {
	ctx := context.Background()
	e := refusalToggleEngine(t)
	ua := "Mozilla/5.0 (X11; Linux x86_64)"

	on := req("on.test", "198.51.100.21", "/favicon.ico", ua)
	on.Unchallengeable = true
	if d := e.Evaluate(ctx, on); d.Action != ActionRefuse || d.Reason != reasonUnchallengeable {
		t.Errorf("default: got %s/%s, want %s/%s",
			d.Action, d.Reason, ActionRefuse, reasonUnchallengeable)
	}

	off := req("off.test", "198.51.100.22", "/favicon.ico", ua)
	off.Unchallengeable = true
	d := e.Evaluate(ctx, off)
	if d.Action != ActionChallenge || d.Reason != reasonNoToken {
		t.Errorf("refuse_unchallengeable: false: got %s/%s, want %s/%s",
			d.Action, d.Reason, ActionChallenge, reasonNoToken)
	}
	if d.Difficulty == 0 {
		t.Error("rolled-back challenge carried no difficulty, so nothing usable was restored")
	}
}

// TestUnchallengeableRefusalStaysInThePowMetricSeries: the new reason must keep
// collapsing to the bounded "pow" label like the five token-failure causes,
// rather than fanning guardian_decisions_total out with a sixth series.
func TestUnchallengeableRefusalStaysInThePowMetricSeries(t *testing.T) {
	if got := reasonCategory(reasonUnchallengeable); got != "pow" {
		t.Errorf("reasonCategory(%q) = %q, want %q", reasonUnchallengeable, got, "pow")
	}
}
