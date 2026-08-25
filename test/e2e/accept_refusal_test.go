// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
)

// TestAcceptHeuristicRefusalThroughAngie exists for one reason a unit test
// cannot serve: the whole refusal rests on the client's own Accept reaching
// @guardian_challenge unmodified, and that is a property of the Angie glue, not
// of the daemon. `location @guardian_challenge` overrides only the X-Guardian-*
// set, so Accept survives today; the day someone adds a proxy_set_header there,
// every in-process test still passes and the fix silently stops working in
// production. This is the test that fails instead.
//
// Both directions are asserted against the same path, because either alone is
// consistent with a broken relay: if Accept never arrived, the first leg would
// return the interstitial too.
func TestAcceptHeuristicRefusalThroughAngie(t *testing.T) {
	before := metric(t, "guardian_challenges_total", `outcome="accept_heuristic_refused"`)

	// A client asking for JSON, with no Fetch metadata, cannot run an
	// interstitial and is refused one rather than scored for abandoning it.
	resp := get(t, "/accept-refusal", powHost, browserUA, map[string]string{
		"Accept": "application/json",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Accept: application/json: status %d, want 403; body:\n%s", resp.StatusCode, bodyOf(t, resp))
	}
	body := bodyOf(t, resp)
	if strings.Contains(body, "guardian-data") {
		t.Fatalf("refused request received the interstitial anyway; Accept did not reach the challenge handler:\n%s", body)
	}
	// The wording is asserted, not just the status: this branch fires for
	// Accept: */*, which formally accepts HTML, so a body claiming the client
	// does not accept HTML would be untrue.
	if !strings.Contains(body, "document navigation") {
		t.Fatalf("refusal body = %q, want the behavioural explanation", body)
	}

	// no-store survives Angie. A cacheable refusal was measured and rejected
	// (see refuseChallenge), so this pins the value rather than the idea.
	if cache := strings.Join(resp.Header.Values("Cache-Control"), ", "); !strings.Contains(cache, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cache)
	}

	if got := metric(t, "guardian_challenges_total", `outcome="accept_heuristic_refused"`); got < before+1 {
		t.Errorf("challenges accept_heuristic_refused: %v → %v, want +1", before, got)
	}

	// The sibling refusal from #45, which has had no e2e coverage at all. Worth
	// the two extra requests here: it proves Angie relays Sec-Fetch-Dest as well
	// as Accept, and that the two branches report distinct outcomes rather than
	// one label standing in for both, which is exactly the ambiguity that made
	// the original production diagnosis take a day.
	subBefore := metric(t, "guardian_challenges_total", `outcome="subresource_refused"`)
	sub := get(t, "/accept-refusal", powHost, browserUA, map[string]string{
		"Sec-Fetch-Dest": "image",
		"Accept":         "image/avif,image/webp,*/*;q=0.8",
	})
	if sub.StatusCode != http.StatusForbidden {
		t.Fatalf("Sec-Fetch-Dest: image: status %d, want 403", sub.StatusCode)
	}
	if body := bodyOf(t, sub); !strings.Contains(body, "same-origin document request") {
		t.Errorf("subresource refusal body = %q, want the subresource wording, "+
			"not the Accept one: the branches must stay distinguishable", body)
	}
	if got := metric(t, "guardian_challenges_total", `outcome="subresource_refused"`); got < subBefore+1 {
		t.Errorf("challenges subresource_refused: %v → %v, want +1", subBefore, got)
	}

	// The other direction: an ordinary navigation Accept on the same path still
	// gets the interstitial, so the refusal is not simply refusing everything.
	nav := get(t, "/accept-refusal", powHost, browserUA, map[string]string{
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	if nav.StatusCode != http.StatusOK {
		t.Fatalf("navigation Accept: status %d, want 200 interstitial", nav.StatusCode)
	}
	if navBody := bodyOf(t, nav); !strings.Contains(navBody, "guardian-data") {
		t.Fatalf("navigation Accept did not receive the interstitial; body:\n%s", navBody)
	}
}

// TestRefusalIsRecordedAsRefused covers the hop the test above cannot: the auth
// subrequest. The decision that reaches /admin/decisions, the decision log and
// guardian_decisions_total is made at `location = /__guardian/auth`, a
// different Angie location with its own proxy_set_header block, so Accept
// arriving at @guardian_challenge says nothing about whether it arrives at
// /auth. If it does not, the daemon records "challenge / pow:no_token" for a
// request it then refuses, every in-process test still passes, and an operator
// reading the dashboard sees a challenge storm that never happened. That is the
// exact misreporting this was written to end, so it needs a test that fails
// through the real glue rather than an assumption about nginx defaults.
func TestRefusalIsRecordedAsRefused(t *testing.T) {
	const uri = "/refusal-recorded"
	before := metric(t, "guardian_decisions_total", `action="refuse"`)

	// The production shape: anonymous, no Fetch metadata, Accept: */*. This is
	// the browser's favicon service, which fetches on a channel that carries no
	// cookie and therefore can never present a token.
	resp := get(t, uri, powHost, browserUA, map[string]string{"Accept": "*/*"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body:\n%s", resp.StatusCode, bodyOf(t, resp))
	}

	var dl struct {
		Decisions []struct {
			URI    string `json:"uri"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"decisions"`
	}
	dr := adminReq(t, http.MethodGet, "/admin/decisions?limit=50", nil)
	if err := json.UnmarshalRead(dr.Body, &dl); err != nil {
		t.Fatalf("decode /admin/decisions: %v", err)
	}

	// Every decision recorded for this path must be the refusal. Asserting over
	// all of them, rather than looking for one refuse row, is what catches the
	// regression: a stray "challenge / pow:no_token" beside it means the auth
	// hop never saw Accept and the record is lying again.
	var seen int
	for _, d := range dl.Decisions {
		if !strings.Contains(d.URI, uri) {
			continue
		}
		seen++
		if d.Action != "refuse" || d.Reason != "pow:unchallengeable" {
			t.Errorf("decision for %s = %s/%s, want refuse/pow:unchallengeable",
				d.URI, d.Action, d.Reason)
		}
	}
	if seen == 0 {
		t.Fatalf("no decision recorded for %s in %+v", uri, dl.Decisions)
	}

	if got := metric(t, "guardian_decisions_total", `action="refuse"`); got < before+1 {
		t.Errorf("decisions action=refuse: %v → %v, want +1", before, got)
	}
}

// TestRefusalRollbackIsConsistentAcrossBothHops covers the documented opt-out,
// which is the case where the two Angie hops can disagree and the only reason
// the switch is a config key rather than the per-location
// `proxy_set_header Accept "";` it replaces. That lever lived only in
// `location @guardian_challenge`, so with it applied the auth subrequest still
// classified the client's real headers and recorded a refusal while this hop,
// seeing the cleared header, issued a real puzzle: the log claimed a challenge
// was withheld from a client that had just been handed one.
//
// `/rollback-refusal` carries `pow: { refuse_unchallengeable: false }`, so the
// identical request must get the interstitial here and be recorded as a
// challenge, while the rest of the host still refuses. Asserting both halves is
// the point: either alone passes just as well if the key is ignored.
func TestRefusalRollbackIsConsistentAcrossBothHops(t *testing.T) {
	const uri = "/rollback-refusal"
	anon := map[string]string{"Accept": "*/*"}

	// The wire: a challenge is really served, not a 403.
	resp := get(t, uri, powHost, browserUA, anon)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rolled-back path: status %d, want 200 interstitial; body:\n%s",
			resp.StatusCode, bodyOf(t, resp))
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "guardian-data") {
		t.Fatalf("rolled-back path did not receive the interstitial; body:\n%s", body)
	}

	// The record agrees with the wire. This is the assertion that would have
	// failed before the key existed.
	var dl struct {
		Decisions []struct {
			URI    string `json:"uri"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"decisions"`
	}
	dr := adminReq(t, http.MethodGet, "/admin/decisions?limit=50", nil)
	if err := json.UnmarshalRead(dr.Body, &dl); err != nil {
		t.Fatalf("decode /admin/decisions: %v", err)
	}
	var seen int
	for _, d := range dl.Decisions {
		if !strings.Contains(d.URI, uri) {
			continue
		}
		seen++
		if d.Action != "challenge" {
			t.Errorf("decision for %s = %s/%s, want challenge: the opt-out must roll "+
				"back the record as well as the response", d.URI, d.Action, d.Reason)
		}
	}
	if seen == 0 {
		t.Fatalf("no decision recorded for %s in %+v", uri, dl.Decisions)
	}

	// The rest of the host is unaffected, so this is an opt-out and not an
	// accidental global disable.
	other := get(t, "/still-refused", powHost, browserUA, anon)
	if other.StatusCode != http.StatusForbidden {
		t.Errorf("unscoped path: status %d, want 403; the overlay must not leak",
			other.StatusCode)
	}
}
