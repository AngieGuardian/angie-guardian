// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
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
