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

// TestAngieOwn401IsNotAnsweredWithTheInterstitial covers a defect that lives
// entirely in the Angie glue, so nothing in-process can see it.
//
// `error_page 401 = @guardian_challenge` matches on status, not on who produced
// it. auth_basic runs before auth_request in the ACCESS phase and
// short-circuits, so Guardian never evaluates a credential-less request and the
// 401 is Angie's own. Sent to @guardian_challenge it was answered with the
// interstitial, and because the `=` form takes the status from the target the
// client got 200 with WWW-Authenticate stranded on it: no browser prompts for
// credentials on a 200. The visitor solved the puzzle, reloaded, was 401'd
// again, and looped until the issuance rate limit stopped them.
//
// @guardian_challenge now tests $guardian_action and passes any 401 that is not
// Guardian's own straight through. This asserts all three properties that fix
// has to hold at once, because each is individually satisfiable by a wrong one:
// a bare `return 401` with no add_header would leak the interstitial's CSP; a
// guard that tested only for "challenge" would break refusals (covered in
// TestAcceptHeuristicRefusalThroughAngie, which shares this glue); and a guard
// that passed everything through would break the challenge flow itself
// (covered in TestPoWFullSolveThroughAngie).
func TestAngieOwn401IsNotAnsweredWithTheInterstitial(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux x86_64) e2e-basic"
	htmlAccept := map[string]string{"Accept": "text/html,application/xhtml+xml"}

	// No credentials: Angie's own 401 must survive as a 401.
	resp := get(t, "/basic/", powHost, ua, htmlAccept)
	body := bodyOf(t, resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: Angie's own 401 was rewritten (200 means the interstitial answered it)",
			resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge: without it no browser prompts", got)
	}
	// The interstitial is the specific wrong answer, so name it rather than
	// asserting on the status alone.
	if strings.Contains(body, "guardian_challenge") || strings.Contains(strings.ToLower(body), "checking you") {
		t.Errorf("the proof-of-work interstitial was served for a 401 Guardian never issued:\n%s", body)
	}
	// The interstitial's CSP must not ride along on the passed-through error
	// page: it permits inline script and a blob: worker, which this response has
	// no use for. This is what the add_header inside the guard is for.
	if csp := resp.Header.Get("Content-Security-Policy"); strings.Contains(csp, "worker-src") {
		t.Errorf("passed-through 401 inherited the interstitial CSP: %q", csp)
	}

	// With valid credentials the request reaches Guardian and the site as
	// normal, so the guard did not turn the location into a dead end.
	authed := get(t, "/basic/", powHost, ua, map[string]string{
		"Accept": "text/html,application/xhtml+xml",
		// e2e:s3cret, matching deploy/docker/basic.htpasswd.
		"Authorization": "Basic ZTJlOnMzY3JldA==",
	})
	switch authed.StatusCode {
	case http.StatusOK:
		// Guardian allowed it outright.
	case http.StatusUnauthorized:
		// Guardian challenged it, which is also correct on a PoW host: what
		// matters is that this is now GUARDIAN's 401, carrying the interstitial
		// rather than a stock error page.
		if b := bodyOf(t, authed); !strings.Contains(strings.ToLower(b), "checking you") {
			t.Errorf("authenticated request got a 401 that is not the interstitial:\n%s", b)
		}
	default:
		t.Errorf("authenticated request: status = %d, want 200 or a Guardian challenge", authed.StatusCode)
	}
}
