// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) e2e"

// TestAllowlistedPathReachesBackend confirms an allowlisted path skips the whole
// pipeline and is proxied to the whoami backend (which echoes "Hostname:").
func TestAllowlistedPathReachesBackend(t *testing.T) {
	resp := get(t, "/robots.txt", powHost, browserUA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/robots.txt: status %d, want 200", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
		t.Fatalf("/robots.txt did not reach whoami backend; body:\n%s", body)
	}
}

// TestDefaultsPathOverlay confirms a paths: overlay under defaults reaches
// every host (localhost declares its own paths: map, wp.localhost declares
// none) and, unlike an allowlist entry, only turns off the layer it names:
// the WAF still inspects the exempted path.
func TestDefaultsPathOverlay(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)

	for _, host := range []string{powHost, wpHost} {
		resp := get(t, "/public-feed.xml", host, browserUA, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s /public-feed.xml: status %d, want 200 (defaults overlay disables pow)", host, resp.StatusCode)
		}
		if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
			t.Fatalf("%s /public-feed.xml did not reach whoami backend; body:\n%s", host, body)
		}
	}

	// Not a terminal allow: the path-traversal rule (deny, targets path+query)
	// still fires on the same path.
	if r := get(t, "/public-feed.xml?f=../../etc/passwd", powHost, browserUA, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("traversal on the exempted path: status %d, want 403 (the WAF must still run)", r.StatusCode)
	}
}

// TestBrowserGetIsChallenged confirms an unvouched GET on a PoW-always host
// is diverted to the interstitial (Angie turns the 401 into 200 HTML) and that
// the page carries the embedded challenge JSON.
func TestBrowserGetIsChallenged(t *testing.T) {
	resp := get(t, "/needs-pow", powHost, browserUA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge interstitial: status %d, want 200", resp.StatusCode)
	}
	body := bodyOf(t, resp)
	if !strings.Contains(body, "guardian-data") || !strings.Contains(body, "challenge") {
		t.Fatalf("response is not the PoW interstitial; body:\n%s", body)
	}
	// Two layers set a policy here: guardiand sends its own on the response, and
	// the snippet's location-scoped add_header both re-states it and stops a
	// vhost-level site CSP from applying to (and breaking) this page. A browser
	// enforces EVERY policy it receives, so the invariant is that each one
	// permits the blob: solver worker, not just the first.
	policies := resp.Header.Values("Content-Security-Policy")
	if len(policies) == 0 {
		t.Fatal("interstitial carries no Content-Security-Policy")
	}
	for _, csp := range policies {
		if !strings.Contains(csp, "worker-src blob:") {
			t.Fatalf("interstitial Content-Security-Policy = %q, want worker-src blob:", csp)
		}
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("interstitial X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestNonBrowserUAIsChallenged confirms command-line clients cannot bypass
// pow.mode=always by omitting a browser-shaped User-Agent.
func TestNonBrowserUAIsChallenged(t *testing.T) {
	resp := get(t, "/api-ish", powHost, "curl/8.0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("curl UA: status %d, want 200 interstitial", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "guardian-data") {
		t.Fatalf("curl UA did not receive the PoW interstitial; body:\n%s", body)
	}
}

// TestPostIsDivertedToChallenge proves non-idempotent methods cannot bypass
// pow.mode=always. Angie internally fetches the interstitial with GET and does
// not forward the original request body to Guardian or the backend.
func TestPostIsDivertedToChallenge(t *testing.T) {
	resp := req(t, http.MethodPost, site+"/submit", map[string]string{
		"Host": powHost, "User-Agent": browserUA, "Content-Type": "application/json",
	}, strings.NewReader(`{"secret":"must-not-reach-backend"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST challenge: status %d, want 200 interstitial", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "guardian-data") {
		t.Fatalf("POST did not receive the PoW interstitial; body:\n%s", body)
	}
}

// TestPoWFullSolveThroughAngie is the scenario the old in-process tests could
// not cover: the complete browser journey through a REAL Angie,
//
//	challenged → solve → redeem (cookie) → vouched request allowed → replay rejected.
func TestPoWFullSolveThroughAngie(t *testing.T) {
	ua := browserUA + " solve"

	// 1–3. Challenge → solve → redeem, all through Angie.
	token := solvePoWThroughAngie(t, "/protected-page", powHost, ua)

	// 4. A vouched request (carrying the token cookie) reaches the backend.
	//    Angie forwards the Cookie header to guardiand as X-Guardian-Cookie,
	//    and the pow_token stage allows it (reason "pow:token").
	resp := get(t, "/protected-page", powHost, ua, map[string]string{
		"Cookie": "guardian_token=" + token,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vouched request: status %d, want 200", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
		t.Fatalf("vouched request did not reach backend; body:\n%s", body)
	}

	// 5. The solve is attributable afterwards: the admin feed says which host,
	//    path and client paid it, at what difficulty, and what it cost them.
	//    This is the whole journey end to end, through the real proxy: without
	//    it a slow proof of work is only an unlabelled histogram bucket.
	var dl struct {
		Decisions []struct {
			Host        string `json:"host"`
			URI         string `json:"uri"`
			UA          string `json:"ua"`
			Action      string `json:"action"`
			Reason      string `json:"reason"`
			SolveMS     int    `json:"solve_ms"`
			RoundTripMS int    `json:"round_trip_ms"`
			Bits        int    `json:"bits"`
		} `json:"decisions"`
	}
	dr := adminReq(t, http.MethodGet, "/admin/decisions?action=solve&limit=all", nil)
	if err := json.NewDecoder(dr.Body).Decode(&dl); err != nil {
		t.Fatalf("decode /admin/decisions: %v", err)
	}
	var found bool
	for _, d := range dl.Decisions {
		if d.UA != ua {
			continue // another test's solve; this suite shares one daemon
		}
		found = true
		if d.Action != "solve" || d.Reason != "pow:solved" {
			t.Errorf("solve row = %s/%s, want solve/pow:solved", d.Action, d.Reason)
		}
		if d.URI != "/protected-page" || d.Host != powHost {
			t.Errorf("solve attribution = %s %s, want %s /protected-page", d.Host, d.URI, powHost)
		}
		// solvePoWThroughAngie reports elapsed_ms: 42.
		if d.SolveMS != 42 {
			t.Errorf("solve_ms = %d, want the reported 42", d.SolveMS)
		}
		if d.Bits <= 0 {
			t.Errorf("bits = %d, want the difficulty this challenge carried", d.Bits)
		}
		// Sane rather than nonzero: the point is that the challenge's issued-at
		// flowed through, which a zero or garbage value would show as decades.
		// Asserting strictly positive would rest on the journey never
		// completing inside a single millisecond.
		if d.RoundTripMS < 0 || d.RoundTripMS > 600_000 {
			t.Errorf("round_trip_ms = %d, want the server-measured issue to redeem", d.RoundTripMS)
		}
	}
	if !found {
		t.Fatalf("no solve recorded for %q in %+v", ua, dl.Decisions)
	}

	// And the histogram carries the domain, which is what answers the same
	// question over a Grafana horizon rather than a bounded ring.
	if n := metric(t, "guardian_challenge_solve_seconds_count", `domain=`); n <= 0 {
		t.Errorf("guardian_challenge_solve_seconds_count{domain=...} = %v, want a labelled series", n)
	}
}

// TestSpentChallengeCannotBeReplayed confirms a solved challenge is single-use:
// re-POSTing the same {challenge_id, nonce} after it has been spent is rejected
// (the mint-twice replay class).
func TestSpentChallengeCannotBeReplayed(t *testing.T) {
	ua := browserUA + " replay"
	host := powHost

	ch := fetchChallenge(t, "/replay-test", host, ua)
	nonce := solve(t, ch.Challenge, ch.Difficulty)
	post := func() *http.Response {
		return req(t, http.MethodPost, site+"/__guardian/pass",
			map[string]string{"Host": host, "User-Agent": ua, "Content-Type": "application/json"},
			strings.NewReader(`{"challenge_id":"`+ch.ChallengeID+`","nonce":"`+nonce+`","elapsed_ms":10}`))
	}

	if resp := post(); resp.StatusCode != http.StatusOK {
		t.Fatalf("first redeem: status %d, want 200", resp.StatusCode)
	}
	// Second redemption of the now-spent challenge must fail.
	if resp := post(); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replay redeem: status %d, want 403", resp.StatusCode)
	}
}

// TestNoJSMetaRefreshFallback exercises the JavaScript-free redemption path: a
// meta-refresh GET to /__guardian/pass?cid=...&nojs=1. It is rejected if the
// client did not demonstrably wait (NoJSMinDelay, 5s), then accepted with a
// 303 + cookie + redirect to the original URI after the wait.
func TestNoJSMetaRefreshFallback(t *testing.T) {
	ua := browserUA + " nojs"
	host := powHost

	ch := fetchChallenge(t, "/nojs-page?q=1", host, ua)
	url := site + "/__guardian/pass?cid=" + ch.ChallengeID + "&nojs=1"

	// Immediate redemption is too fast → rejected.
	resp := req(t, http.MethodGet, url, map[string]string{"Host": host, "User-Agent": ua}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("instant no-JS: status %d, want 403", resp.StatusCode)
	}

	// After the minimum wall-clock delay the same redemption succeeds.
	time.Sleep(6 * time.Second)
	resp = req(t, http.MethodGet, url, map[string]string{"Host": host, "User-Agent": ua}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("no-JS redeem: status %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/nojs-page?q=1" {
		t.Errorf("no-JS redirect = %q, want the original URI /nojs-page?q=1", loc)
	}
	var gotCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == "guardian_token" && c.Value != "" {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Error("no-JS redeem set no guardian_token cookie")
	}
}
