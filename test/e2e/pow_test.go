// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
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
	// The snippet's location-scoped CSP must reach the client: it permits the
	// blob: solver worker and, by defining an add_header in the location,
	// stops a vhost-level site CSP from applying to (and breaking) this page.
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "worker-src blob:") {
		t.Fatalf("interstitial Content-Security-Policy = %q, want worker-src blob:", csp)
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
