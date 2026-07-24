// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestStoreOutageFailOpen proves the flagship fail-open contract end to end
// (issue #10). On the shared-store backend (valkey, redis protocol), it kills
// the store mid-run and asserts, in order:
//
//  1. requests keep flowing through Angie with no 5xx: the interstitial still
//     renders (stateless issuance fallback), a full challenge journey still
//     mints a working token, and allowlisted paths still reach the backend;
//  2. a block placed before the outage keeps denying (the in-process mirror
//     fronts the store, so known blocks survive a store outage);
//  3. the in-process counter cache keeps enforcing the per-IP challenge
//     issuance limit (429 past the cap) with no store at all;
//  4. /readyz honestly reports the outage (503) while /healthz stays 200, so
//     orchestrators see degraded-but-alive;
//
// then restarts the store and asserts clean recovery: /readyz back to 200,
// the pre-outage block still enforced, new blocks placeable again, a stateful
// challenge journey working, and the issuance limiter still biting.
//
// The test boots its own compose stack (base + chaos overlay) so killing the
// store cannot disturb the shared suite stack.
func TestStoreOutageFailOpen(t *testing.T) {
	ctx := context.Background()
	c, err := compose.NewDockerCompose(
		"../../deploy/docker/compose.yaml",
		"../../deploy/docker/compose.chaos.yaml",
	)
	if err != nil {
		t.Fatalf("chaos compose parse: %v", err)
	}
	ports := make([]int, 3)
	for i := range ports {
		p, err := freePort()
		if err != nil {
			t.Fatalf("pick free port: %v", err)
		}
		ports[i] = p
	}
	chaosSite := fmt.Sprintf("http://127.0.0.1:%d", ports[0])
	chaosAdmin := fmt.Sprintf("http://127.0.0.1:%d", ports[1])
	chaosAuth := fmt.Sprintf("http://127.0.0.1:%d", ports[2])
	chaosStack := c.WithEnv(map[string]string{
		"GUARDIAN_SITE_PORT":  strconv.Itoa(ports[0]),
		"GUARDIAN_ADMIN_PORT": strconv.Itoa(ports[1]),
		"GUARDIAN_AUTH_PORT":  strconv.Itoa(ports[2]),
		"GUARDIAN_CONFIG":     "./guardian.e2e-chaos.yaml",
	}).
		WaitForService("guardiand",
			wait.ForHTTP("/healthz").WithPort("8072/tcp").
				WithStartupTimeout(60*time.Second)).
		WaitForService("angie",
			wait.ForHTTP("/robots.txt").WithPort("80/tcp").
				WithStatusCodeMatcher(func(s int) bool { return s == http.StatusOK }).
				WithStartupTimeout(90*time.Second))
	t.Cleanup(func() {
		down, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = chaosStack.Down(down, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
	})
	if err := chaosStack.Up(ctx, compose.Wait(true)); err != nil {
		t.Fatalf("chaos compose up: %v", err)
	}

	// --- helpers bound to the chaos stack's ports ---------------------------

	chaosAdminReq := func(method, path, body string) *http.Response {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		r, err := http.NewRequest(method, chaosAdmin+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := noRedirect.Do(r)
		if err != nil {
			t.Fatalf("chaos admin %s %s: %v", method, path, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	// probe returns a status code, 0 on connection error (tolerated: the
	// pollers below decide what a non-answer means).
	probe := func(url string) int {
		r, err := noRedirect.Get(url)
		if err != nil {
			return 0
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r.StatusCode
	}
	waitStatus := func(url string, want int, within time.Duration, why string) {
		t.Helper()
		deadline := time.Now().Add(within)
		last := -1
		for time.Now().Before(deadline) {
			if last = probe(url); last == want {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s: %s stayed at %d, want %d", why, url, last, want)
	}
	guardHeaders := func(ip string) map[string]string {
		return map[string]string{
			"X-Guardian-Host": powHost, "X-Guardian-IP": ip,
			"X-Guardian-UA": browserUA, "X-Guardian-URI": "/page",
		}
	}
	authStatus := func(ip string) int {
		t.Helper()
		return req(t, http.MethodGet, chaosAuth+"/auth", guardHeaders(ip), nil).StatusCode
	}
	// journey walks the full browser flow through Angie: interstitial,
	// brute-force solve, redeem on /__guardian/pass, then reach the backend
	// with the minted cookie. It returns the challenge id so callers can
	// assert which issuance path (stateful vs stateless s1.) produced it.
	journey := func(stage string) (challengeID string) {
		t.Helper()
		resp := req(t, http.MethodGet, chaosSite+"/page",
			map[string]string{"Host": powHost, "User-Agent": browserUA}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: interstitial status %d, want 200", stage, resp.StatusCode)
		}
		m := dataRe.FindStringSubmatch(bodyOf(t, resp))
		if m == nil {
			t.Fatalf("%s: no challenge JSON in interstitial", stage)
		}
		id, challenge, difficulty := parseChallengeJSON(t, m[1])
		nonce := solve(t, challenge, difficulty)
		payload := fmt.Sprintf(`{"challenge_id":%q,"nonce":%q,"elapsed_ms":42}`, id, nonce)
		pass := req(t, http.MethodPost, chaosSite+"/__guardian/pass",
			map[string]string{"Host": powHost, "User-Agent": browserUA, "Content-Type": "application/json"},
			strings.NewReader(payload))
		if pass.StatusCode != http.StatusOK {
			t.Fatalf("%s: /__guardian/pass status %d, body %s", stage, pass.StatusCode, bodyOf(t, pass))
		}
		var token string
		for _, ck := range pass.Cookies() {
			if ck.Name == "guardian_token" {
				token = ck.Value
			}
		}
		if token == "" {
			t.Fatalf("%s: no guardian_token cookie minted", stage)
		}
		through := req(t, http.MethodGet, chaosSite+"/page", map[string]string{
			"Host": powHost, "User-Agent": browserUA, "Cookie": "guardian_token=" + token,
		}, nil)
		if through.StatusCode != http.StatusOK {
			t.Fatalf("%s: vouched request status %d, want 200 backend", stage, through.StatusCode)
		}
		if body := bodyOf(t, through); !strings.Contains(body, "Hostname:") {
			t.Fatalf("%s: vouched request did not reach the backend:\n%s", stage, body)
		}
		return id
	}
	// hammer drives /challenge as ip until the issuance limiter answers 429.
	// The limit is 30/h (guardian.e2e-chaos.yaml); the attempt cap leaves room
	// to rebuild the count even if the hour bucket rolled mid-test.
	hammer := func(ip, stage string) {
		t.Helper()
		for attempt := 0; attempt < 70; attempt++ {
			resp := req(t, http.MethodGet, chaosAuth+"/challenge", guardHeaders(ip), nil)
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode == http.StatusTooManyRequests {
				return
			}
		}
		t.Fatalf("%s: issuance limiter never answered 429 for %s", stage, ip)
	}
	toggleValkey := func(start bool) {
		t.Helper()
		ctr, err := chaosStack.ServiceContainer(context.Background(), "valkey")
		if err != nil {
			t.Fatalf("valkey container: %v", err)
		}
		if start {
			if err := ctr.Start(context.Background()); err != nil {
				t.Fatalf("start valkey: %v", err)
			}
			return
		}
		timeout := 10 * time.Second
		if err := ctr.Stop(context.Background(), &timeout); err != nil {
			t.Fatalf("stop valkey: %v", err)
		}
	}

	// --- baseline: store up ---------------------------------------------------

	waitStatus(chaosAdmin+"/readyz", http.StatusOK, 45*time.Second, "baseline")
	if id := journey("baseline"); strings.HasPrefix(id, "s1.") {
		t.Fatalf("baseline challenge %q is stateless; want stateful with the store up", id)
	}

	const blockedIP = "203.0.113.66"
	if r := chaosAdminReq(http.MethodPut, "/admin/blocks/"+blockedIP,
		`{"reason":"chaos-e2e","ttl":"30m"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("place pre-outage block: status %d, body %s", r.StatusCode, bodyOf(t, r))
	}
	if s := authStatus(blockedIP); s != http.StatusForbidden {
		t.Fatalf("pre-outage block not enforced: /auth = %d, want 403", s)
	}

	// --- outage ---------------------------------------------------------------

	toggleValkey(false)

	// The store health probe (10s cadence) must flip /readyz to 503 while
	// liveness stays green: degraded, not dead.
	waitStatus(chaosAdmin+"/readyz", http.StatusServiceUnavailable, 45*time.Second, "outage detection")
	if s := probe(chaosAdmin + "/healthz"); s != http.StatusOK {
		t.Fatalf("/healthz = %d during outage, want 200 (liveness must not follow the store)", s)
	}

	// Requests keep flowing with no 5xx: allowlisted path straight through,
	// and the full challenge journey still works, now on the stateless
	// issuance fallback.
	for i := 0; i < 10; i++ {
		if s := probe(chaosSite + "/robots.txt"); s != http.StatusOK {
			t.Fatalf("allowlisted request %d during outage: status %d, want 200", i+1, s)
		}
	}
	if id := journey("outage"); !strings.HasPrefix(id, "s1.") {
		t.Fatalf("outage challenge %q is stateful; want the s1. stateless fallback", id)
	}

	// A block the mirror already knows keeps denying with the store gone.
	if s := authStatus(blockedIP); s != http.StatusForbidden {
		t.Fatalf("block dropped during outage: /auth = %d, want 403 (mirror must front the store)", s)
	}

	// The counter cache alone enforces the per-IP issuance limit.
	const hammerIP = "203.0.113.99"
	hammer(hammerIP, "outage")

	// --- recovery -------------------------------------------------------------

	toggleValkey(true)
	waitStatus(chaosAdmin+"/readyz", http.StatusOK, 60*time.Second, "recovery")

	// The pre-outage block survived the store restart (appendonly) and still
	// denies; fresh block writes work again; issuance goes back to stateful;
	// and the limiter still bites for the hammered IP.
	if s := authStatus(blockedIP); s != http.StatusForbidden {
		t.Fatalf("pre-outage block gone after recovery: /auth = %d, want 403", s)
	}
	const recoveredIP = "203.0.113.77"
	if r := chaosAdminReq(http.MethodPut, "/admin/blocks/"+recoveredIP,
		`{"reason":"chaos-e2e-recovery","ttl":"30m"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("place post-recovery block: status %d", r.StatusCode)
	}
	if s := authStatus(recoveredIP); s != http.StatusForbidden {
		t.Fatalf("post-recovery block not enforced: /auth = %d, want 403", s)
	}
	if id := journey("recovery"); strings.HasPrefix(id, "s1.") {
		t.Fatalf("recovery challenge %q is stateless; want stateful with the store back", id)
	}
	hammer(hammerIP, "recovery")
}

// parseChallengeJSON decodes the interstitial's embedded guardian-data JSON.
// Split from parseChallenge (which takes a whole *http.Response) so the chaos
// journey can reuse an already-read body.
func parseChallengeJSON(t *testing.T, raw string) (id, challenge string, difficulty int) {
	t.Helper()
	var cd challengeData
	if err := json.Unmarshal([]byte(raw), &cd); err != nil {
		t.Fatalf("decode challenge json: %v", err)
	}
	return cd.ChallengeID, cd.Challenge, cd.Difficulty
}
