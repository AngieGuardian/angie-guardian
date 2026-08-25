// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestStoreOutageFailOpen proves the flagship fail-open contract end to end
// (issue #10). On the shared-store backend (valkey, redis protocol), it takes
// the store away mid-run in BOTH failure modes: first a network partition
// (paused container: the address stays but packets silently drop, so every
// store op pays its full timeout budget), then a process crash plus restart
// (stopped container: fast connection errors, then real recovery). During
// each outage it asserts, in order:
//
//  1. requests keep flowing through Angie with no 5xx. Fail-open is layered
//     and WHICH layer answers depends on how the dead store fails on this
//     host: when store ops error fast (connection refused), guardian answers
//     the auth hop inside the Angie glue's 2s budget and the interstitial
//     renders on the stateless issuance fallback; when the dead address
//     silently drops packets, the auth hop may exceed its budget and Angie's
//     own error_page fail-open serves the backend directly. Either is the
//     designed degrade; a 5xx or a deny is the only failure.
//  2. guardian's own outage behaviour, deterministically on the direct auth
//     port (no Angie timeout in that path): challenge issuance falls back to
//     the stateless s1. format, a solution still redeems (token minted
//     fail-open), and the minted token vouches;
//  3. a block placed before the outage keeps denying (the in-process mirror
//     fronts the store, so known blocks survive a store outage);
//  4. the in-process counter cache keeps enforcing the per-IP challenge
//     issuance limit (429 past the cap) with no store at all;
//  5. /readyz honestly reports the outage (503) while /healthz stays 200, so
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
		"../../deploy/docker/compose.e2e.yaml",
		"../../deploy/docker/compose.chaos.yaml",
	)
	if err != nil {
		t.Fatalf("chaos compose parse: %v", err)
	}
	ports := make([]int, 4)
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
	tlsDir, err := makeSharedTLSDir()
	if err != nil {
		t.Fatalf("create chaos TLS directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tlsDir) })
	tlsCertPath, tlsKeyPath, _, err := writeSelfSignedCertificate(tlsDir)
	if err != nil {
		t.Fatalf("create chaos TLS certificate: %v", err)
	}
	chaosStack := c.WithEnv(map[string]string{
		"GUARDIAN_SITE_PORT":  strconv.Itoa(ports[0]),
		"GUARDIAN_ADMIN_PORT": strconv.Itoa(ports[1]),
		"GUARDIAN_AUTH_PORT":  strconv.Itoa(ports[2]),
		"GUARDIAN_TLS_PORT":   strconv.Itoa(ports[3]),
		"GUARDIAN_TLS_CERT":   tlsCertPath,
		"GUARDIAN_TLS_KEY":    tlsKeyPath,
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
		printServiceLogs(ctx, chaosStack, "angie")
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
	// statefulJourney runs journey and requires the challenge to come from
	// the stateful issuance path. A single attempt may draw the stateless
	// fallback even with the store up: the store client's per-op budget is
	// deliberately tight (core/store/redis.go), so one slow SET on a loaded
	// runner makes guardian fail open by design. Only issuance that stays
	// stateless across attempts is a failure. The attempt cap keeps both
	// call sites together well inside the 8/h issuance limit the journeys
	// share (they run as the compose gateway IP).
	statefulJourney := func(stage string) {
		t.Helper()
		const attempts = 3
		var id string
		for i := 1; i <= attempts; i++ {
			if id = journey(stage); !strings.HasPrefix(id, "s1.") {
				return
			}
			t.Logf("%s: attempt %d/%d drew the stateless fallback (transient store timeout); retrying", stage, i, attempts)
			time.Sleep(2 * time.Second)
		}
		t.Fatalf("%s: challenge %q still stateless after %d attempts; want stateful with the store up", stage, id, attempts)
	}
	// hammer drives /challenge as ip until the issuance limiter answers 429.
	// The limit is 8/h (guardian.e2e-chaos.yaml): low, because each pre-limit
	// request during the outage pays the store timeouts before the stateless
	// fallback answers. The attempt cap leaves room to rebuild the count even
	// if the hour bucket rolled mid-test.
	hammer := func(ip, stage string) {
		t.Helper()
		for attempt := 0; attempt < 25; attempt++ {
			resp := req(t, http.MethodGet, chaosAuth+"/challenge", guardHeaders(ip), nil)
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode == http.StatusTooManyRequests {
				return
			}
		}
		t.Fatalf("%s: issuance limiter never answered 429 for %s", stage, ip)
	}
	valkeyContainerID := func() string {
		t.Helper()
		ctr, err := chaosStack.ServiceContainer(context.Background(), "valkey")
		if err != nil {
			t.Fatalf("valkey container: %v", err)
		}
		return ctr.GetContainerID()
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
	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	pauseValkey := func(pause bool) {
		t.Helper()
		id := valkeyContainerID()
		if pause {
			if _, err := docker.ContainerPause(context.Background(), id, client.ContainerPauseOptions{}); err != nil {
				t.Fatalf("pause valkey: %v", err)
			}
			return
		}
		if _, err := docker.ContainerUnpause(context.Background(), id, client.ContainerUnpauseOptions{}); err != nil {
			t.Fatalf("unpause valkey: %v", err)
		}
	}

	// assertOutage runs the full during-outage assertion set. challengeIP must
	// be unique per call so the challenge-farming escalation counter of one
	// phase cannot bleed into the next phase's difficulty.
	const blockedIP = "203.0.113.66"
	const hammerIP = "203.0.113.99"
	assertOutage := func(stage, challengeIP string) {
		t.Helper()

		// The store health probe (10s cadence) must flip /readyz to 503 while
		// liveness stays green: degraded, not dead.
		waitStatus(chaosAdmin+"/readyz", http.StatusServiceUnavailable, 45*time.Second, stage+" detection")
		if s := probe(chaosAdmin + "/healthz"); s != http.StatusOK {
			t.Fatalf("%s: /healthz = %d, want 200 (liveness must not follow the store)", stage, s)
		}

		// Requests keep flowing with no 5xx: allowlisted paths straight through.
		for i := 0; i < 5; i++ {
			if s := probe(chaosSite + "/robots.txt"); s != http.StatusOK {
				t.Fatalf("%s: allowlisted request %d: status %d, want 200", stage, i+1, s)
			}
		}
		// An unvouched page request through Angie must also keep flowing. Which
		// fail-open layer answers depends on runner speed (see the test
		// comment): guardian's interstitial inside the 2s auth budget, or
		// Angie's error_page fail-open serving the backend past it. Classify,
		// accept both.
		resp := req(t, http.MethodGet, chaosSite+"/page",
			map[string]string{"Host": powHost, "User-Agent": browserUA}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: unvouched page = %d, want 200 (interstitial or fail-open backend)", stage, resp.StatusCode)
		}
		if body := bodyOf(t, resp); dataRe.MatchString(body) {
			t.Logf("%s: guardian served the interstitial within the auth budget", stage)
		} else if strings.Contains(body, "Hostname:") {
			t.Logf("%s: Angie error_page fail-open served the backend", stage)
		} else {
			t.Fatalf("%s: 200 with neither interstitial nor backend body:\n%s", stage, body)
		}

		// Guardian's own outage behaviour, deterministically on the direct
		// auth port (no Angie timeout in this path): issuance falls back to
		// the stateless format, the solution redeems (token minted
		// fail-open), and the minted token vouches.
		chResp := req(t, http.MethodGet, chaosAuth+"/challenge", guardHeaders(challengeIP), nil)
		if chResp.StatusCode != http.StatusOK {
			t.Fatalf("%s: direct /challenge = %d, want 200", stage, chResp.StatusCode)
		}
		m := dataRe.FindStringSubmatch(bodyOf(t, chResp))
		if m == nil {
			t.Fatalf("%s: no challenge JSON on the direct auth port", stage)
		}
		id, challenge, difficulty := parseChallengeJSON(t, m[1])
		if !strings.HasPrefix(id, "s1.") {
			t.Fatalf("%s: challenge %q is stateful; want the s1. stateless fallback", stage, id)
		}
		nonce := solve(t, challenge, difficulty)
		pass := req(t, http.MethodPost, chaosAuth+"/pass", map[string]string{
			"X-Guardian-Host": powHost, "X-Guardian-IP": challengeIP,
			"X-Guardian-UA": browserUA, "Content-Type": "application/json",
		}, strings.NewReader(fmt.Sprintf(`{"challenge_id":%q,"nonce":%q}`, id, nonce)))
		if pass.StatusCode != http.StatusOK {
			t.Fatalf("%s: stateless redeem = %d, want 200 (token must mint fail-open)", stage, pass.StatusCode)
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
		vouched := guardHeaders(challengeIP)
		vouched["X-Guardian-Cookie"] = "guardian_token=" + token
		if s := req(t, http.MethodGet, chaosAuth+"/auth", vouched, nil).StatusCode; s != http.StatusOK {
			t.Fatalf("%s: minted token rejected: /auth = %d, want 200", stage, s)
		}

		// A block the mirror already knows keeps denying with the store gone.
		if s := authStatus(blockedIP); s != http.StatusForbidden {
			t.Fatalf("%s: block dropped: /auth = %d, want 403 (mirror must front the store)", stage, s)
		}

		// The counter cache alone enforces the per-IP issuance limit.
		hammer(hammerIP, stage)
	}

	// --- baseline: store up ---------------------------------------------------

	waitStatus(chaosAdmin+"/readyz", http.StatusOK, 45*time.Second, "baseline")
	statefulJourney("baseline")

	if r := chaosAdminReq(http.MethodPut, "/admin/blocks/"+blockedIP,
		`{"reason":"chaos-e2e","ttl":"30m"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("place pre-outage block: status %d, body %s", r.StatusCode, bodyOf(t, r))
	}
	if s := authStatus(blockedIP); s != http.StatusForbidden {
		t.Fatalf("pre-outage block not enforced: /auth = %d, want 403", s)
	}

	// --- outage 1: network partition ------------------------------------------
	// A paused container keeps its address but silently drops packets, the
	// harshest failure mode: every store op pays its full dial/read timeouts.
	// This phase pins the timeout budget in core/store/redis.go NewRedis.

	pauseValkey(true)
	assertOutage("partition", "203.0.113.88")
	pauseValkey(false)
	waitStatus(chaosAdmin+"/readyz", http.StatusOK, 60*time.Second, "partition recovery")
	if s := authStatus(blockedIP); s != http.StatusForbidden {
		t.Fatalf("block gone after partition recovery: /auth = %d, want 403", s)
	}

	// --- outage 2: store process death and restart ----------------------------
	// A stopped container fails fast (refused/unresolvable), and the restart
	// proves recovery against a store that actually went away.

	toggleValkey(false)
	assertOutage("crash", "203.0.113.89")
	toggleValkey(true)
	waitStatus(chaosAdmin+"/readyz", http.StatusOK, 60*time.Second, "crash recovery")

	// The pre-outage block survived the store restart (appendonly) and still
	// denies; fresh block writes work again; issuance goes back to stateful;
	// and the limiter still bites for the hammered IP.
	if s := authStatus(blockedIP); s != http.StatusForbidden {
		t.Fatalf("pre-outage block gone after recovery: /auth = %d, want 403", s)
	}
	// The store process restarted moments ago, so the client's connection pool
	// can still hold connections to the one that died. core/store/redis.go caps
	// MaxRetries at 1 on purpose, so a stalled store cannot eat the 2s auth
	// budget, which means a write that draws a dead connection twice fails
	// rather than being retried into submission. /readyz turning OK proves one
	// probe op round-tripped, not that every pooled connection has been reaped.
	//
	// So the assertion is "writes come back promptly after recovery", not "the
	// very first write after /readyz is OK". Same transient class, and the same
	// bounded-retry shape, as statefulJourney above. This flaked exactly once in
	// CI (pipeline 11431, July 29 2026) and passed on a retry of the same SHA.
	const recoveredIP = "203.0.113.77"
	const blockAttempts = 3
	placed, lastStatus := false, 0
	for i := 1; i <= blockAttempts && !placed; i++ {
		r := chaosAdminReq(http.MethodPut, "/admin/blocks/"+recoveredIP,
			`{"reason":"chaos-e2e-recovery","ttl":"30m"}`)
		if r.StatusCode == http.StatusOK {
			placed = true
			if i > 1 {
				t.Logf("post-recovery block landed on attempt %d/%d", i, blockAttempts)
			}
			break
		}
		lastStatus = r.StatusCode
		t.Logf("place post-recovery block: attempt %d/%d = %d (transient store error); retrying",
			i, blockAttempts, lastStatus)
		time.Sleep(2 * time.Second)
	}
	if !placed {
		// Carry guardiand's own account of the failure: without it, a CI flake
		// leaves only a bare status code to reason from, which is exactly the
		// position the July 2026 failure left us in.
		t.Fatalf("place post-recovery block: still %d after %d attempts\nguardiand logs (tail):\n%s",
			lastStatus, blockAttempts, logTail(guardiandLogs(t), 40))
	}
	if s := authStatus(recoveredIP); s != http.StatusForbidden {
		t.Fatalf("post-recovery block not enforced: /auth = %d, want 403", s)
	}
	statefulJourney("recovery")
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

// logTail returns the last n lines of a container log, so a chaos failure can
// carry guardiand's own view of it without dumping the whole run into CI output.
func logTail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
