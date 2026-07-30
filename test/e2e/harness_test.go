// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

// Package e2e drives the guardian end to end through a REAL Angie binary.
//
// Unlike the in-process tests in transport/http (which call the Go handler via
// httptest, with Angie out of the loop), this suite boots the full Path A
// topology from deploy/docker/compose.yaml:
//
//	Angie (reverse proxy, auth_request) ──► guardiand (sidecar) ──► whoami backend
//
// with testcontainers-go, then drives traffic through Angie on the published
// host ports and asserts on the guardian's decisions AND its report surface
// (Prometheus /metrics + the admin API).
//
// It is gated behind the `e2e` build tag so `go test ./...` stays fast and
// Docker-free; run it with `make e2e` or `go test -tags e2e ./test/e2e/...`.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	adminToken = "harness-admin-token" // guardian.e2e.yaml admin.token

	// powHost is the harness domain with pow.mode: always (guardian.e2e.yaml).
	powHost = "localhost"
	// wafOnlyHost has pow disabled: WAF runs, but no interstitial.
	wafOnlyHost = "api.localhost"
	// wpHost shares the common rules file but disables wp-probe by id
	// (waf.keywords.disabled_rule_ids); pow is off like wafOnlyHost.
	wpHost = "wp.localhost"
)

// Base URLs of the two published listeners, set in runSuite once the harness
// has picked free host ports (avoids colliding with whatever else runs on the
// box; the compose file publishes them via ${GUARDIAN_SITE_PORT}/
// ${GUARDIAN_ADMIN_PORT}).
var (
	site  string // the protected site, through Angie
	admin string // guardiand admin API + /metrics
	auth  string // guardiand auth hot path, published for the attack-mode test
)

// stack is the running compose stack, shared by every test via TestMain.
var stack compose.ComposeStack

// TestMain boots the compose stack once for the whole package, waits until
// Angie and guardiand are both serving, runs the tests, then tears it all down.
func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

// runSuite is split out so the deferred teardown runs before os.Exit.
func runSuite(m *testing.M) int {
	ctx := context.Background()

	c, err := compose.NewDockerCompose("../../deploy/docker/compose.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: compose parse:", err)
		return 1
	}
	stack = c

	// Pick three free host ports so the published listeners never collide with
	// anything else on the box, and hand them to compose via the env-var
	// defaults in compose.yaml.
	sitePort, err := freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: pick site port:", err)
		return 1
	}
	adminPort, err := freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: pick admin port:", err)
		return 1
	}
	authPort, err := freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: pick auth port:", err)
		return 1
	}
	site = fmt.Sprintf("http://127.0.0.1:%d", sitePort)
	admin = fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	auth = fmt.Sprintf("http://127.0.0.1:%d", authPort)
	stack = stack.WithEnv(map[string]string{
		"GUARDIAN_SITE_PORT":  strconv.Itoa(sitePort),
		"GUARDIAN_ADMIN_PORT": strconv.Itoa(adminPort),
		// The auth hot path is published so the attack-mode test can drive
		// /challenge directly from synthetic client IPs (trusted_proxy: true).
		"GUARDIAN_AUTH_PORT": strconv.Itoa(authPort),
		// The e2e config: identical to the manual harness's
		// guardian.docker.yaml except for a low PoW difficulty, so the
		// Go solver in this suite stays fast.
		"GUARDIAN_CONFIG": "./guardian.e2e.yaml",
	})

	// Wait strategies run in parallel per service. guardiand serves /healthz on
	// the admin listener (8072); Angie serves the protected site on :80 and
	// only starts once guardiand is healthy (compose depends_on).
	stack = stack.
		WaitForService("guardiand",
			wait.ForHTTP("/healthz").WithPort("8072/tcp").
				WithStartupTimeout(60*time.Second)).
		WaitForService("angie",
			wait.ForHTTP("/robots.txt").WithPort("80/tcp").
				WithStatusCodeMatcher(func(s int) bool { return s == http.StatusOK }).
				WithStartupTimeout(90*time.Second))

	upErr := stack.Up(ctx, compose.Wait(true))
	defer func() {
		down, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = stack.Down(down, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
	}()
	if upErr != nil {
		fmt.Fprintln(os.Stderr, "e2e: compose up:", upErr)
		return 1
	}

	// A clean slate: clear any behavioural block left on the shared Docker
	// gateway IP by a previous run before the assertions begin.
	clearGatewayBlocks()

	return m.Run()
}

// freePort asks the OS for an unused TCP port on the loopback, then releases it
// so compose can bind it. A brief TOCTOU window exists, but is negligible for a
// test harness.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// --- HTTP helpers -----------------------------------------------------------

// noRedirect does not follow redirects, so the no-JS 303 can be inspected.
var noRedirect = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// req is one request through Angie (or to the admin API) with optional headers.
// Because every request from the test host reaches guardiand as the Docker
// gateway IP, the Host header selects the guardian domain policy (Angie passes
// it through as X-Guardian-Host).
func req(t *testing.T, method, url string, headers map[string]string, body io.Reader) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		// net/http ignores a "Host" entry in Header: the wire Host must be set
		// on r.Host. Route it there so Angie (and thus guardiand's
		// X-Guardian-Host) sees the domain we're actually testing.
		if http.CanonicalHeaderKey(k) == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// postWithRetry POSTs body (rebuilt each attempt, since it is consumed on send)
// and retries on a transient upstream status (502/503) from the shared compose
// stack, which is not a passthrough failure but a momentary backend/sidecar
// hiccup. Returns the last response.
func postWithRetry(t *testing.T, url string, headers map[string]string, body string) *http.Response {
	t.Helper()
	var resp *http.Response
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		resp = req(t, http.MethodPost, url, headers, strings.NewReader(body))
		if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable {
			return resp
		}
		t.Logf("transient upstream status %d on attempt %d; retrying", resp.StatusCode, attempt+1)
	}
	return resp
}

// get is a GET through Angie to the protected site, with a Host and User-Agent.
func get(t *testing.T, path, host, ua string, extra map[string]string) *http.Response {
	t.Helper()
	h := map[string]string{"Host": host, "User-Agent": ua}
	for k, v := range extra {
		h[k] = v
	}
	return req(t, http.MethodGet, site+path, h, nil)
}

// bodyOf reads and returns the response body as a string.
func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- admin API helpers ------------------------------------------------------

// adminReq calls the guardiand admin API with the bearer token.
func adminReq(t *testing.T, method, path string, body io.Reader) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, admin+path, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := noRedirect.Do(r)
	if err != nil {
		t.Fatalf("admin %s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// blockStatus reports whether the admin API considers ip blocked, and why.
func blockStatus(t *testing.T, ip string) (blocked bool, reason string) {
	t.Helper()
	resp := adminReq(t, http.MethodGet, "/admin/blocks/"+ip, nil)
	var out struct {
		Blocked bool   `json:"blocked"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode block status: %v", err)
	}
	return out.Blocked, out.Reason
}

// offenses reports the 24h repeat-offender count behind the block-TTL
// doubling, 0 when the admin API omits it (never automatically blocked).
func offenses(t *testing.T, ip string) int64 {
	t.Helper()
	resp := adminReq(t, http.MethodGet, "/admin/blocks/"+ip, nil)
	var out struct {
		Offenses int64 `json:"offenses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode block detail: %v", err)
	}
	return out.Offenses
}

// blockIP places a manual block through the admin API.
func blockIP(t *testing.T, ip, reason string) {
	t.Helper()
	body := strings.NewReader(`{"reason":"` + reason + `"}`)
	if resp := adminReq(t, http.MethodPut, "/admin/blocks/"+ip, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("block %s: status %d", ip, resp.StatusCode)
	}
}

// unblock lifts a block, choosing whether the repeat-offender ladder goes with
// it. The counters that caused the block are cleared either way.
func unblock(t *testing.T, ip string, resetBackoff bool) {
	t.Helper()
	path := "/admin/blocks/" + ip + "?reset_backoff=" + strconv.FormatBool(resetBackoff)
	resp := adminReq(t, http.MethodDelete, path, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unblock %s: status %d", ip, resp.StatusCode)
	}
	var out struct {
		Reset struct {
			Incomplete bool `json:"incomplete"`
		} `json:"reset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode unblock response: %v", err)
	}
	if out.Reset.Incomplete {
		t.Fatalf("unblock %s reported an incomplete counter reset", ip)
	}
}

// activeBlocks returns every currently active behavioural block (IP →
// reason) from the admin API. All host traffic arrives from a single source
// IP, but its address depends entirely on the Docker daemon's configuration
// (bridge address pools, userland proxy on/off), so the suite must read the
// blocked IP back instead of guessing gateway addresses. Best-effort: nil on
// any error, since it is also used from teardown paths without a *testing.T.
func activeBlocks() map[string]string {
	r, err := http.NewRequest(http.MethodGet, admin+"/admin/blocks", nil)
	if err != nil {
		return nil
	}
	r.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := noRedirect.Do(r)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out struct {
		Blocks []struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		} `json:"blocks"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	blocks := make(map[string]string, len(out.Blocks))
	for _, b := range out.Blocks {
		blocks[b.IP] = b.Reason
	}
	return blocks
}

// unblockResetWindow mirrors core's unblockHoldWindow: for that long after an
// unblock, the IP cannot be automatically re-blocked, which is what stops a
// concurrent scorer from undoing the reset. The suite feels it far more than a
// real deployment does, because every request here shares one source IP, so
// one test's cleanup gags the next test's WAF block.
const unblockResetWindow = 2 * time.Second

// clearGatewayBlocks lifts every active behavioural block so a WAF `block`
// from one test cannot poison the next. The suite owns the whole stack (fresh
// store volume per run), so every block in it is ours to clear. Best-effort.
//
// It waits out the reset window when it actually cleared something, so the
// next test starts able to block again. A call that found nothing blocked
// wrote no guard and returns immediately, which is most of them.
func clearGatewayBlocks() {
	cleared := false
	for ip := range activeBlocks() {
		r, err := http.NewRequest(http.MethodDelete, admin+"/admin/blocks/"+ip, nil)
		if err != nil {
			continue
		}
		r.Header.Set("Authorization", "Bearer "+adminToken)
		if resp, err := noRedirect.Do(r); err == nil {
			resp.Body.Close()
			cleared = true
		}
	}
	if cleared {
		time.Sleep(unblockResetWindow)
	}
}

// findBlockedGateway returns the source IP that is currently blocked (host
// traffic shares one source IP; see activeBlocks for why its address cannot
// be assumed), or "" if none is blocked. Used by the block tests to read back
// the block the WAF just placed.
func findBlockedGateway(t *testing.T) (ip, reason string) {
	t.Helper()
	for ip, why := range activeBlocks() {
		return ip, why
	}
	return "", ""
}

// --- Prometheus metrics helpers --------------------------------------------

// metric fetches /metrics and returns the value of the first sample whose line
// starts with `name` and contains every label fragment in `labels` (e.g.
// `action="deny"`). Returns 0 if no such sample exists.
func metric(t *testing.T, name string, labels ...string) float64 {
	t.Helper()
	resp := req(t, http.MethodGet, admin+"/metrics", nil, nil)
	body := bodyOf(t, resp)
	var sum float64
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		ok := true
		for _, l := range labels {
			if !strings.Contains(line, l) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			sum += v
		}
	}
	return sum
}

// --- PoW solving through Angie ----------------------------------------------

var dataRe = regexp.MustCompile(`<script id="guardian-data" type="application/json">(.*?)</script>`)

// challengeData is the JSON the interstitial embeds for its JS solver.
// Difficulty is in leading zero bits.
type challengeData struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	Difficulty  int    `json:"difficulty_bits"`
	PassURL     string `json:"pass_url"`
}

// fetchChallenge GETs the interstitial through Angie and parses its embedded
// challenge JSON. host/ua must match what a later /pass POST uses, because the
// challenge is bound to {host, ip} and the token to {ip, ua}.
func fetchChallenge(t *testing.T, path, host, ua string) challengeData {
	t.Helper()
	// Angie only serves /challenge on a 401 (auth_request diverts there). A
	// GET on a PoW-always host yields the interstitial with a
	// 200 (Angie's error_page 401 = @guardian_challenge returns 200 HTML).
	resp := get(t, path, host, ua, nil)
	page := bodyOf(t, resp)
	m := dataRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no guardian-data JSON in challenge page (status %d):\n%s", resp.StatusCode, page)
	}
	var d challengeData
	if err := json.Unmarshal([]byte(m[1]), &d); err != nil {
		t.Fatalf("guardian-data is not valid JSON: %v", err)
	}
	return d
}

// solve brute-forces a nonce whose SHA-256(challenge+nonce) has `difficulty`
// leading zero bits, the exact check core/pow does (challenge.go
// leadingZeroBits). Harness difficulties are small (~16 bits) so this is fast.
func solve(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := 0; n < 1<<30; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		if leadingZeroBits(sum[:]) >= difficulty {
			return nonce
		}
	}
	t.Fatalf("no nonce found for difficulty %d bits", difficulty)
	return ""
}

func leadingZeroBits(sum []byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// solvePoWThroughAngie walks the full browser journey through Angie: fetch the
// interstitial, solve it, POST the solution to /__guardian/pass, and return the
// guardian_token cookie value. It fails the test if any step misbehaves.
func solvePoWThroughAngie(t *testing.T, path, host, ua string) string {
	t.Helper()
	ch := fetchChallenge(t, path, host, ua)
	nonce := solve(t, ch.Challenge, ch.Difficulty)

	payload, _ := json.Marshal(map[string]any{
		"challenge_id": ch.ChallengeID,
		"nonce":        nonce,
		"elapsed_ms":   42,
	})
	resp := req(t, http.MethodPost, site+"/__guardian/pass",
		map[string]string{
			"Host":         host,
			"User-Agent":   ua,
			"Content-Type": "application/json",
		}, strings.NewReader(string(payload)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/__guardian/pass: status %d, body %s", resp.StatusCode, bodyOf(t, resp))
	}
	for _, c := range resp.Cookies() {
		if c.Name == "guardian_token" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("no guardian_token cookie in /__guardian/pass response")
	return ""
}

// --- container control (for the fail-mode test) -----------------------------

// stopGuardiand / startGuardiand toggle the sidecar to exercise Angie's fail
// mode. Used by the fail-mode test, which restores state afterwards.
func stopGuardiand(t *testing.T) {
	t.Helper()
	ctr, err := stack.ServiceContainer(context.Background(), "guardiand")
	if err != nil {
		t.Fatalf("guardiand container: %v", err)
	}
	timeout := 10 * time.Second
	if err := ctr.Stop(context.Background(), &timeout); err != nil {
		t.Fatalf("stop guardiand: %v", err)
	}
}

func startGuardiand(t *testing.T) {
	t.Helper()
	ctr, err := stack.ServiceContainer(context.Background(), "guardiand")
	if err != nil {
		t.Fatalf("guardiand container: %v", err)
	}
	if err := ctr.Start(context.Background()); err != nil {
		t.Fatalf("start guardiand: %v", err)
	}
	// Wait until the admin /healthz answers again before returning.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r, err := noRedirect.Get(admin + "/healthz")
		if err == nil {
			r.Body.Close()
			if r.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("guardiand did not come back healthy after restart")
}

// guardiandLogs returns the current guardiand container logs (for asserting on
// structured decision lines when needed).
func guardiandLogs(t *testing.T) string {
	t.Helper()
	ctr, err := stack.ServiceContainer(context.Background(), "guardiand")
	if err != nil {
		t.Fatalf("guardiand container: %v", err)
	}
	rc, err := ctr.Logs(context.Background())
	if err != nil {
		t.Fatalf("guardiand logs: %v", err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return string(b)
}

// ensure the testcontainers import is used even if a refactor drops the only
// reference; the type alias documents what ServiceContainer returns.
var _ = func(*testcontainers.DockerContainer) {}
