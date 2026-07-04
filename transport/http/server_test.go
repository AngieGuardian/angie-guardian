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
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(testYAML), 0o600); err != nil {
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
	engine := core.NewEngine(cfg, st, mgr, slog.Default())
	ts := httptest.NewServer(New(engine, cfg, mgr, st, slog.Default()))
	t.Cleanup(ts.Close)
	return ts
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
		Difficulty  int    `json:"difficulty"`
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

func solve(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := 0; n < 1_000_000; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		ok := true
		for i := 0; i < difficulty; i++ {
			nib := sum[i/2] >> 4
			if i%2 == 1 {
				nib = sum[i/2] & 0x0f
			}
			if nib != 0 {
				ok = false
				break
			}
		}
		if ok {
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
	if resp.Header.Get("X-Guardian-Action") != "challenge" || resp.Header.Get("X-Guardian-Difficulty") != "1" {
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

func TestChallengeRateLimit(t *testing.T) {
	ts := testServer(t)
	h := guardianHeaders("html.test", "198.51.100.9", "/", "Mozilla/5.0")
	var last int
	for i := 0; i < issuanceRateLimit+5; i++ {
		resp := do(t, "GET", ts.URL+"/challenge", h, nil)
		io.Copy(io.Discard, resp.Body)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d issuances: status = %d, want 429", issuanceRateLimit+5, last)
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
