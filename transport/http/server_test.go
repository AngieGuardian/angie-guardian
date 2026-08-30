// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"golang.org/x/crypto/argon2"
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

func testServer(t testing.TB) *httptest.Server {
	t.Helper()
	return testServerWithYAML(t, testYAML)
}

func testServerWithYAML(t testing.TB, yaml string) *httptest.Server {
	t.Helper()
	ts, _ := testServerAndHandler(t, yaml)
	return ts
}

func testServerAndHandler(t testing.TB, yaml string) (*httptest.Server, *Server) {
	t.Helper()
	return testServerAndHandlerWithStore(t, yaml, store.NewMemory(), nil)
}

// testServerWithMetrics is the same stack wired to a real registry, for the
// tests that assert on a counter rather than on a response.
func testServerWithMetrics(t testing.TB, yaml string) (*httptest.Server, *Server, *metrics.Metrics) {
	t.Helper()
	m := metrics.New("memory")
	ts, h := testServerAndHandlerWithStore(t, yaml, store.NewMemory(), m)
	return ts, h, m
}

func testServerAndHandlerWithStore(t testing.TB, yaml string, st store.Store, m *metrics.Metrics) (*httptest.Server, *Server) {
	t.Helper()
	return testServerAndHandlerWithStoreAndLogger(t, yaml, st, m, slog.Default())
}

func testServerAndHandlerWithStoreAndLogger(t testing.TB, yaml string, st store.Store, m *metrics.Metrics, log *slog.Logger) (*httptest.Server, *Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := pow.NewManager(key, st)
	mgr.NoJSMinDelay = 50 * time.Millisecond
	engine, err := core.NewEngine(cfg, st, mgr, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	// Only when a test asked for a registry: SetMetrics also pushes the handle
	// into intel and the anomaly models, and there is no reason for the thirty
	// tests that pass nil to take that path at all.
	if m != nil {
		engine.SetMetrics(m)
	}
	h := New(engine, mgr, st, m, log)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, h
}

type unavailableCASStore struct{ store.Store }

func (s unavailableCASStore) CompareAndSwap(context.Context, string, []byte, []byte, time.Duration) (bool, error) {
	return false, errors.New("store unavailable")
}

type blockingGetStore struct {
	store.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingGetStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
		return s.Store.Get(ctx, key)
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
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

func TestRequestContextExposesEffectiveHostAsHeader(t *testing.T) {
	h := &Server{}
	req := httptest.NewRequest(http.MethodGet, "http://internal/auth", nil)
	req.Host = "internal"
	req.Header.Set("X-Guardian-Host", "public.example")
	ctx := h.requestContext(req)
	if got := ctx.Header("Host"); len(got) != 1 || got[0] != "public.example" {
		t.Fatalf("header:host = %v, want public.example", got)
	}
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

// require_proxied must reject identity-trusting endpoints when the
// X-Guardian-* headers are absent (the request bypassed the Angie glue), and
// must leave /healthz and /denied open: the systemd healthcheck probes
// headerless and the glue sets no headers on @guardian_denied.
func TestRequireProxiedGate(t *testing.T) {
	ts := testServerWithYAML(t, "require_proxied: true\n"+testYAML)

	for _, path := range []string{"/auth", "/challenge", "/pass", PassPath} {
		resp := do(t, "GET", ts.URL+path, nil, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s without X-Guardian-IP: status = %d, want 403", path, resp.StatusCode)
		}
	}

	// With the glue headers present, evaluation proceeds normally.
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0"), nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Guardian-Action") != "allow" {
		t.Fatalf("proxied allow: status = %d action = %q", resp.StatusCode, resp.Header.Get("X-Guardian-Action"))
	}

	if resp := do(t, "GET", ts.URL+"/healthz", nil, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz must stay open under require_proxied: status = %d", resp.StatusCode)
	}
	// /denied always answers 403, but it must be the styled HTML page, not
	// the plain-text gate rejection: the glue sets no headers on it.
	resp = do(t, "GET", ts.URL+"/denied", nil, nil)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != http.StatusForbidden ||
		!strings.HasPrefix(ct, "text/html") {
		t.Errorf("/denied: status = %d content-type = %q, want the styled 403 page", resp.StatusCode, ct)
	}

	// Default-off: the same headerless probe keeps working (dev, tests, curl).
	off := testServer(t)
	if resp := do(t, "GET", off.URL+"/auth", nil, nil); resp.StatusCode == http.StatusForbidden &&
		resp.Header.Get("X-Guardian-Action") == "" {
		t.Fatalf("require_proxied off must fall back to the socket address, got bare %d", resp.StatusCode)
	}
}

// TestAuthHeaderAndMethodRules proves the auth endpoint feeds the WAF what
// header/method rules need: named Accept and Referer rules see the headers the
// auth subrequest inherits from the client, and a methods-only rule sees the
// method relayed via X-Guardian-Method.
func TestAuthHeaderAndMethodRules(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(`rules:
  - id: api-json
    action: allow
    targets: [ "header:accept" ]
    regexes: [ 'application/(json|problem\+json)' ]
  - id: api-path
    action: deny
    targets: [ path ]
    keywords: [ "/api/" ]
  - id: jndi-header
    targets: [ "header:referer" ]
    keywords: [ "${jndi:" ]
  - id: no-track
    methods: [ TRACK ]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var decisionLog bytes.Buffer
	log := slog.New(slog.NewTextHandler(&decisionLog, nil))
	ts, _ := testServerAndHandlerWithStoreAndLogger(t, fmt.Sprintf(`store: { backend: memory }
defaults:
  waf: { rules: { enabled: true, files: [ "%s" ] } }
`, rules), store.NewMemory(), nil, log)

	// Clean request: allowed.
	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clean: status = %d, want 200", resp.StatusCode)
	}

	// The generic named-header path handles Accept without special plumbing.
	// Because file order is policy order, the allow rule wins over the later
	// path deny when both match.
	h := guardianHeaders("plain.test", "198.51.100.7", "/api/items", "api-client/1.0")
	h["Accept"] = "text/html, Application/Problem+JSON; Charset=UTF-8"
	resp = do(t, "GET", ts.URL+"/auth", h, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Guardian-Reason") != "waf:api-json" {
		t.Fatalf("allowed Accept: status = %d reason = %q, want 200 waf:api-json",
			resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}
	if got := decisionLog.String(); !strings.Contains(got, "action=allow") || !strings.Contains(got, "reason=waf:api-json") {
		t.Fatalf("WAF allow decision was not logged with its rule ID: %s", got)
	}

	h = guardianHeaders("plain.test", "198.51.100.7", "/api/items", "api-client/1.0")
	h["Accept"] = "text/plain"
	resp = do(t, "GET", ts.URL+"/auth", h, nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Reason") != "waf:api-path" {
		t.Fatalf("non-allowed Accept: status = %d reason = %q, want 403 waf:api-path",
			resp.StatusCode, resp.Header.Get("X-Guardian-Reason"))
	}

	// Same request with a JNDI payload in the Referer: denied by the header rule.
	h = guardianHeaders("plain.test", "198.51.100.7", "/page", "Mozilla/5.0")
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

func TestPassRejectsAmbiguousJSON(t *testing.T) {
	ts := testServer(t)
	valid := []byte(`{"challenge_id":"id","nonce":"1"}`)
	invalidUTF8 := append([]byte(`{"challenge_id":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`","nonce":"1"}`)...)
	for name, body := range map[string][]byte{
		"duplicate member": []byte(`{"challenge_id":"id","challenge_id":"other","nonce":"1"}`),
		"unknown member":   []byte(`{"challenge_id":"id","nonce":"1","extra":true}`),
		"wrong-case name":  []byte(`{"Challenge_ID":"id","nonce":"1"}`),
		"trailing value":   append(append([]byte(nil), valid...), []byte(` {}`)...),
		"invalid UTF-8":    invalidUTF8,
	} {
		t.Run(name, func(t *testing.T) {
			resp := do(t, http.MethodPost, ts.URL+PassPath,
				guardianHeaders("html.test", "198.51.100.200", "/", "Mozilla/5.0"), body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func fetchChallenge(t *testing.T, ts *httptest.Server, ip, ua string) (id, challenge string, difficulty int) {
	t.Helper()
	return fetchChallengeOn(t, ts, "html.test", ip, ua)
}

func fetchChallengeOn(t *testing.T, ts *httptest.Server, host, ip, ua string) (id, challenge string, difficulty int) {
	return fetchChallengeForURI(t, ts, host, ip, ua, "/original?q=1")
}

func fetchChallengeForURI(t *testing.T, ts *httptest.Server, host, ip, ua, uri string) (id, challenge string, difficulty int) {
	t.Helper()
	resp := do(t, "GET", ts.URL+"/challenge", guardianHeaders(host, ip, uri, ua), nil)
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

type argonChallengeData struct {
	ChallengeID string        `json:"challenge_id"`
	Challenge   string        `json:"challenge"`
	Algorithm   pow.Algorithm `json:"algorithm"`
	MemoryKiB   uint32        `json:"memory_kib"`
	Iterations  uint32        `json:"iterations"`
	Salt        string        `json:"salt"`
	WorkerURL   string        `json:"worker_url"`
	WASMURL     string        `json:"wasm_url"`
	PassURL     string        `json:"pass_url"`
}

func fetchArgonChallenge(t *testing.T, ts *httptest.Server, host, ip, ua string) argonChallengeData {
	t.Helper()
	resp := do(t, "GET", ts.URL+"/challenge", guardianHeaders(host, ip, "/original?q=1", ua), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge page: status = %d, want 200", resp.StatusCode)
	}
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := dataRe.FindSubmatch(page)
	if m == nil {
		t.Fatal("no guardian-data JSON found")
	}
	var data argonChallengeData
	if err := json.Unmarshal(m[1], &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func solveArgonChallenge(t *testing.T, data argonChallengeData) string {
	t.Helper()
	salt, err := hex.DecodeString(data.Salt)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(argon2.IDKey([]byte(data.Challenge), salt, data.Iterations, data.MemoryKiB, 1, 32))
}

const argonTestYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
argon2_verifier: { max_concurrent: 1, verification_rate_limit: 20/min }
defaults:
  pow: { enabled: false }
domains:
  argon.test:
    pow:
      enabled: true
      algorithm: argon2id
      base_difficulty: 1
      max_difficulty: 2
      argon2id: { memory_kib: 8192, base_iterations: 1, max_iterations: 1, attack_iterations_cap: 1 }
`

func TestArgon2IDHTTPFlowAndVerifierSaturation(t *testing.T) {
	ts, srv := testServerAndHandler(t, argonTestYAML)
	ip, ua := "198.51.100.27", "Mozilla/5.0"
	data := fetchArgonChallenge(t, ts, "argon.test", ip, ua)
	if data.Algorithm != pow.AlgorithmArgon2ID || data.MemoryKiB != 8192 || data.Iterations != 1 || data.WorkerURL != argonWorkerURL || data.WASMURL != argonWASMURL {
		t.Fatalf("argon challenge payload = %+v", data)
	}
	proof := solveArgonChallenge(t, data)
	body, _ := json.Marshal(map[string]any{"challenge_id": data.ChallengeID, "proof": proof, "elapsed_ms": 10})

	// Saturation is explicitly retriable and must leave the challenge unspent.
	srv.argonInflight.Store(1)
	resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("argon.test", ip, "/original?q=1", ua), body)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("saturated redeem: status=%d Retry-After=%q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	srv.argonInflight.Store(0)
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("argon.test", ip, "/original?q=1", ua), body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("same-proof retry: status=%d body=%s", resp.StatusCode, b)
	}
	rows := solveRows(srv)
	if len(rows) != 1 || rows[0].PoWAlgorithm != "argon2id" || rows[0].Argon2MemoryKiB != 8192 || rows[0].Argon2Iterations != 1 || rows[0].Bits != 0 {
		t.Fatalf("Argon2id solve record = %+v", rows)
	}
}

func TestArgon2IDRateLimitReturnsWindowResetAndPreservesChallenge(t *testing.T) {
	yaml := strings.Replace(argonTestYAML, "verification_rate_limit: 20/min", "verification_rate_limit: 1/min", 1)
	ts, srv := testServerAndHandler(t, yaml)
	ip, ua := "198.51.100.29", "Mozilla/5.0"
	first := fetchArgonChallenge(t, ts, "argon.test", ip, ua)
	second := fetchArgonChallenge(t, ts, "argon.test", ip, ua)

	requestBody := func(data argonChallengeData) []byte {
		body, _ := json.Marshal(map[string]any{
			"challenge_id": data.ChallengeID,
			"proof":        solveArgonChallenge(t, data),
			"elapsed_ms":   10,
		})
		return body
	}
	redeem := func(body []byte) *http.Response {
		return do(t, "POST", ts.URL+"/pass", guardianHeaders("argon.test", ip, "/original?q=1", ua), body)
	}
	firstBody, secondBody := requestBody(first), requestBody(second)
	if resp := redeem(firstBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("first redeem: status=%d, want 200", resp.StatusCode)
	}
	resp := redeem(secondBody)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate-limited redeem: status=%d, want 429", resp.StatusCode)
	}
	retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > 60 {
		t.Fatalf("rate-limited redeem: Retry-After=%q, want seconds remaining in the current minute", resp.Header.Get("Retry-After"))
	}

	// A rate-limited proof remains valid. Relaxing the live admission limit lets
	// the exact same challenge through without solving or issuing it again.
	if err := srv.engine.Reload(loadConfigFromYAML(t, argonTestYAML)); err != nil {
		t.Fatal(err)
	}
	if resp = redeem(secondBody); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("same-proof retry: status=%d body=%s", resp.StatusCode, body)
	}
}

func TestArgon2IDDifficultySignalsSelectBoundedIterations(t *testing.T) {
	yaml := strings.Replace(argonTestYAML,
		"base_iterations: 1, max_iterations: 1, attack_iterations_cap: 1",
		"base_iterations: 1, max_iterations: 2, attack_iterations_cap: 3", 1)
	ts, srv := testServerAndHandler(t, yaml)
	srv.engine.SetAttackDetector(attackmode.New(srv.engine.Config().AttackModeSettings(), nil, slog.Default()))
	ua := "Mozilla/5.0"

	if got := fetchArgonChallenge(t, ts, "argon.test", "198.51.100.40", ua).Iterations; got != 1 {
		t.Fatalf("normal iterations = %d, want 1", got)
	}
	srv.engine.AttackDetector().Pin(attackmode.Elevated, 0)
	if got := srv.engine.AttackDetector().State().Level; got != attackmode.Elevated {
		t.Fatalf("pinned posture = %s, want elevated", got)
	}
	if got := fetchArgonChallenge(t, ts, "argon.test", "198.51.100.41", ua).Iterations; got != 2 {
		t.Fatalf("elevated iterations = %d, want 2", got)
	}
	srv.engine.AttackDetector().Pin(attackmode.Attack, 0)
	if got := fetchArgonChallenge(t, ts, "argon.test", "198.51.100.42", ua).Iterations; got != 3 {
		t.Fatalf("attack iterations = %d, want 3", got)
	}
}

func TestNoScriptFallbackUsesAuthenticatedPathRateLimit(t *testing.T) {
	yaml := strings.Replace(testYAML,
		"pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, noscript_fallback: true }",
		"pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, noscript_fallback: true, noscript_redemption_rate_limit: 6/min }\n    paths:\n      \"/strict/\":\n        pow: { noscript_redemption_rate_limit: 1/h }", 1)
	ts := testServerWithYAML(t, yaml)
	ip, ua := "198.51.100.30", "nojs"
	ids := make([]string, 2)
	for i := range ids {
		ids[i], _, _ = fetchChallengeForURI(t, ts, "html.test", ip, ua, "/strict/page")
	}
	time.Sleep(100 * time.Millisecond)
	headers := guardianHeaders("html.test", ip, "/pass", ua)
	resp := do(t, "GET", fmt.Sprintf("%s/pass?cid=%s&nojs=1", ts.URL, ids[0]), headers, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first strict-path redemption: status=%d, want 303", resp.StatusCode)
	}
	resp = do(t, "GET", fmt.Sprintf("%s/pass?cid=%s&nojs=1", ts.URL, ids[1]), headers, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second strict-path redemption: status=%d, want 429", resp.StatusCode)
	}
	retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > 3600 {
		t.Fatalf("second strict-path redemption: Retry-After=%q, want seconds remaining in the current hour", resp.Header.Get("Retry-After"))
	}
}

func TestArgon2IDNoScriptFallbackUsesMandatoryDelay(t *testing.T) {
	yaml := strings.Replace(argonTestYAML, "enabled: true\n      algorithm: argon2id", "enabled: true\n      noscript_fallback: true\n      algorithm: argon2id", 1)
	ts, _ := testServerAndHandler(t, yaml)
	ip, ua := "198.51.100.33", "Mozilla/5.0 nojs"
	data := fetchArgonChallenge(t, ts, "argon.test", ip, ua)
	url := fmt.Sprintf("%s%s?cid=%s&nojs=1", ts.URL, PassPath, data.ChallengeID)

	resp := do(t, "GET", url, guardianHeaders("argon.test", ip, "/", ua), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("instant Argon2id no-JS: status=%d, want 403", resp.StatusCode)
	}
	time.Sleep(100 * time.Millisecond)
	resp = do(t, "GET", url, guardianHeaders("argon.test", ip, "/", ua), nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Argon2id no-JS redeem: status=%d, want 303", resp.StatusCode)
	}
}

func TestRedemptionRateLimitAlsoAggregatesByASN(t *testing.T) {
	_, srv := testServerAndHandler(t, testYAML)
	limit := core.Rate{Count: 1, Per: time.Minute}
	now := time.Unix(121, 0)
	if exceeded, _ := srv.redemptionRateLimitExceededAt("asn-test", "html.test", "198.51.100.31", 64500, limit, now); exceeded {
		t.Fatal("first address in ASN was unexpectedly limited")
	}
	if exceeded, _ := srv.redemptionRateLimitExceededAt("asn-test", "html.test", "198.51.100.32", 64500, limit, now); !exceeded {
		t.Fatal("second address should exhaust the shared ASN bucket")
	}
}

func TestRedemptionRateLimitRetryAfterUsesFixedWindowBoundary(t *testing.T) {
	_, srv := testServerAndHandler(t, testYAML)
	limit := core.Rate{Count: 10, Per: time.Minute}
	now := time.Unix(121, 0) // one second into a Unix-aligned minute
	for i := 0; i < limit.Count; i++ {
		if exceeded, _ := srv.redemptionRateLimitExceededAt("retry-test", "html.test", "198.51.100.40", 0, limit, now); exceeded {
			t.Fatalf("attempt %d was limited before the configured allowance", i+1)
		}
	}
	exceeded, retryAfter := srv.redemptionRateLimitExceededAt("retry-test", "html.test", "198.51.100.40", 0, limit, now)
	if !exceeded || retryAfter != 59*time.Second {
		t.Fatalf("exceeded=%t Retry-After=%s, want true and 59s", exceeded, retryAfter)
	}
}

func TestChallengeAlgorithmSurvivesHotReload(t *testing.T) {
	ts, srv := testServerAndHandler(t, testYAML)
	ip, ua := "198.51.100.28", "Mozilla/5.0"
	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	nonce := solve(t, challenge, difficulty)

	nextYAML := strings.Replace(argonTestYAML, "argon.test", "html.test", 1)
	if err := srv.engine.Reload(loadConfigFromYAML(t, nextYAML)); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": nonce, "elapsed_ms": 10})
	resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/original?q=1", ua), body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("pre-reload SHA-256 challenge after reload: status=%d body=%s", resp.StatusCode, b)
	}

	argonData := fetchArgonChallenge(t, ts, "html.test", "198.51.100.29", ua)
	argonProof := solveArgonChallenge(t, argonData)
	if err := srv.engine.Reload(loadConfigFromYAML(t, testYAML)); err != nil {
		t.Fatal(err)
	}
	argonBody, _ := json.Marshal(map[string]any{"challenge_id": argonData.ChallengeID, "proof": argonProof, "elapsed_ms": 10})
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", "198.51.100.29", "/original?q=1", ua), argonBody)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("pre-reload Argon2id challenge after reload: status=%d body=%s", resp.StatusCode, b)
	}
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
			if c.MaxAge != int((7 * 24 * time.Hour).Seconds()) {
				t.Errorf("cookie MaxAge = %d, want %d", c.MaxAge, int((7 * 24 * time.Hour).Seconds()))
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

// TestPoWNetworkHandoverEndToEnd walks the recovery journey at the transport
// boundary: a proof solved on one address is redeemed on another, consumed
// without a pass or tamper row, then the original URI issues a fresh challenge
// for the new exact address and that second solve reaches the normal token path.
func TestPoWNetworkHandoverEndToEnd(t *testing.T) {
	ts, h, m := testServerWithMetrics(t, testYAML)
	oldIP, newIP, ua := "198.51.100.7", "2001:db8::7", "Mozilla/5.0 handover"
	id, challenge, difficulty := fetchChallengeForURI(t, ts, "html.test", oldIP, ua, "/ledger?month=8")
	body, _ := json.Marshal(map[string]any{
		"challenge_id": id, "nonce": solve(t, challenge, difficulty), "elapsed_ms": 42,
	})

	resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", newIP, "/ignored", ua), body)
	if resp.StatusCode != http.StatusConflict {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("handover redeem: status = %d body = %s, want 409", resp.StatusCode, raw)
	}
	var recovery struct {
		OK       bool   `json:"ok"`
		Reason   string `json:"reason"`
		RetryURL string `json:"retry_url"`
	}
	if err := json.UnmarshalRead(resp.Body, &recovery); err != nil {
		t.Fatal(err)
	}
	if recovery.OK || recovery.Reason != "network_handover" || recovery.RetryURL != "/ledger?month=8" {
		t.Fatalf("recovery response = %+v", recovery)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatal("network handover minted a pass cookie")
	}

	var retries, failures int
	for _, d := range h.engine.RecentDecisions(0) {
		switch d.Action {
		case core.ActionRedeemRetry:
			retries++
			if d.Reason != core.ReasonNetworkHandover || d.IP != newIP || d.URI != "/ledger?month=8" {
				t.Errorf("handover row = %+v", d)
			}
		case core.ActionRedeemFail:
			failures++
		}
	}
	if retries != 1 || failures != 0 {
		t.Fatalf("outcome rows: retries=%d failures=%d, want 1/0", retries, failures)
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var handovers float64
	for _, mf := range families {
		if mf.GetName() != "guardian_challenges_total" {
			continue
		}
		for _, sample := range mf.GetMetric() {
			for _, label := range sample.GetLabel() {
				if label.GetName() == "outcome" && label.GetValue() == "network_handover" {
					handovers += sample.GetCounter().GetValue()
				}
			}
		}
	}
	if handovers != 1 {
		t.Errorf("guardian_challenges_total{outcome=network_handover} = %v, want 1", handovers)
	}

	// The response's safe original URI is the browser's next authorization
	// request. It is still unvouched and therefore receives a new challenge.
	resp = do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", newIP, recovery.RetryURL, ua), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("new-address authorization: status = %d, want 401", resp.StatusCode)
	}
	newID, newChallenge, newDifficulty := fetchChallengeForURI(t, ts, "html.test", newIP, ua, recovery.RetryURL)
	newBody, _ := json.Marshal(map[string]any{
		"challenge_id": newID, "nonce": solve(t, newChallenge, newDifficulty), "elapsed_ms": 42,
	})
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", newIP, recovery.RetryURL, ua), newBody)
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) == 0 {
		t.Fatalf("replacement redeem: status = %d cookies = %d, want 200 with pass", resp.StatusCode, len(resp.Cookies()))
	}

	// The consumed original cannot trigger a second recovery.
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", "2001:db8::8", "/ignored", ua), body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed handover: status = %d, want 403", resp.StatusCode)
	}
}

func TestStoreOutageFallsBackToStatelessChallenge(t *testing.T) {
	base := store.NewMemory()
	ts, h := testServerAndHandlerWithStore(t, testYAML, unavailableCASStore{Store: base}, nil)
	ip, ua := "198.51.100.77", "Mozilla/5.0"

	resp := do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/page", ua), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth status = %d, want 401 challenge", resp.StatusCode)
	}
	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	if !pow.IsStatelessID(id) {
		t.Fatalf("store-down fallback issued stateful id %q", id)
	}
	body, _ := json.Marshal(map[string]any{
		"challenge_id": id, "nonce": solve(t, challenge, difficulty), "elapsed_ms": 40,
	})
	time.Sleep(25 * time.Millisecond) // so the measured round trip is not sub-millisecond
	resp = do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/page", ua), body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("stateless fallback redeem status = %d body = %s", resp.StatusCode, b)
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("stateless fallback did not mint a token cookie")
	}

	// A stateless challenge carries its difficulty and issue time inside its own
	// MAC-verified payload rather than in a stored record, so this is the path
	// where a missing field surfaces as a solve row reading "0 bits" or an
	// issue time of 1970. It is also the path that runs during a store outage,
	// which is exactly when someone is watching the dashboard.
	rows := solveRows(h)
	if len(rows) != 1 {
		t.Fatalf("recorded %d solve rows, want 1", len(rows))
	}
	d := rows[0]
	if int(d.Bits) != difficulty {
		t.Errorf("bits = %d, want the %d this stateless challenge carried", d.Bits, difficulty)
	}
	if d.SolveMS != 40 {
		t.Errorf("solve_ms = %d, want the reported 40", d.SolveMS)
	}
	// A zero or garbage issued-at would read as decades, not as a fast solve.
	// The ceiling is deliberately far above any real interval: it is here to
	// catch epoch zero, not to time a loaded CI runner.
	if d.RoundTripMS < 20 || d.RoundTripMS > 600_000 {
		t.Errorf("round_trip_ms = %d, want the real interval just measured", d.RoundTripMS)
	}
}

func TestNoJSFlow(t *testing.T) {
	ts, h := testServerAndHandler(t, testYAML)
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

	// The client waited out the meta refresh instead of hashing, so the row
	// says so and reports no solve time. Recording the wait as one would put
	// the configured minimum delay into the solve-time statistics.
	rows := solveRows(h)
	if len(rows) != 1 {
		t.Fatalf("recorded %d solve rows, want 1", len(rows))
	}
	if rows[0].Reason != core.ReasonNoJS {
		t.Errorf("reason = %q, want %q", rows[0].Reason, core.ReasonNoJS)
	}
	if rows[0].SolveMS != 0 {
		t.Errorf("solve_ms = %d, want 0: nothing was hashed", rows[0].SolveMS)
	}
	if rows[0].RoundTripMS < 90 {
		t.Errorf("round_trip_ms = %d, want at least the 100ms wait", rows[0].RoundTripMS)
	}
}

func TestNoJSAddressChangeDoesNotRecoverWithoutProof(t *testing.T) {
	ts, h := testServerAndHandler(t, testYAML)
	oldIP, newIP, ua := "198.51.100.8", "2001:db8::8", "Mozilla/5.0 nojs handover"
	id, _, _ := fetchChallengeForURI(t, ts, "html.test", oldIP, ua, "/nojs-handover?q=1")
	time.Sleep(100 * time.Millisecond)
	url := fmt.Sprintf("%s%s?cid=%s&nojs=1", ts.URL, PassPath, id)
	resp := do(t, "GET", url, guardianHeaders("html.test", newIP, "/ignored", ua), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("address-changed no-JS redeem: status=%d, want 403", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatal("address-changed no-JS redeem minted a pass cookie")
	}
	for _, d := range h.engine.RecentDecisions(0) {
		if d.Action == core.ActionRedeemRetry {
			t.Fatal("work-free no-JS mismatch recorded a recoverable handover")
		}
	}

	// The mismatch did not consume the challenge. Its issuing address can still
	// complete the accepted time-based fallback.
	resp = do(t, "GET", url, guardianHeaders("html.test", oldIP, "/ignored", ua), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/nojs-handover?q=1" {
		t.Fatalf("original address after mismatch: status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
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
	rules := filepath.Join(t.TempDir(), "shed-rules.yaml")
	if err := os.WriteFile(rules, []byte(`rules:
  - id: dotfile
    action: deny
    targets: [ path ]
    keywords: [ ".env" ]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	shedYAML := fmt.Sprintf(`
store: { backend: memory }
signing_key_file: k
attack_mode: { enabled: true, effects: { max_inflight: 1 } }
defaults:
  pow: { enabled: true, mode: always, base_difficulty: 2, max_difficulty: 4 }
  waf:
    honeypot: { enabled: true, paths: [ "/trap" ] }
    rules: { enabled: true, files: [ %q ] }
  denylist: { ips: [ "203.0.113.66" ] }
domains:
  html.test: { pow: { enabled: true } }
`, rules)
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

	// A token is not a WAF bypass. The normal pipeline runs honeypot and
	// terminal rule checks before token acceptance; saturation must retain
	// those store-free checks instead of fast-passing a vouched attack request.
	for _, uri := range []string{"/backup/.env", "/trap"} {
		bad := guardianHeaders("html.test", ip, uri, ua)
		bad["X-Guardian-Cookie"] = pow.CookieName + "=" + cookie
		resp = do(t, "GET", ts.URL+"/auth", bad, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("token holder requesting %s under saturation: status = %d, want 403", uri, resp.StatusCode)
		}
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

func TestHotEnabledMaxInflightCountsExistingEvaluation(t *testing.T) {
	base := store.NewMemory()
	st := &blockingGetStore{Store: base, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(st.release) }) }
	t.Cleanup(release)
	ts, h := testServerAndHandlerWithStore(t, `
store: { backend: memory }
attack_mode: { enabled: true, effects: { max_inflight: 0 } }
`, st, nil)

	firstDone := make(chan *http.Response, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
		for k, v := range guardianHeaders("site.test", "198.51.100.1", "/", "test") {
			req.Header.Set(k, v)
		}
		resp, _ := noRedirect.Do(req)
		firstDone <- resp
	}()
	<-st.entered

	nextPath := filepath.Join(t.TempDir(), "next.yaml")
	if err := os.WriteFile(nextPath, []byte(`
store: { backend: memory }
attack_mode: { enabled: true, effects: { max_inflight: 1 } }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := core.LoadConfig(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Reload(next); err != nil {
		t.Fatal(err)
	}

	respCh := make(chan *http.Response, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
		for k, v := range guardianHeaders("site.test", "198.51.100.2", "/", "test") {
			req.Header.Set(k, v)
		}
		resp, _ := noRedirect.Do(req)
		respCh <- resp
	}()
	select {
	case resp := <-respCh:
		if resp == nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Guardian-Action") != "shed" {
			t.Fatalf("request after hot-enable was not shed: %#v", resp)
		}
		resp.Body.Close()
	case <-time.After(time.Second):
		t.Fatal("request after hot-enable entered Evaluate instead of being shed")
	}
	release()
	if resp := <-firstDone; resp != nil {
		resp.Body.Close()
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

// solveOnce walks challenge, hash and redeem, posting the given client-reported
// elapsed time, and returns the pass response.
func solveOnce(t *testing.T, ts *httptest.Server, ip, ua string, elapsedMS int64, hold time.Duration) *http.Response {
	t.Helper()
	do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/original?q=1", ua), nil)
	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	body, _ := json.Marshal(map[string]any{
		"challenge_id": id, "nonce": solve(t, challenge, difficulty), "elapsed_ms": elapsedMS,
	})
	// Stands in for the time a real client spends hashing, so the server-side
	// issue-to-redeem measurement has something to measure.
	time.Sleep(hold)
	return do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/original?q=1", ua), body)
}

func solveRows(h *Server) []core.RecentDecision {
	var out []core.RecentDecision
	for _, d := range h.engine.RecentDecisions(0) {
		if d.Action == core.ActionSolve {
			out = append(out, d)
		}
	}
	return out
}

// A solve is attributable: the ring says which host, path, IP and User-Agent
// paid the proof of work, and at what difficulty. Without this the only record
// of a ten-second solve is an unlabelled bucket in a process-wide histogram.
func TestRedeemRecordsSolve(t *testing.T) {
	ts, h := testServerAndHandler(t, testYAML)
	ip, ua := "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64)"

	if resp := solveOnce(t, ts, ip, ua, 42, 25*time.Millisecond); resp.StatusCode != http.StatusOK {
		t.Fatalf("pass: status = %d, want 200", resp.StatusCode)
	}

	rows := solveRows(h)
	if len(rows) != 1 {
		t.Fatalf("recorded %d solve rows, want 1", len(rows))
	}
	d := rows[0]
	if d.Reason != core.ReasonSolved {
		t.Errorf("reason = %q, want %q", d.Reason, core.ReasonSolved)
	}
	if d.Host != "html.test" || d.IP != ip || d.UA != ua || d.URI != "/original?q=1" {
		t.Errorf("attribution = %s %s %s %s", d.Host, d.IP, d.UA, d.URI)
	}
	if d.SolveMS != 42 {
		t.Errorf("solve_ms = %d, want the reported 42", d.SolveMS)
	}
	// base_difficulty 1 on the config scale is 4 leading zero bits.
	if d.Bits != 4 {
		t.Errorf("bits = %d, want 4", d.Bits)
	}
	// The server measures issue to redeem itself, so the client held the
	// challenge for at least as long as it actually did. (It is not compared
	// against solve_ms here: the two are only ordered within the clock-skew
	// allowance, and this test posts a solve time it did not spend.)
	if d.RoundTripMS < 20 {
		t.Errorf("round_trip_ms = %d, want at least the 25ms the challenge was held", d.RoundTripMS)
	}
}

// redeemStoreErrDetail stands in for what an internal redeem failure really
// carries: a backend address here, a key file path when the signing key cannot
// be read.
const redeemStoreErrDetail = "dial tcp 10.9.9.9:6379: connect: connection refused"

// redeemErrStore fails only the challenge record read, so the rest of the
// harness keeps working and the failure lands on the internal-error branch.
type redeemErrStore struct{ store.Store }

func (s redeemErrStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if strings.HasPrefix(key, "challenge:") {
		return nil, false, errors.New(redeemStoreErrDetail)
	}
	return s.Store.Get(ctx, key)
}

// TestRedeemInternalErrorDoesNotLeakDetail pins the client-facing half of the
// redeem failure split. The Angie glue serves /__guardian/pass with
// auth_request off, so this endpoint answers unauthenticated internet clients
// directly, and an internal failure must not hand one the raw error: that text
// is where store addresses and key file paths live. The client-fault
// rejections keep naming their sentinel (TestRedeemFailureRecordsRow covers
// those); only Guardian's own failures collapse to a fixed string, with the
// detail going to the log alone.
func TestRedeemInternalErrorDoesNotLeakDetail(t *testing.T) {
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	ts, _ := testServerAndHandlerWithStore(t, testYAML, redeemErrStore{Store: base}, nil)
	ip, ua := "198.51.100.9", "Mozilla/5.0 (X11; Linux x86_64)"

	// A canonical UUID, so Redeem reaches the record read rather than
	// rejecting the shape first.
	body, _ := json.Marshal(map[string]any{
		"challenge_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"nonce":        "1",
	})
	resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/x", ua), body)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), redeemStoreErrDetail) {
		t.Errorf("the 500 body hands an unauthenticated client the internal error:\n%s", raw)
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	if out.OK || out.Error == "" {
		t.Errorf("body = %+v, want ok=false carrying a fixed explanation", out)
	}
}

// A failed redemption is attributable too: the ring says who failed, on which
// host, and why, which is what tells "failed N" in the funnel apart from an
// attack. Without it the reason lives only in a log line.
func TestRedeemFailureRecordsRow(t *testing.T) {
	ts, h, m := testServerWithMetrics(t, testYAML)
	ip, ua := "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64)"

	failRows := func() []core.RecentDecision {
		var out []core.RecentDecision
		for _, d := range h.engine.RecentDecisions(0) {
			if d.Action == core.ActionRedeemFail {
				out = append(out, d)
			}
		}
		return out
	}

	// A nonce that misses the difficulty. The challenge is real, so this is
	// the ErrBadSolution leg, not an unknown ID.
	do(t, "GET", ts.URL+"/auth", guardianHeaders("html.test", ip, "/original?q=1", ua), nil)
	id, challenge, difficulty := fetchChallenge(t, ts, ip, ua)
	body, _ := json.Marshal(map[string]any{"challenge_id": id, "nonce": failNonce(t, challenge, difficulty)})
	if resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/original?q=1", ua), body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad nonce: status = %d, want 403", resp.StatusCode)
	}
	rows := failRows()
	if len(rows) != 1 {
		t.Fatalf("recorded %d redeem_fail rows, want 1", len(rows))
	}
	d := rows[0]
	if d.Reason != core.ReasonBadSolution {
		t.Errorf("reason = %q, want %q", d.Reason, core.ReasonBadSolution)
	}
	if d.Host != "html.test" || d.IP != ip || d.UA != ua {
		t.Errorf("attribution = %s %s %s, want html.test %s %s", d.Host, d.IP, d.UA, ip, ua)
	}

	// A challenge ID nothing ever issued.
	body, _ = json.Marshal(map[string]any{"challenge_id": "nothing-ever-issued", "nonce": "1"})
	if resp := do(t, "POST", ts.URL+"/pass", guardianHeaders("html.test", ip, "/x", ua), body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown id: status = %d, want 403", resp.StatusCode)
	}
	rows = failRows()
	if len(rows) != 2 {
		t.Fatalf("recorded %d redeem_fail rows, want 2", len(rows))
	}
	// Newest first, like the ring itself.
	if rows[0].Reason != core.ReasonChallengeGone {
		t.Errorf("reason = %q, want %q", rows[0].Reason, core.ReasonChallengeGone)
	}

	// The per-reason counter mirrors the ring, bare-labelled: two failures,
	// one per reason, summing to challenges_total{outcome="failed"}.
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	byReason := map[string]float64{}
	var failed float64
	for _, mf := range families {
		switch mf.GetName() {
		case "guardian_challenge_failures_total":
			for _, s := range mf.GetMetric() {
				for _, l := range s.GetLabel() {
					if l.GetName() == "reason" {
						byReason[l.GetValue()] = s.GetCounter().GetValue()
					}
				}
			}
		case "guardian_challenges_total":
			for _, s := range mf.GetMetric() {
				for _, l := range s.GetLabel() {
					if l.GetName() == "outcome" && l.GetValue() == "failed" {
						failed = s.GetCounter().GetValue()
					}
				}
			}
		}
	}
	if byReason["bad_solution"] != 1 || byReason["unknown_challenge"] != 1 || len(byReason) != 2 {
		t.Errorf("challenge_failures_total = %v, want bad_solution 1 + unknown_challenge 1", byReason)
	}
	if failed != 2 {
		t.Errorf("challenges_total{failed} = %v, want 2 (must equal the failures sum)", failed)
	}
}

// failNonce returns a nonce that does not meet the difficulty, so a test can
// exercise the ErrBadSolution leg without racing luck.
func failNonce(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := 0; n < 1_000_000; n++ {
		nonce := "fail" + strconv.Itoa(n)
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
		if zeros < difficulty {
			return nonce
		}
	}
	t.Fatal("no failing nonce found")
	return ""
}

// elapsed_ms is unauthenticated browser telemetry. A client cannot have hashed
// for longer than its challenge existed, so an impossible value is dropped to
// "not reported" and counted, rather than being averaged into the histogram
// that base_difficulty is tuned against.
func TestRedeemRejectsImpossibleSolveTime(t *testing.T) {
	ts, h, m := testServerWithMetrics(t, testYAML)

	// A full day of "hashing" on a challenge issued milliseconds ago.
	if resp := solveOnce(t, ts, "198.51.100.8", "Mozilla/5.0", 86_400_000, 0); resp.StatusCode != http.StatusOK {
		t.Fatalf("pass: status = %d, want 200 (the solve itself is valid)", resp.StatusCode)
	}

	rows := solveRows(h)
	if len(rows) != 1 {
		t.Fatalf("recorded %d solve rows, want 1", len(rows))
	}
	if rows[0].SolveMS != 0 {
		t.Errorf("solve_ms = %d, want 0: an impossible report is not a solve time", rows[0].SolveMS)
	}

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var implausible, observed float64
	for _, mf := range families {
		switch mf.GetName() {
		case "guardian_challenges_total":
			for _, s := range mf.GetMetric() {
				for _, l := range s.GetLabel() {
					if l.GetName() == "outcome" && l.GetValue() == "solve_time_implausible" {
						implausible = s.GetCounter().GetValue()
					}
				}
			}
		case "guardian_challenge_solve_seconds":
			for _, s := range mf.GetMetric() {
				observed += float64(s.GetHistogram().GetSampleCount())
			}
		}
	}
	if implausible != 1 {
		t.Errorf("solve_time_implausible = %v, want 1", implausible)
	}
	if observed != 0 {
		t.Errorf("histogram observed %v samples, want 0: the rejected value must not be recorded", observed)
	}
}

// The solve-time histogram is labelled by domain, and the Host header that
// reaches this handler is raw client input. This pins the collapse that keeps
// the label bounded: a configured domain gets its own series, and every other
// host, however many distinct ones a flood invents, shares "default".
//
// The failure this prevents is not a wrong number on a chart. An unbounded
// label value means one Prometheus series per distinct Host header, which takes
// down the daemon's memory and the scrape target with it, from nothing more
// than a header a client chooses. Same invariant as TestReasonCategoryBounded
// in core, one metric further along.
func TestSolveTimeDomainLabelIsBounded(t *testing.T) {
	const yaml = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
domains:
  configured.test: {}
`
	ts, _, m := testServerWithMetrics(t, yaml)

	// One solve on the configured domain, then several on hosts nobody
	// configured, each from its own IP so per-IP issuance limits and difficulty
	// escalation stay out of it.
	solveOn := func(host, ip string) {
		t.Helper()
		id, challenge, difficulty := fetchChallengeOn(t, ts, host, ip, "Mozilla/5.0")
		body, _ := json.Marshal(map[string]any{
			"challenge_id": id, "nonce": solve(t, challenge, difficulty), "elapsed_ms": 30,
		})
		resp := do(t, "POST", ts.URL+"/pass", guardianHeaders(host, ip, "/original?q=1", "Mozilla/5.0"), body)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("%s: redeem status = %d body = %s", host, resp.StatusCode, b)
		}
	}
	solveOn("configured.test", "198.51.100.10")
	for i, host := range []string{
		"attacker-chosen-1.example",
		"attacker-chosen-2.example",
		strings.Repeat("x", 200) + ".example",
	} {
		solveOn(host, fmt.Sprintf("198.51.100.%d", 20+i))
	}

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]uint64{}
	for _, mf := range families {
		if mf.GetName() != "guardian_challenge_solve_seconds" {
			continue
		}
		for _, series := range mf.GetMetric() {
			for _, l := range series.GetLabel() {
				if l.GetName() == "domain" {
					labels[l.GetValue()] += series.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	if len(labels) != 2 {
		t.Fatalf("domain label values = %v, want exactly configured.test and default", labels)
	}
	if labels["configured.test"] != 1 {
		t.Errorf("configured.test observed %d solves, want 1", labels["configured.test"])
	}
	if labels["default"] != 3 {
		t.Errorf("default observed %d solves, want all 3 unconfigured hosts", labels["default"])
	}
}

// TestSafeRedirect covers the guard that confines the post-challenge redirect.
// The no-JS path sends the client wherever the challenge record says it was
// going, and that URI travelled from the request line, so an off-site value
// there would turn the interstitial into an open redirect.
//
// The control characters are the subtle half. The WHATWG URL parser strips
// ASCII tab, CR and LF from a URL BEFORE parsing, so "/\t/evil.example/"
// reaches it as "//evil.example/" and is scheme-relative after all. Angie
// rejects those bytes in a request line and Go's header writer rewrites CR and
// LF, so the tab case was the only one that could reach a client, and only via
// a direct probe. Pinned here regardless: this function is what confines the
// redirect, and it must hold without relying on the two layers around it.
func TestSafeRedirect(t *testing.T) {
	cases := []struct{ in, want, why string }{
		{"/account", "/account", "an ordinary same-site path is preserved"},
		{"/a/b?c=d#e", "/a/b?c=d#e", "query and fragment ride along untouched"},
		{"/", "/", "the root is fine"},
		{"", "/", "empty is not a path"},
		{"account", "/", "relative, so not obviously same-site"},
		{"https://evil.example/", "/", "absolute off-site"},
		{"//evil.example/", "/", "scheme-relative"},
		{"/\\evil.example/", "/", "backslash spelling of scheme-relative"},
		{"/\t/evil.example/", "/", "tab is stripped by the URL parser, leaving //evil.example/"},
		{"/\r/evil.example/", "/", "CR likewise"},
		{"/\n/evil.example/", "/", "LF likewise"},
		{"/ok\tpath", "/", "a tab anywhere makes the result unpredictable, so refuse it"},
	}
	for _, tc := range cases {
		if got := safeRedirect(tc.in); got != tc.want {
			t.Errorf("safeRedirect(%q) = %q, want %q: %s", tc.in, got, tc.want, tc.why)
		}
	}
}
