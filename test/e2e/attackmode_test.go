// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAttackModeTrips drives the auth hot path directly (published for this
// test) from many synthetic client IPs, hammering /challenge until the global
// attack posture trips. It then asserts the posture is attack, that fresh
// challenges are issued in the stateless format at the raised difficulty, that
// a stateless challenge round-trips and its replay is rejected, and that an
// existing pre-attack token still passes. It finishes by forcing the posture
// back to normal, mirroring the escalation test's cleanup discipline.
func TestAttackModeTrips(t *testing.T) {
	t.Cleanup(func() {
		// Pin the posture back to normal so the flood this test generated does
		// not bleed into sibling tests (the detector's window and dwell would
		// otherwise keep it elevated for a while). The pin is a hard override,
		// so this is a reliable reset; it stays pinned since no other e2e test
		// exercises attack behaviour.
		adminReq(t, http.MethodPost, "/admin/attack", strings.NewReader(`{"level":"normal"}`))
	})

	// First, mint a real token BEFORE the attack, at the normal difficulty, so
	// we can prove attack mode does not invalidate it.
	preToken := solveThroughAuth(t, "203.0.113.10")

	// Hammer /challenge from rotating synthetic IPs. The e2e config trips
	// attack at 30 issued/s with a low solve ratio; we issue fast and solve
	// none, so the ratio stays ~0. A bounded pool of workers keeps a steady,
	// concurrent issuance rate well above the threshold, without the connection
	// spike an unbounded per-batch fan-out (120 goroutines at once) would inflict
	// on the shared compose stack, which could leave a sibling test's upstream
	// momentarily unreachable. Sequential single-request issuance instead risked
	// dipping below the threshold on a loaded CI runner and stalling at elevated.
	// The detector aggregates over a 10s window, so we keep issuing across
	// several windows until it trips.
	const floodWorkers = 16
	deadline := time.Now().Add(45 * time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := range floodWorkers {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for n := base; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				floodChallenge(t, fmt.Sprintf("198.51.100.%d", n%254+1))
			}
		}(w * 16)
	}

	var level string
	for time.Now().Before(deadline) {
		if level = attackLevel(t); level == "attack" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	// Flood requests deliberately tolerate transport errors and leave a large
	// keep-alive pool behind. Do not let the strict assertions below reuse a
	// connection that guardiand closed while saturated.
	noRedirect.CloseIdleConnections()

	if level != "attack" {
		// Dump the last-observed window signals so a CI stall (rate below the
		// attack threshold, or an unexpectedly high solve ratio) is diagnosable
		// rather than just "stuck at elevated".
		t.Fatalf("posture never reached attack (last = %q); signals: %s", level, attackSignals(t))
	}

	// The metrics gauge agrees. Match the bare metric line (a trailing space
	// before the value) so the prefix does not also catch
	// guardian_attack_mode_transitions_total / _signal.
	if g := metric(t, "guardian_attack_mode "); g != 2 {
		t.Fatalf("guardian_attack_mode = %v, want 2", g)
	}

	// A freshly issued challenge is stateless (s1. prefix) and at the raised
	// difficulty: base 16 bits + 4 (attack_difficulty_raise 1.0) = 20. The probe
	// IP is deliberately OUTSIDE the flood range (198.51.100.0/24) so it carries
	// only the fleet-wide raise, with no per-IP challenge-farming escalation
	// stacked on top (which would push the difficulty above 20).
	const probeIP = "203.0.113.222"
	id, challenge, difficulty := parseChallenge(t, authChallenge(t, probeIP))
	if !strings.HasPrefix(id, "s1.") {
		t.Fatalf("challenge id %q is not stateless under attack", id)
	}
	if difficulty != 20 {
		t.Fatalf("attack difficulty = %d, want 20 (16 + 4 raise)", difficulty)
	}

	// The stateless challenge round-trips, and replaying it is rejected.
	nonce := solve(t, challenge, difficulty)
	if !redeemAuth(t, probeIP, id, nonce) {
		t.Fatal("stateless challenge did not redeem")
	}
	if redeemAuth(t, probeIP, id, nonce) {
		t.Fatal("stateless challenge replay was accepted")
	}

	// The pre-attack token still vouches: no re-challenge stampede.
	h := map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": "203.0.113.10",
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
		"X-Guardian-Cookie": "guardian_token=" + preToken,
	}
	resp := req(t, http.MethodGet, auth+"/auth", h, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-attack token rejected under attack: status %d", resp.StatusCode)
	}
}

// floodChallenge issues one challenge for the load flood and drains+closes the
// body so the connection is reused rather than leaked. It does NOT register a
// t.Cleanup (the flood makes thousands of calls) and tolerates transient errors
// (the point is sustained issuance rate, not any single request succeeding).
func floodChallenge(t *testing.T, ip string) {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, auth+"/challenge", nil)
	if err != nil {
		return
	}
	r.Header.Set("X-Guardian-Host", powHost)
	r.Header.Set("X-Guardian-IP", ip)
	r.Header.Set("X-Guardian-UA", "Mozilla/5.0")
	r.Header.Set("X-Guardian-URI", "/page")
	resp, err := noRedirect.Do(r)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// authChallenge issues a challenge from the direct auth port as client ip.
func authChallenge(t *testing.T, ip string) *http.Response {
	t.Helper()
	const attempts = 5
	for attempt := 1; attempt <= attempts; attempt++ {
		r, err := http.NewRequest(http.MethodGet, auth+"/challenge", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Guardian-Host", powHost)
		r.Header.Set("X-Guardian-IP", ip)
		r.Header.Set("X-Guardian-UA", "Mozilla/5.0")
		r.Header.Set("X-Guardian-URI", "/page")
		resp, err := noRedirect.Do(r)
		if err == nil {
			t.Cleanup(func() { resp.Body.Close() })
			return resp
		}
		noRedirect.CloseIdleConnections()
		t.Logf("issue auth challenge: attempt %d/%d: %v; retrying", attempt, attempts, err)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("could not issue auth challenge after %d attempts", attempts)
	return nil
}

func attackLevel(t *testing.T) string {
	t.Helper()
	resp := adminReq(t, http.MethodGet, "/admin/attack", nil)
	var out struct {
		Level string `json:"level"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.Level
}

// attackSignals returns the raw signals block from /admin/attack, for failure
// diagnostics (the current window's challenge/solve rates).
func attackSignals(t *testing.T) string {
	t.Helper()
	resp := adminReq(t, http.MethodGet, "/admin/attack", nil)
	var out struct {
		Signals json.RawMessage `json:"signals"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return string(out.Signals)
}

func parseChallenge(t *testing.T, resp *http.Response) (id, challenge string, difficulty int) {
	t.Helper()
	body := bodyOf(t, resp)
	// Solving may outlive the server's keep-alive window on a loaded CI runner.
	// Retire the challenge request's idle connection now so the non-idempotent
	// /pass POST cannot race a server-side idle close (net/http deliberately
	// does not transparently retry POSTs on a stale connection).
	resp.Body.Close()
	noRedirect.CloseIdleConnections()
	m := dataRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no challenge JSON in response (status %d)", resp.StatusCode)
	}
	var cd challengeData
	if err := json.Unmarshal([]byte(m[1]), &cd); err != nil {
		t.Fatalf("decode challenge json: %v", err)
	}
	return cd.ChallengeID, cd.Challenge, cd.Difficulty
}

// redeemAuth posts a solution to the direct auth port; reports success.
func redeemAuth(t *testing.T, ip, id, nonce string) bool {
	t.Helper()
	body := fmt.Sprintf(`{"challenge_id":%q,"nonce":%q}`, id, nonce)
	resp := req(t, http.MethodPost, auth+"/pass", map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": ip, "X-Guardian-UA": "Mozilla/5.0",
		"Content-Type": "application/json",
	}, strings.NewReader(body))
	return resp.StatusCode == http.StatusOK
}

// solveThroughAuth issues, solves and redeems one challenge, returning the
// minted token cookie value.
func solveThroughAuth(t *testing.T, ip string) string {
	t.Helper()
	const attempts = 5
	for attempt := 1; attempt <= attempts; attempt++ {
		token, err := trySolveThroughAuth(t, ip)
		if err == nil {
			return token
		}
		noRedirect.CloseIdleConnections()
		t.Logf("mint pre-attack token: attempt %d/%d: %v; retrying", attempt, attempts, err)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("could not mint pre-attack token after %d attempts", attempts)
	return ""
}

// trySolveThroughAuth performs one complete challenge transaction. Callers
// retry the whole transaction rather than replaying /pass: if a POST reached
// guardiand before its connection reset, that challenge may already be spent.
func trySolveThroughAuth(t *testing.T, ip string) (string, error) {
	t.Helper()
	h := map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": ip,
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
	}
	challengeReq, err := http.NewRequest(http.MethodGet, auth+"/challenge", nil)
	if err != nil {
		return "", err
	}
	for k, v := range h {
		challengeReq.Header.Set(k, v)
	}
	challengeResp, err := noRedirect.Do(challengeReq)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(challengeResp.Body)
	challengeResp.Body.Close()
	if err != nil {
		return "", err
	}
	m := dataRe.FindStringSubmatch(string(body))
	if m == nil {
		return "", fmt.Errorf("no challenge JSON in response (status %d)", challengeResp.StatusCode)
	}
	var cd challengeData
	if err := json.Unmarshal([]byte(m[1]), &cd); err != nil {
		return "", fmt.Errorf("decode challenge json: %w", err)
	}

	nonce := solve(t, cd.Challenge, cd.Difficulty)
	passBody := fmt.Sprintf(`{"challenge_id":%q,"nonce":%q}`, cd.ChallengeID, nonce)
	passReq, err := http.NewRequest(http.MethodPost, auth+"/pass", strings.NewReader(passBody))
	if err != nil {
		return "", err
	}
	for k, v := range h {
		passReq.Header.Set(k, v)
	}
	passReq.Header.Set("Content-Type", "application/json")
	passResp, err := noRedirect.Do(passReq)
	if err != nil {
		return "", err
	}
	defer passResp.Body.Close()
	for _, c := range passResp.Cookies() {
		if c.Name == "guardian_token" {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("no token minted (status %d)", passResp.StatusCode)
}
