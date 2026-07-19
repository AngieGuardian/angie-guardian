// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
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
	// none, so the ratio stays ~0. Each batch fires concurrently so the issuance
	// rate clears the attack threshold decisively regardless of per-request
	// latency on a loaded CI runner (sequential round-trips through Docker
	// networking could dip the sustained rate toward the threshold and stall at
	// elevated). The detector aggregates over a 10s window, so we keep issuing
	// across several windows until it trips.
	deadline := time.Now().Add(45 * time.Second)
	var level string
	for time.Now().Before(deadline) {
		var wg sync.WaitGroup
		for i := range 120 {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				resp := authChallenge(t, fmt.Sprintf("198.51.100.%d", n%254+1))
				resp.Body.Close()
			}(i)
		}
		wg.Wait()
		if level = attackLevel(t); level == "attack" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
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
	// difficulty: base 16 bits + 4 (attack_difficulty_raise 1.0) = 20.
	id, challenge, difficulty := parseChallenge(t, authChallenge(t, "198.51.100.200"))
	if !strings.HasPrefix(id, "s1.") {
		t.Fatalf("challenge id %q is not stateless under attack", id)
	}
	if difficulty != 20 {
		t.Fatalf("attack difficulty = %d, want 20 (16 + 4 raise)", difficulty)
	}

	// The stateless challenge round-trips, and replaying it is rejected.
	nonce := solve(t, challenge, difficulty)
	if !redeemAuth(t, "198.51.100.200", id, nonce) {
		t.Fatal("stateless challenge did not redeem")
	}
	if redeemAuth(t, "198.51.100.200", id, nonce) {
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

// authChallenge issues a challenge from the direct auth port as client ip.
func authChallenge(t *testing.T, ip string) *http.Response {
	t.Helper()
	return req(t, http.MethodGet, auth+"/challenge", map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": ip,
		"X-Guardian-UA": "Mozilla/5.0", "X-Guardian-URI": "/page",
	}, nil)
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
	id, challenge, difficulty := parseChallenge(t, authChallenge(t, ip))
	nonce := solve(t, challenge, difficulty)
	body := fmt.Sprintf(`{"challenge_id":%q,"nonce":%q}`, id, nonce)
	resp := req(t, http.MethodPost, auth+"/pass", map[string]string{
		"X-Guardian-Host": powHost, "X-Guardian-IP": ip, "X-Guardian-UA": "Mozilla/5.0",
		"Content-Type": "application/json",
	}, strings.NewReader(body))
	for _, c := range resp.Cookies() {
		if c.Name == "guardian_token" {
			return c.Value
		}
	}
	t.Fatalf("no token minted (status %d)", resp.StatusCode)
	return ""
}
