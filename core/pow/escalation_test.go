// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"testing"
	"time"
)

// unsolve finds a nonce that does NOT meet the difficulty, so a "wrong
// solution" test can never pass by luck.
func unsolve(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := range 1_000 {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		if leadingZeroBits(sum[:]) < difficulty {
			return nonce
		}
	}
	t.Fatal("no failing nonce found")
	return ""
}

// TestBumpEscalation pins the escalation curve: a small allowance of unsolved
// issuances is free, then every escalationStep further issuances add one bit.
func TestBumpEscalation(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)
	host := "example.com"
	ip := "198.51.100.40"

	// issuance number → expected extra bits, with free=4 and step=2.
	want := []int{0, 0, 0, 0, 0, 1, 1, 2, 2, 3}
	for i, w := range want {
		if got := m.BumpEscalation(ctx, host, ip, time.Minute); got != w {
			t.Fatalf("issuance %d: extra bits = %d, want %d", i+1, got, w)
		}
	}

	// A different IP is unaffected.
	if got := m.BumpEscalation(ctx, host, "198.51.100.41", time.Minute); got != 0 {
		t.Fatalf("fresh ip: extra bits = %d, want 0", got)
	}
	if got := m.BumpEscalation(ctx, "other.example", ip, time.Minute); got != 0 {
		t.Fatalf("fresh host: extra bits = %d, want 0", got)
	}
	if got := m.BumpEscalation(ctx, "EXAMPLE.com:443", ip, time.Minute); got == 0 {
		t.Fatal("equivalent host with case and port started a separate counter")
	}
}

// TestEscalationResetsOnRedeem: solving any challenge proves the client is
// not farming, so a successful redemption must clear the counter.
func TestEscalationResetsOnRedeem(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)
	ip := "198.51.100.42"

	for range escalationFreeIssues + 2*escalationStep {
		m.BumpEscalation(ctx, "example.com", ip, time.Minute)
	}
	if got := m.BumpEscalation(ctx, "example.com", ip, time.Minute); got == 0 {
		t.Fatal("counter should have escalated before the redemption")
	}

	ch, err := m.Issue(ctx, "example.com", ip, "/", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 4),
		Host: "example.com", IP: ip, UserAgent: "Mozilla/5.0",
		TokenTTL: time.Minute, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := m.BumpEscalation(ctx, "example.com", ip, time.Minute); got != 0 {
		t.Fatalf("extra bits after successful redemption = %d, want 0 (counter reset)", got)
	}
}

// TestEscalationSurvivesFailedRedeem: a wrong nonce must NOT reset the
// counter, or a farmer could clear its slate with garbage solutions.
func TestEscalationSurvivesFailedRedeem(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)
	ip := "198.51.100.43"

	var last int
	for range escalationFreeIssues + escalationStep {
		last = m.BumpEscalation(ctx, "example.com", ip, time.Minute)
	}
	if last == 0 {
		t.Fatal("counter should have escalated")
	}

	ch, err := m.Issue(ctx, "example.com", ip, "/", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: unsolve(t, ch.Challenge, 4),
		Host: "example.com", IP: ip, UserAgent: "Mozilla/5.0",
		TokenTTL: time.Minute, ChallengeTTL: time.Minute,
	})
	if !errors.Is(err, ErrBadSolution) {
		t.Fatalf("bad nonce: err = %v, want ErrBadSolution", err)
	}

	if got := m.BumpEscalation(ctx, "example.com", ip, time.Minute); got < last {
		t.Fatalf("extra bits after failed redemption = %d, want >= %d (no reset)", got, last)
	}
}

func TestEscalationResetIsScopedToChallengeHost(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)
	ip := "198.51.100.44"
	strictHost, cheapHost := "strict.example", "cheap.example"
	strictWindow, cheapWindow := 30*time.Minute, time.Minute

	var strictExtra int
	for range escalationFreeIssues + 2*escalationStep {
		strictExtra = m.BumpEscalation(ctx, strictHost, ip, strictWindow)
	}
	if strictExtra == 0 {
		t.Fatal("strict host counter should have escalated")
	}

	ch, err := m.Issue(ctx, cheapHost, ip, "/", 0, cheapWindow, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: "0", Host: cheapHost, IP: ip, UserAgent: "UA",
		TokenTTL: time.Minute, ChallengeTTL: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	if got := m.BumpEscalation(ctx, strictHost, ip, strictWindow); got < strictExtra {
		t.Fatalf("strict host escalation was reset by another host: got %d, want >= %d", got, strictExtra)
	}
	if got := m.BumpEscalation(ctx, cheapHost, ip, cheapWindow); got != 0 {
		t.Fatalf("solved host escalation = %d, want 0", got)
	}
}
