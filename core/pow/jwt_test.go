// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestVerifyTokenFailureCauses pins the classification every rejection carries.
// The pipeline turns these sentinels into distinct decision reasons, so an
// operator can tell an absent cookie from a replayed or aged-out one; folding
// two causes back together would silently undo that (#43).
func TestVerifyTokenFailureCauses(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	m.now = func() time.Time { return now }

	const host, ip, ua = "example.com", "198.51.100.7", "Mozilla/5.0"
	ch, err := m.Issue(ctx, host, ip, "/", 8, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: host, IP: ip, UserAgent: ua,
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := res.Token

	if err := m.VerifyToken(tok, host, ip, ua, 8, time.Hour); err != nil {
		t.Fatalf("freshly minted token must verify: %v", err)
	}

	cases := []struct {
		name   string
		verify func() error
		want   error
	}{
		{"unparseable cookie value", func() error {
			return m.VerifyToken("garbage", host, ip, ua, 0, 0)
		}, ErrTokenInvalid},
		{"tampered signature", func() error {
			return m.VerifyToken(tok+"x", host, ip, ua, 0, 0)
		}, ErrTokenInvalid},
		{"presented on another host", func() error {
			return m.VerifyToken(tok, "other.com", ip, ua, 0, 0)
		}, ErrTokenBinding},
		{"presented from another IP", func() error {
			return m.VerifyToken(tok, host, "203.0.113.1", ua, 0, 0)
		}, ErrTokenBinding},
		{"presented with another User-Agent", func() error {
			return m.VerifyToken(tok, host, ip, "curl/8.0", 0, 0)
		}, ErrTokenBinding},
		{"solved below the required bits", func() error {
			return m.VerifyToken(tok, host, ip, ua, 12, 0)
		}, ErrTokenUnderDifficulty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.verify()
			if err == nil {
				t.Fatalf("want %v, got no error", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want it to wrap %v", err, tc.want)
			}
		})
	}

	// A verifier behind the issuer sees nbf in the future. That is invalid,
	// not expired; troubleshooting guidance depends on the direction of skew.
	t.Run("issuer clock ahead", func(t *testing.T) {
		issuedAt := now
		now = issuedAt.Add(-time.Minute)
		defer func() { now = issuedAt }()
		err := m.VerifyToken(tok, host, ip, ua, 0, 0)
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("got %v, want it to wrap %v", err, ErrTokenInvalid)
		}
		if errors.Is(err, ErrTokenExpired) {
			t.Errorf("a token whose nbf is still ahead must not report as expired: %v", err)
		}
	})

	// Older than the target path's token_ttl, while its own exp is still ahead.
	now = now.Add(90 * time.Second)
	t.Run("older than the path token_ttl", func(t *testing.T) {
		err := m.VerifyToken(tok, host, ip, ua, 0, time.Minute)
		if !errors.Is(err, ErrTokenExpired) {
			t.Errorf("got %v, want it to wrap %v", err, ErrTokenExpired)
		}
	})

	// Past its own exp. This one is caught inside the JWT parse, alongside a bad
	// signature, so without explicit classification it would report as
	// ErrTokenInvalid — the misleading answer for by far the likelier cause.
	now = now.Add(2 * time.Hour)
	t.Run("past its own exp", func(t *testing.T) {
		err := m.VerifyToken(tok, host, ip, ua, 0, 0)
		if !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("got %v, want it to wrap %v", err, ErrTokenExpired)
		}
		if errors.Is(err, ErrTokenInvalid) {
			t.Errorf("an expired token must not also report as invalid: %v", err)
		}
	})
}
