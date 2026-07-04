// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

func TestKeyRotationKeepsOldTokensValid(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	m := NewManager(key, st)

	// Mint a token with the original key.
	ch, err := m.Issue(ctx, "example.com", "198.51.100.7", "/", 0, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: "0",
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldToken := res.Token
	if err := m.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA"); err != nil {
		t.Fatal(err)
	}

	// Rotate. The signing key changes; the old key is archived.
	if err := m.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}

	// The pre-rotation token still verifies (old key kept in the verify set).
	if err := m.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA"); err != nil {
		t.Fatalf("token minted before rotation must still verify: %v", err)
	}

	// A freshly minted token also verifies (new signing key).
	ch2, _ := m.Issue(ctx, "example.com", "198.51.100.7", "/", 0, time.Minute, false)
	res2, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch2.ID, Nonce: "0",
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyToken(res2.Token, "example.com", "198.51.100.7", "UA"); err != nil {
		t.Fatalf("post-rotation token must verify: %v", err)
	}

	// A fresh Manager loading only the current key (no prevDir) rejects the
	// old token — proving the old signature really did change.
	freshKey, _ := LoadOrCreateKey(keyPath)
	fresh := NewManager(freshKey, st)
	if err := fresh.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA"); err == nil {
		t.Fatal("old token must fail against the new key alone")
	}

	// A Manager that also loads the archived keys accepts it again — this is
	// how peer instances behind the LB stay consistent after a rotation.
	prev, err := LoadPreviousKeys(prevDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 1 {
		t.Fatalf("expected 1 archived key, got %d", len(prev))
	}
	peer := NewManagerWithKeys(freshKey, prev, st)
	if err := peer.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA"); err != nil {
		t.Fatalf("peer with archived key must accept old token: %v", err)
	}
}
