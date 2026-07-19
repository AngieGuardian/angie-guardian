// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

func genKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestStatelessRedeemAcrossRotation is the review regression: a stateless
// challenge issued by an instance still holding the OLD key must redeem on a
// peer that has rotated to a NEW current key and holds the old key as retired.
// Both share a store (as replicas behind a load balancer do).
func TestStatelessRedeemAcrossRotation(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	keyA, keyB := genKey(t), genKey(t)

	// Old instance: keyA is current.
	oldMgr := NewManager(keyA, st)
	// Rotated peer: keyB current, keyA retired (verify-only), sharing the store.
	newMgr := NewManagerWithKeys(keyB, []ed25519.PrivateKey{keyA}, st)

	// A client is issued a stateless challenge by the OLD instance...
	ch, err := oldMgr.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	if err != nil {
		t.Fatal(err)
	}
	// ...and its solve POST lands on the ROTATED peer (load balancer).
	res, err := newMgr.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "Mozilla/5.0",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("rotated peer rejected the old instance's stateless challenge: %v", err)
	}
	if res.Token == "" {
		t.Fatal("no token minted across rotation")
	}

	// And the reverse: a challenge the rotated peer issues (keyB) must redeem
	// on the old instance ONLY after it learns keyB. Before that it is unknown,
	// which is correct (the old instance cannot verify a secret it never had).
	ch2, _ := newMgr.IssueStateless("a.test", "203.0.113.8", "/", 8, false)
	if _, err := oldMgr.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch2.ID, Nonce: solve(t, ch2.Challenge, 8),
		Host: "a.test", IP: "203.0.113.8", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	}); err == nil {
		t.Fatal("old instance verified a key it never held; expected rejection")
	}
	// After the old instance also rotates to keyB (keyA retired), it verifies.
	oldMgr.SetKeys(keyB, []ed25519.PrivateKey{keyA})
	if _, err := oldMgr.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch2.ID, Nonce: solve(t, ch2.Challenge, 8),
		Host: "a.test", IP: "203.0.113.8", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	}); err != nil {
		t.Fatalf("after adopting keyB, redemption still failed: %v", err)
	}
}
