// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestStatelessRedeemAcrossRotation: a stateless challenge issued by an
// instance still holding the OLD key must redeem on a peer that has rotated to
// a NEW current key and holds the old key as retired. Both share a store (as
// replicas behind a load balancer do).
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
	// on the old instance ONLY after it learns keyB. These are in-memory
	// managers with no key files, so there is nothing to refresh from disk;
	// SetKeys is the only way they learn a peer's key. The file-backed rolling
	// path, where a redeeming replica DOES pick up the new key from disk
	// automatically, is covered by TestStatelessRedeemAcrossFileRotation.
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

// TestStatelessRedeemAcrossFileRotation covers the file-backed rolling
// topology: two replicas share the same key files. One rotates, issues a
// stateless challenge with the NEW key, and its solve POST lands on a
// still-running peer that has NOT yet re-read the new key. Redeem refreshes the
// keys off disk (rate-limited, like VerifyToken) and verifies, with no manual
// SetKeys.
func TestStatelessRedeemAcrossFileRotation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	rotator, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Unix(1_900_000_000, 0).UTC()
	rotationTime := base.Add(900 * time.Millisecond)
	redeemTime := base.Add(1050 * time.Millisecond)

	// Rotate the shared files: NEW key current, old key retired.
	rotator.now = func() time.Time { return rotationTime }
	if err := rotator.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}

	// The rotator issues a stateless challenge under the NEW current key.
	rotator.now = func() time.Time { return redeemTime }
	ch, err := rotator.IssueStateless("a.test", "203.0.113.9", "/", 8, false)
	if err != nil {
		t.Fatal(err)
	}

	// The peer's routine signing-refresh timestamp is inside the throttle
	// window, so the failure-path refresh (lastFailureRefresh) must fire on its
	// own throttle even though a routine refresh just happened. The peer has
	// never seen the new key in memory.
	peer.lastRefresh = base.Add(950 * time.Millisecond)
	peer.now = func() time.Time { return redeemTime }

	res, err := peer.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.9", UserAgent: "Mozilla/5.0",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("file-backed peer rejected a rotated-key stateless challenge without a manual SetKeys: %v", err)
	}
	if res.Token == "" {
		t.Fatal("no token minted across file rotation")
	}
}

func TestPeerRefreshesCurrentKeyBeforeStatelessIssue(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })

	rotator, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_900_000_000, 0).UTC()
	rotator.now = func() time.Time { return base.Add(900 * time.Millisecond) }
	if err := rotator.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}

	issueTime := base.Add(1050 * time.Millisecond)
	peer.lastRefresh = base
	peer.now = func() time.Time { return issueTime }
	rotator.now = func() time.Time { return issueTime }
	ch, err := peer.IssueStateless("a.test", "203.0.113.10", "/", 8, false)
	if err != nil {
		t.Fatal(err)
	}
	rest := strings.TrimPrefix(ch.ID, statelessPrefix)
	payloadB64, macB64, ok := strings.Cut(rest, ".")
	if !ok {
		t.Fatalf("malformed stateless id %q", ch.ID)
	}
	payload, err := b64.DecodeString(payloadB64)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := b64.DecodeString(macB64)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(mac, statelessMAC(rotator.issuingSecret(), payload)) {
		t.Fatal("quiet peer issued with the stale key instead of refreshing the current key")
	}
	res, err := rotator.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.10", UserAgent: "Mozilla/5.0",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil || res.Token == "" {
		t.Fatalf("peer issued stateless challenge with an already-retired key: token=%t err=%v", res != nil && res.Token != "", err)
	}
}

func TestStatelessIssueAndRedeemFailClosedOnKeyRefreshError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	m, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := m.IssueStateless("a.test", "203.0.113.11", "/", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	m.lastRefresh = time.Time{}
	if _, err := m.IssueStateless("a.test", "203.0.113.12", "/", 0, false); err == nil {
		t.Fatal("stateless issuance continued after key refresh failed")
	}
	if _, err := m.IssueStateless("a.test", "203.0.113.12", "/", 0, false); err == nil {
		t.Fatal("throttled stateless issuance forgot the preceding refresh failure")
	}
	if _, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Host: "a.test", IP: "203.0.113.11", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	}); err == nil || errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("redemption did not surface key refresh failure: %v", err)
	}
	if _, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Host: "a.test", IP: "203.0.113.11", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	}); err == nil || errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("throttled redemption forgot the preceding refresh failure: %v", err)
	}
}

func TestStatelessRejectsChallengeMintedAfterKeyRetirementGrace(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	oldKey, currentKey := genKey(t), genKey(t)
	retiredAt := time.Unix(1_900_000_000, 0).UTC()
	issuedAt := retiredAt.Add(statelessRetirementGrace + time.Millisecond)

	compromised := NewManager(oldKey, st)
	compromised.now = func() time.Time { return issuedAt }
	ch, err := compromised.IssueStateless("a.test", "203.0.113.13", "/", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newManagerWithRetiredKeys(currentKey, []RetiredKey{{Key: oldKey, RetiredAt: retiredAt}}, st)
	verifier.now = func() time.Time { return issuedAt }
	_, err = verifier.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Host: "a.test", IP: "203.0.113.13", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("post-retirement challenge err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessRetiredSecretExpiresFromVerificationSet(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	oldKey, currentKey := genKey(t), genKey(t)
	retiredAt := time.Unix(1_900_000_000, 0).UTC()
	verifier := newManagerWithRetiredKeys(currentKey, []RetiredKey{{Key: oldKey, RetiredAt: retiredAt}}, st)
	verifier.now = func() time.Time { return retiredAt.Add(maxAcceptedTokenLifetime + time.Second) }
	payload := []byte(`{"v":1}`)
	oldSecret := deriveHMACSecrets([]managerKey{{private: oldKey}})[0]
	if _, ok := verifier.matchStatelessSecret(statelessMAC(oldSecret, payload), payload); ok {
		t.Fatal("expired retired secret remained in stateless verification set")
	}
}
