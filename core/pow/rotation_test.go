// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/melroy89/angie-guardian/core/store"
)

func mintRotationToken(t *testing.T, m *Manager, host, ip, ua string) string {
	t.Helper()
	ch, err := m.Issue(context.Background(), host, ip, "/", 0, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: "0", Host: host, IP: ip, UserAgent: ua,
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

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
	if err := m.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA", 0, 0); err != nil {
		t.Fatal(err)
	}

	// Rotate. The signing key changes; the old key is archived.
	if err := m.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}

	// The pre-rotation token still verifies (old key kept in the verify set).
	if err := m.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA", 0, 0); err != nil {
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
	if err := m.VerifyToken(res2.Token, "example.com", "198.51.100.7", "UA", 0, 0); err != nil {
		t.Fatalf("post-rotation token must verify: %v", err)
	}

	// A fresh Manager loading only the current key (no prevDir) rejects the
	// old token — proving the old signature really did change.
	freshKey, _ := LoadOrCreateKey(keyPath)
	fresh := NewManager(freshKey, st)
	if err := fresh.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA", 0, 0); err == nil {
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
	if err := peer.VerifyToken(oldToken, "example.com", "198.51.100.7", "UA", 0, 0); err != nil {
		t.Fatalf("peer with archived key must accept old token: %v", err)
	}
}

func TestRetiredKeyCannotMintPostRetirementOrOverlongTokens(t *testing.T) {
	_, retired, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, current, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	retiredAt := time.Unix(1_800_000_000, 0).UTC()
	now := retiredAt.Add(2 * time.Hour)
	m := newManagerWithRetiredKeys(current, []RetiredKey{{Key: retired, RetiredAt: retiredAt}}, st)
	m.now = func() time.Time { return now }

	const host, ip, ua = "example.com", "198.51.100.7", "Mozilla/5.0"
	sign := func(issued, expires time.Time) string {
		t.Helper()
		claims := &TokenClaims{
			Host: host,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   Fingerprint(ip, ua),
				IssuedAt:  jwt.NewNumericDate(issued),
				NotBefore: jwt.NewNumericDate(issued),
				ExpiresAt: jwt.NewNumericDate(expires),
			},
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(retired)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	legitimate := sign(retiredAt.Add(-time.Minute), retiredAt.Add(3*time.Hour))
	if err := m.VerifyToken(legitimate, host, ip, ua, 0, 0); err != nil {
		t.Fatalf("bounded pre-retirement token rejected: %v", err)
	}
	overlong := sign(retiredAt.Add(-time.Minute), retiredAt.Add(10*365*24*time.Hour))
	if err := m.VerifyToken(overlong, host, ip, ua, 0, 0); err == nil {
		t.Fatal("overlong token signed by retired key was accepted")
	}
	postRetirement := sign(retiredAt.Add(time.Hour), retiredAt.Add(3*time.Hour))
	if err := m.VerifyToken(postRetirement, host, ip, ua, 0, 0); err == nil {
		t.Fatal("token minted after key retirement was accepted")
	}
}

func TestLivePeerRefreshesAfterRotation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })

	a, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	host, ip, ua := "example.com", "198.51.100.8", "UA"
	oldToken := mintRotationToken(t, b, host, ip, ua)

	if err := a.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}
	newToken := mintRotationToken(t, a, host, ip, ua)
	for name, tc := range map[string]struct {
		manager *Manager
		token   string
	}{
		"rotating peer accepts old token":   {a, oldToken},
		"live peer accepts old token":       {b, oldToken},
		"rotating peer accepts new token":   {a, newToken},
		"live peer refreshes for new token": {b, newToken},
	} {
		if err := tc.manager.VerifyToken(tc.token, host, ip, ua, 0, 0); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLivePeerRefreshesBeforeAcceptingOldKeyJWT(t *testing.T) {
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
	oldKey := peer.signingKey()
	base := time.Unix(1_900_000_000, 0).UTC()
	rotator.now = func() time.Time { return base }
	if err := rotator.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}

	const host, ip, ua = "example.test", "198.51.100.44", "Mozilla/5.0"
	issued := base.Add(2 * time.Second)
	claims := func() *TokenClaims {
		return &TokenClaims{
			Host: host, Difficulty: 32,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: Fingerprint(ip, ua), IssuedAt: jwt.NewNumericDate(issued),
				NotBefore: jwt.NewNumericDate(issued), ExpiresAt: jwt.NewNumericDate(issued.Add(time.Hour)),
			},
		}
	}
	forgedOld, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims()).SignedString(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	peer.now = func() time.Time { return issued }
	if err := peer.VerifyToken(forgedOld, host, ip, ua, 20, time.Hour); err == nil {
		t.Fatal("quiet peer accepted a freshly forged JWT from the retired key")
	}

	// A current-key token verifies and enters the cache. Losing access to the
	// key files after the next refresh deadline must still fail closed before
	// that cache can be consulted, and the throttled consecutive call must
	// remember the refresh failure rather than accepting the cached token.
	currentToken, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims()).SignedString(rotator.signingKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.VerifyToken(currentToken, host, ip, ua, 20, time.Hour); err != nil {
		t.Fatalf("current-key token rejected: %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	afterDeadline := issued.Add(keyRefreshInterval + time.Millisecond)
	peer.now = func() time.Time { return afterDeadline }
	firstErr := peer.VerifyToken(currentToken, host, ip, ua, 20, time.Hour)
	secondErr := peer.VerifyToken(currentToken, host, ip, ua, 20, time.Hour)
	if firstErr == nil || secondErr == nil {
		t.Fatalf("cached token bypassed key refresh failure: first=%v second=%v", firstErr, secondErr)
	}
}

func TestSuccessfulSigningDoesNotProlongVerificationRefreshFailure(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })

	m, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_900_000_000, 0).UTC()
	m.now = func() time.Time { return base }
	m.routineRefreshUntil.Store(base.Add(-time.Second).UnixNano())
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyToken("invalid", "example.test", "192.0.2.1", "ua", 0, 0); err == nil {
		t.Fatal("verification unexpectedly survived a missing current-key file")
	}
	if err := os.WriteFile(keyPath, rawKey, 0o600); err != nil {
		t.Fatal(err)
	}

	// Signing already loads the current key under the rotation lock. It must
	// not move the full-keyset refresh timestamp: doing so can keep returning a
	// cached retired-key-directory error forever on a busy issuer.
	afterThrottle := base.Add(keyRefreshInterval + time.Millisecond)
	m.now = func() time.Time { return afterThrottle }
	token, err := m.mintToken("example.test", Fingerprint("192.0.2.1", "ua"), "cid", 20, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyToken(token, "example.test", "192.0.2.1", "ua", 20, time.Hour); err != nil {
		t.Fatalf("verification did not recover after key files returned: %v", err)
	}
}

func TestReloadTakesAtomicSnapshotAcrossRotation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cross-process rotation lock is implemented on Linux")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	m, err := NewManagerFromFiles(keyPath, prevDir, st)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_900_000_000, 0).UTC()
	m.now = func() time.Time { return base }
	oldRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Pause a rotation after archiving the old key but before replacing the
	// current file. Reload must wait instead of installing this torn snapshot.
	unlock, err := lockRotation(keyPath + ".rotate.lock")
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			unlock()
		}
	}()
	if err := os.MkdirAll(prevDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := archiveKey(filepath.Join(prevDir, fmt.Sprintf("%d-paused.key", base.Unix())), oldRaw); err != nil {
		t.Fatal(err)
	}
	reloaded := make(chan error, 1)
	go func() { reloaded <- m.ReloadKeys() }()
	select {
	case err := <-reloaded:
		t.Fatalf("reload escaped the rotation lock with torn key state: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	newKey, newPEM, err := newKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicReplaceKey(keyPath, newPEM); err != nil {
		t.Fatal(err)
	}
	unlock()
	released = true
	if err := <-reloaded; err != nil {
		t.Fatal(err)
	}
	if !m.signingKey().Equal(newKey) {
		t.Fatal("reload did not install the post-rotation current key")
	}
	keys := m.verificationKeys()
	if len(keys) != 2 || keys[1].retiredAt.IsZero() {
		t.Fatalf("reload did not install one retired old key: %+v", keys)
	}
}

func TestPeerNeverSignsWithAlreadyRetiredKey(t *testing.T) {
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
	rotationTime := base.Add(900 * time.Millisecond)
	signingTime := base.Add(1050 * time.Millisecond)
	rotator.now = func() time.Time { return rotationTime }
	if err := rotator.Rotate(keyPath, prevDir); err != nil {
		t.Fatal(err)
	}

	// The peer's normal refresh timestamp is deliberately inside the old
	// 250ms throttle window. Signing must still lock and observe the new file.
	peer.lastRefresh = base.Add(850 * time.Millisecond)
	peer.now = func() time.Time { return signingTime }
	rotator.now = func() time.Time { return signingTime }
	token, err := peer.mintToken("example.test", Fingerprint("198.51.100.7", "UA"), "cid", 20, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.VerifyToken(token, "example.test", "198.51.100.7", "UA", 0, 0); err != nil {
		t.Fatalf("peer minted a token with an already-retired key: %v", err)
	}
}

func TestLoadRetiredKeysDeduplicatesUsingLatestRetirement(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	prevDir := filepath.Join(dir, "previous")
	if err := os.MkdirAll(prevDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(raw)
	for _, stamp := range []int64{1_900_000_000, 1_900_000_100} {
		name := filepath.Join(prevDir, fmt.Sprintf("%d-%x.key", stamp, fingerprint[:8]))
		if err := archiveKey(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := loadRetiredKeysAt(prevDir, time.Unix(1_900_000_101, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].Key.Equal(key) {
		t.Fatalf("deduplicated keys = %d, want the one archived key", len(keys))
	}
	if got := keys[0].RetiredAt.Unix(); got != 1_900_000_100 {
		t.Fatalf("retirement timestamp = %d, want latest 1900000100", got)
	}
}

func TestLoadRetiredKeysOmitsExpiredHorizon(t *testing.T) {
	dir := t.TempDir()
	prevDir := filepath.Join(dir, "previous")
	if err := os.MkdirAll(prevDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	for i, stamp := range []int64{
		now.Add(-maxAcceptedTokenLifetime).Unix(),
		now.Add(-maxAcceptedTokenLifetime - time.Second).Unix(),
	} {
		path := filepath.Join(dir, fmt.Sprintf("key-%d", i))
		if _, err := LoadOrCreateKey(path); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := sha256.Sum256(raw)
		name := filepath.Join(prevDir, fmt.Sprintf("%d-%x.key", stamp, fingerprint[:8]))
		if err := archiveKey(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := loadRetiredKeysAt(prevDir, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("active retired keys = %d, want only the exact-horizon key", len(keys))
	}
	if got := keys[0].RetiredAt; !got.Equal(now.Add(-maxAcceptedTokenLifetime)) {
		t.Fatalf("kept retirement = %v, want exact horizon", got)
	}
}

func TestLoadRetiredKeysSkipsExpiredContentsBeforeParsing(t *testing.T) {
	prevDir := t.TempDir()
	now := time.Unix(1_900_000_000, 0).UTC()
	expired := now.Add(-maxAcceptedTokenLifetime - time.Second).Unix()
	path := filepath.Join(prevDir, fmt.Sprintf("%d-corrupt.key", expired))
	if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadRetiredKeysAt(prevDir, now)
	if err != nil {
		t.Fatalf("expired key contents were parsed: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expired keys = %d, want 0", len(keys))
	}
}

func TestRotateRequiresArchiveDirectory(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "ed25519.key")
	if _, err := LoadOrCreateKey(keyPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RotateKey(keyPath, "", time.Now().Unix()); err == nil {
		t.Fatal("rotation without previous_key_dir must fail")
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed rotation changed the current key")
	}
}

func TestSameSecondRotationsPreserveAllKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	k0, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	k1, err := RotateKey(keyPath, prevDir, now)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := RotateKey(keyPath, prevDir, now)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := LoadPreviousKeys(prevDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(previous) != 2 {
		t.Fatalf("archived keys = %d, want 2", len(previous))
	}
	retired, err := LoadRetiredKeys(prevDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range retired {
		if key.RetiredAt.Unix() != now {
			t.Fatalf("retirement timestamp = %v, want unix %d", key.RetiredAt, now)
		}
	}
	for _, want := range []ed25519.PrivateKey{k0, k1} {
		if !containsKey(previous, want) {
			t.Fatal("a pre-rotation key was lost from the archive")
		}
	}
	current, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Equal(k2) {
		t.Fatal("current key does not match the last rotation")
	}
}

func TestConcurrentRotationsAreAtomicAndPreserveKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.key")
	prevDir := filepath.Join(dir, "previous")
	original, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	const rotations = 8
	results := make(chan ed25519.PrivateKey, rotations)
	errs := make(chan error, rotations)
	stopReader := make(chan struct{})
	readerErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stopReader:
				readerErr <- nil
				return
			default:
				if _, err := loadKey(keyPath); err != nil {
					readerErr <- err
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for range rotations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := RotateKey(keyPath, prevDir, time.Now().Unix())
			if err != nil {
				errs <- err
				return
			}
			results <- key
		}()
	}
	wg.Wait()
	close(stopReader)
	if err := <-readerErr; err != nil {
		t.Fatalf("reader observed a missing or malformed current key: %v", err)
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	close(results)

	previous, err := LoadPreviousKeys(prevDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(previous) != rotations {
		t.Fatalf("archived keys = %d, want %d", len(previous), rotations)
	}
	current, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]ed25519.PrivateKey{current}, previous...)
	if !containsKey(all, original) {
		t.Fatal("original key was not preserved")
	}
	for generated := range results {
		if !containsKey(all, generated) {
			t.Fatal("a concurrently generated key was lost")
		}
	}
}

func containsKey(keys []ed25519.PrivateKey, want ed25519.PrivateKey) bool {
	for _, key := range keys {
		if key.Equal(want) {
			return true
		}
	}
	return false
}
