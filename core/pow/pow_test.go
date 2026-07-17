// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	m := NewManager(key, st)
	m.NoJSMinDelay = 10 * time.Millisecond
	// Run counter flushes inline so escalation tests see deterministic
	// store state instead of racing background goroutines.
	m.counters.Go = func(f func()) { f() }
	return m
}

func TestLoadOrCreateKeyConcurrentFirstStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ed25519.key")
	const workers = 64
	start := make(chan struct{})
	keys := make(chan ed25519.PrivateKey, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			key, err := LoadOrCreateKey(path)
			keys <- key
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(keys)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var want ed25519.PrivateKey
	for key := range keys {
		if want == nil {
			want = key
		}
		if !want.Equal(key) {
			t.Fatal("concurrent creators observed different signing keys")
		}
	}
}

// solve brute-forces a nonce for the given challenge — the Go equivalent of
// the browser solver. Tests use difficulties of a few bits so this is instant.
func solve(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := 0; n < 1_000_000; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		if leadingZeroBits(sum[:]) >= difficulty {
			return nonce
		}
	}
	t.Fatal("no nonce found within bound")
	return ""
}

func TestKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "ed25519.key")
	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Fatal("key must never be regenerated on reload — restarts would log everyone out")
	}
}

func TestIssueRedeemRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)

	ch, err := m.Issue(ctx, "Example.COM", "198.51.100.7", "/original?q=1", 8, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.ID) != 32 || len(ch.Challenge) != 64 || ch.Difficulty != 8 {
		t.Fatalf("unexpected challenge shape: %+v", ch)
	}

	req := &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "example.com", IP: "198.51.100.7", UserAgent: "Mozilla/5.0",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	}
	res, err := m.Redeem(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.RedirectURI != "/original?q=1" {
		t.Errorf("redirect = %q, want original URI", res.RedirectURI)
	}

	// The minted token verifies for the same client+host, and only for them.
	if err := m.VerifyToken(res.Token, "example.com", "198.51.100.7", "Mozilla/5.0", 0); err != nil {
		t.Errorf("token should verify: %v", err)
	}
	if err := m.VerifyToken(res.Token, "other.com", "198.51.100.7", "Mozilla/5.0", 0); err == nil {
		t.Error("token must not verify for another host")
	}
	if err := m.VerifyToken(res.Token, "example.com", "203.0.113.1", "Mozilla/5.0", 0); err == nil {
		t.Error("token must not verify for another IP")
	}
	if err := m.VerifyToken(res.Token+"x", "example.com", "198.51.100.7", "Mozilla/5.0", 0); err == nil {
		t.Error("tampered token must not verify")
	}

	// Double redemption must fail: the spent CAS is the anti-replay guarantee.
	if _, err := m.Redeem(ctx, req); !errors.Is(err, ErrChallengeUnknown) {
		t.Errorf("second redemption = %v, want ErrChallengeUnknown", err)
	}
}

func TestMinimumTokenTTLIsImmediatelyValid(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 900_000_000, time.UTC)
	m.now = func() time.Time { return now }

	ch, err := m.Issue(ctx, "example.com", "198.51.100.7", "/", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 4),
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Second, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TokenTTL != time.Second {
		t.Fatalf("redeemed token TTL = %v, want 1s", res.TokenTTL)
	}
	if err := m.VerifyToken(res.Token, "example.com", "198.51.100.7", "UA", 0); err != nil {
		t.Fatalf("new token at minimum accepted TTL is not immediately valid: %v", err)
	}
}

func TestRedeemRejections(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)

	ch, err := m.Issue(ctx, "example.com", "198.51.100.7", "/", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	nonce := solve(t, ch.Challenge, 4)
	base := RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	}

	for name, tc := range map[string]struct {
		mutate func(*RedeemRequest)
		want   error
	}{
		"unknown id":  {func(r *RedeemRequest) { r.ChallengeID = "00000000000000000000000000000000" }, ErrChallengeUnknown},
		"bad id len":  {func(r *RedeemRequest) { r.ChallengeID = "short" }, ErrChallengeUnknown},
		"wrong host":  {func(r *RedeemRequest) { r.Host = "evil.com" }, ErrBindingMismatch},
		"wrong ip":    {func(r *RedeemRequest) { r.IP = "203.0.113.1" }, ErrBindingMismatch},
		"nojs denied": {func(r *RedeemRequest) { r.NoJS = true }, ErrNoJSDisabled},
	} {
		req := base
		tc.mutate(&req)
		if _, err := m.Redeem(ctx, &req); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}

	// A nonce that doesn't meet the difficulty. Find one deterministically.
	req := base
	for n := 0; ; n++ {
		s := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(ch.Challenge + s))
		if leadingZeroBits(sum[:]) < 4 {
			req.Nonce = s
			break
		}
	}
	if _, err := m.Redeem(ctx, &req); !errors.Is(err, ErrBadSolution) {
		t.Errorf("weak nonce: err = %v, want ErrBadSolution", err)
	}

	// All those rejections must not have spent the challenge.
	if _, err := m.Redeem(ctx, &base); err != nil {
		t.Errorf("valid redemption after rejections should succeed, got %v", err)
	}
}

func TestNoJSRedemption(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)

	ch, err := m.Issue(ctx, "example.com", "198.51.100.7", "/page", 4, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	req := &RedeemRequest{
		ChallengeID: ch.ID, NoJS: true,
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	}

	if _, err := m.Redeem(ctx, req); !errors.Is(err, ErrTooFast) {
		t.Fatalf("instant no-JS redemption = %v, want ErrTooFast", err)
	}
	time.Sleep(2 * m.NoJSMinDelay)
	res, err := m.Redeem(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.RedirectURI != "/page" {
		t.Errorf("redirect = %q, want /page", res.RedirectURI)
	}
	if err := m.VerifyToken(res.Token, "example.com", "198.51.100.7", "UA", 0); err != nil {
		t.Errorf("no-JS token should verify: %v", err)
	}
}

func TestLeadingZeroBits(t *testing.T) {
	for _, tc := range []struct {
		sum  []byte
		want int
	}{
		{[]byte{0xff, 0x00}, 0},
		{[]byte{0x80, 0x00}, 0},
		{[]byte{0x40, 0x00}, 1},
		{[]byte{0x20, 0x00}, 2},
		{[]byte{0x0f, 0x00}, 4},
		{[]byte{0x01, 0xff}, 7},
		{[]byte{0x00, 0xff}, 8},
		{[]byte{0x00, 0x0f}, 12},
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x00, 0x00}, 16},
	} {
		if got := leadingZeroBits(tc.sum); got != tc.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", tc.sum, got, tc.want)
		}
	}
}

// TestVerifyTokenMinBits: a token vouches only for a required difficulty no
// higher than what it was actually solved at, so per-path base_difficulty is
// enforced at verification and not just at issuance.
func TestVerifyTokenMinBits(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)

	ch, err := m.Issue(ctx, "example.com", "198.51.100.7", "/", 8, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, min := range []int{0, 4, 8} {
		if err := m.VerifyToken(res.Token, "example.com", "198.51.100.7", "UA", min); err != nil {
			t.Errorf("8-bit token must verify at min %d bits: %v", min, err)
		}
	}
	if err := m.VerifyToken(res.Token, "example.com", "198.51.100.7", "UA", 12); err == nil {
		t.Error("8-bit token must not verify at min 12 bits")
	}
	// The verification cache must not leak an accept across minimums: the
	// 8-bit accepts above are cached, 12 must still be rejected afterwards.
	if err := m.VerifyToken(res.Token, "example.com", "198.51.100.7", "UA", 12); err == nil {
		t.Error("cached accept must not satisfy a higher minimum")
	}
}

// TestRedeemTTLResolver: when the caller supplies a TTLs resolver, the token
// and spent-marker TTLs come from the URI the challenge was issued for, so
// per-path token policy applies at redemption.
func TestRedeemTTLResolver(t *testing.T) {
	ctx := context.Background()
	m := testManager(t)

	ch, err := m.Issue(ctx, "example.com", "198.51.100.7", "/app/login", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	var gotURI string
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 4),
		Host: "example.com", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
		TTLs: func(uri string) (time.Duration, time.Duration) {
			gotURI = uri
			return 30 * time.Minute, time.Minute
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotURI != "/app/login" {
		t.Errorf("TTLs resolver got URI %q, want the issued URI", gotURI)
	}
	if res.TokenTTL != 30*time.Minute {
		t.Errorf("token TTL = %v, want the resolver's 30m", res.TokenTTL)
	}
}
