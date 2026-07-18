// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// countingStore counts writes and can force CAS failures, to prove stateless
// issuance is store-free and that a failed single-spend still mints.
type countingStore struct {
	store.Store
	writes  atomic.Int64
	failCAS bool
}

func (s *countingStore) Set(ctx context.Context, key string, v []byte, ttl time.Duration) error {
	s.writes.Add(1)
	return s.Store.Set(ctx, key, v, ttl)
}

func (s *countingStore) CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	s.writes.Add(1)
	if s.failCAS {
		return false, errors.New("store down")
	}
	return s.Store.CompareAndSwap(ctx, key, old, new, ttl)
}

func TestStatelessRoundTrip(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	ch, err := m.IssueStateless("Example.test", "203.0.113.7", "/page?x=1", 8, false)
	if err != nil {
		t.Fatal(err)
	}
	if !IsStatelessID(ch.ID) || !strings.HasPrefix(ch.ID, "s1.") {
		t.Fatalf("id %q is not a stateless id", ch.ID)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "example.test", IP: "203.0.113.7", UserAgent: "Mozilla/5.0",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if res.Token == "" || res.RedirectURI != "/page?x=1" || res.SoftError != nil {
		t.Fatalf("bad result: %+v", res)
	}
	// The minted token verifies at the embedded difficulty.
	if err := m.VerifyToken(res.Token, "example.test", "203.0.113.7", "Mozilla/5.0", 8, time.Hour); err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
}

func TestStatelessIssuesNoStoreWrite(t *testing.T) {
	m := testManager(t)
	cs := &countingStore{Store: m.store}
	m.store = cs
	if _, err := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false); err != nil {
		t.Fatal(err)
	}
	if cs.writes.Load() != 0 {
		t.Fatalf("stateless issuance performed %d store writes, want 0", cs.writes.Load())
	}
}

func TestStatelessMACTamperRejected(t *testing.T) {
	m := testManager(t)
	ch, err := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the payload segment.
	parts := strings.SplitN(ch.ID, ".", 3)
	tampered := parts[0] + "." + flipChar(parts[1]) + "." + parts[2]
	_, err = m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: tampered, Nonce: "0",
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("tampered payload err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessBindingMismatch(t *testing.T) {
	m := testManager(t)
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	_, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.99", UserAgent: "x", // wrong IP
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong-IP err = %v, want ErrBindingMismatch", err)
	}
}

func TestStatelessExpiryAndSkew(t *testing.T) {
	m := testManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	nonce := solve(t, ch.Challenge, 8)

	// Past the challenge TTL: rejected.
	m.now = func() time.Time { return now.Add(31 * time.Minute) }
	_, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("expired err = %v, want ErrChallengeUnknown", err)
	}

	// Issued far in the "future" (beyond skew): rejected.
	m.now = func() time.Time { return now.Add(-2 * time.Minute) }
	_, err = m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("future-skew err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessBadSolution(t *testing.T) {
	m := testManager(t)
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 12, false)
	_, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: "definitely-not-a-solution",
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrBadSolution) {
		t.Fatalf("bad solution err = %v, want ErrBadSolution", err)
	}
}

func TestStatelessReplayRejected(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	req := &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	}
	if _, err := m.Redeem(ctx, req); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := m.Redeem(ctx, req); !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("replay err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessSpendCASFailureStillMints(t *testing.T) {
	m := testManager(t)
	cs := &countingStore{Store: m.store, failCAS: true}
	m.store = cs
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	res, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("store-down redeem should fail open, got err %v", err)
	}
	if res.Token == "" || res.SoftError == nil {
		t.Fatalf("expected a minted token with a SoftError, got %+v", res)
	}
}

func TestStatefulStillRedeemsAlongsideStateless(t *testing.T) {
	// The 32-hex stateful path must keep working after the dispatch change.
	m := testManager(t)
	ctx := context.Background()
	ch, err := m.Issue(ctx, "a.test", "203.0.113.7", "/", 8, 30*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil || res.Token == "" {
		t.Fatalf("stateful redeem broke: %v / %+v", err, res)
	}
}

func flipChar(s string) string {
	b := []byte(s)
	if len(b) == 0 {
		return "x"
	}
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}
