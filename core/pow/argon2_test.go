// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func solveArgon2(t *testing.T, ch *Challenge) string {
	t.Helper()
	salt, err := hex.DecodeString(ch.Salt)
	if err != nil {
		t.Fatal(err)
	}
	proof := argon2.IDKey([]byte(ch.Challenge), salt, ch.Iterations, ch.MemoryKiB, 1, argon2ProofSize)
	return hex.EncodeToString(proof)
}

func TestArgon2IDChallengeFormatsRedeem(t *testing.T) {
	for _, stateless := range []bool{false, true} {
		t.Run(map[bool]string{false: "stateful-v2", true: "stateless-s2"}[stateless], func(t *testing.T) {
			m := testManager(t)
			spec := ProofSpec{Algorithm: AlgorithmArgon2ID, MemoryKiB: 8 * 1024, Iterations: 1}
			var ch *Challenge
			var err error
			if stateless {
				ch, err = m.IssueStatelessWithSpec("a.test", "203.0.113.7", "/page", spec, false)
			} else {
				ch, err = m.IssueWithSpec(context.Background(), "a.test", "203.0.113.7", "/page", spec, time.Minute, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			if ch.Algorithm != AlgorithmArgon2ID || ch.Difficulty != 0 || ch.Salt == "" {
				t.Fatalf("challenge policy = algorithm %q bits %d salt %q", ch.Algorithm, ch.Difficulty, ch.Salt)
			}
			res, err := m.Redeem(context.Background(), &RedeemRequest{
				ChallengeID: ch.ID, Proof: solveArgon2(t, ch), Host: "a.test", IP: "203.0.113.7", UserAgent: "UA",
				TokenTTL: time.Hour, ChallengeTTL: time.Minute,
				AcquireArgon: func() error { return nil }, ReleaseArgon: func() {},
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Algorithm != AlgorithmArgon2ID || res.MemoryKiB != 8*1024 || res.Iterations != 1 {
				t.Fatalf("redeem policy = %+v", res)
			}
			if err := m.VerifyToken(res.Token, "a.test", "203.0.113.7", "UA", 0, time.Hour); err != nil {
				t.Fatalf("argon2id token did not verify: %v", err)
			}
			if err := m.VerifyToken(res.Token, "a.test", "203.0.113.7", "UA", 24, time.Hour); err != nil {
				t.Fatalf("algorithm reload must not compare an Argon2id token with SHA bits: %v", err)
			}
		})
	}
}

func TestArgon2IDBusyDoesNotConsumeChallenge(t *testing.T) {
	m := testManager(t)
	spec := ProofSpec{Algorithm: AlgorithmArgon2ID, MemoryKiB: 8 * 1024, Iterations: 1}
	ch, err := m.IssueWithSpec(context.Background(), "a.test", "203.0.113.7", "/", spec, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	proof := solveArgon2(t, ch)
	req := &RedeemRequest{
		ChallengeID: ch.ID, Proof: proof, Host: "a.test", IP: "203.0.113.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
		AcquireArgon: func() error { return ErrVerifierBusy }, ReleaseArgon: func() {},
	}
	if _, err := m.Redeem(context.Background(), req); !errors.Is(err, ErrVerifierBusy) {
		t.Fatalf("busy redemption = %v, want ErrVerifierBusy", err)
	}
	req.AcquireArgon = func() error { return nil }
	if _, err := m.Redeem(context.Background(), req); err != nil {
		t.Fatalf("retrying the same challenge after busy: %v", err)
	}
}

func TestArgon2IDRejectsWrongProofWithoutSpending(t *testing.T) {
	m := testManager(t)
	spec := ProofSpec{Algorithm: AlgorithmArgon2ID, MemoryKiB: 8 * 1024, Iterations: 1}
	ch, err := m.IssueStatelessWithSpec("a.test", "203.0.113.7", "/", spec, false)
	if err != nil {
		t.Fatal(err)
	}
	req := &RedeemRequest{
		ChallengeID: ch.ID, Proof: hex.EncodeToString(make([]byte, argon2ProofSize)), Host: "a.test", IP: "203.0.113.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
		AcquireArgon: func() error { return nil }, ReleaseArgon: func() {},
	}
	if _, err := m.Redeem(context.Background(), req); !errors.Is(err, ErrBadSolution) {
		t.Fatalf("wrong proof = %v, want ErrBadSolution", err)
	}
	req.Proof = solveArgon2(t, ch)
	if _, err := m.Redeem(context.Background(), req); err != nil {
		t.Fatalf("valid retry after wrong proof: %v", err)
	}
}
