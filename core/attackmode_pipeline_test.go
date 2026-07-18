// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"log/slog"
	"math/bits"
	"strconv"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// solvePoW brute-forces a nonce whose SHA-256 over challenge+nonce has at
// least difficulty leading zero bits (16 bits is ~65k hashes, instant).
func solvePoW(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for i := 0; ; i++ {
		nonce := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge + nonce))
		lead := 0
		for _, b := range sum {
			z := bits.LeadingZeros8(b)
			lead += z
			if z != 8 {
				break
			}
		}
		if lead >= difficulty {
			return nonce
		}
	}
}

const attackPipelineYAML = `
store: { backend: memory }
signing_key_file: k
attack_mode:
  enabled: true
  effects: { attack_difficulty_raise: 1.0, difficulty_cap: 7.0 }
defaults:
  pow: { enabled: true, mode: always, base_difficulty: 4, max_difficulty: 6 }
domains:
  html.test:
    pow: { enabled: true }
`

// attackEngine builds an engine with a detector pinned to a level.
func attackEngine(t *testing.T, level attackmode.Level) (*Engine, *pow.Manager) {
	t.Helper()
	cfg := loadTestConfig(t, attackPipelineYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key := mustKey(t)
	mgr := pow.NewManager(key, st)
	e, err := NewEngine(cfg, st, mgr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	d := attackmode.New(cfg.AttackModeSettings(), st, slog.Default())
	e.SetAttackDetector(d)
	if level != attackmode.Normal {
		d.Pin(level, 0)
	}
	return e, mgr
}

func TestAttackModeShiftsChallengeDifficulty(t *testing.T) {
	ctx := context.Background()
	// base_difficulty 4 = 16 bits. Attack raise +1.0 = +4 bits -> 20 bits.
	normalE, _ := attackEngine(t, attackmode.Normal)
	d := normalE.Evaluate(ctx, req("html.test", "198.51.100.7", "/page", "Mozilla/5.0"))
	if d.Action != ActionChallenge || d.Difficulty != 16 {
		t.Fatalf("normal: action=%s bits=%d, want challenge/16", d.Action, d.Difficulty)
	}

	attackE, _ := attackEngine(t, attackmode.Attack)
	d = attackE.Evaluate(ctx, req("html.test", "198.51.100.7", "/page", "Mozilla/5.0"))
	if d.Action != ActionChallenge || d.Difficulty != 20 {
		t.Fatalf("attack: action=%s bits=%d, want challenge/20 (16 + 4 raise)", d.Action, d.Difficulty)
	}
}

func TestAttackModeExistingTokenStaysValid(t *testing.T) {
	ctx := context.Background()
	attackE, mgr := attackEngine(t, attackmode.Attack)
	ip, ua, host := "198.51.100.8", "Mozilla/5.0", "html.test"

	// Mint a token at the UNSHIFTED base (16 bits), the way a client that
	// solved before the attack holds one.
	const base = 16
	ch, err := mgr.Issue(ctx, host, ip, "/", base, 4*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Redeem(ctx, &pow.RedeemRequest{
		ChallengeID: ch.ID, Nonce: solvePoW(t, ch.Challenge, base),
		Host: host, IP: ip, UserAgent: ua,
		TokenTTL: 4 * time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Even though attack mode raised NEW challenge difficulty to 20 bits, the
	// pre-attack 16-bit token must still vouch (no re-challenge stampede).
	d := attackE.Evaluate(ctx, &RequestContext{
		Host: host, Method: "GET", URI: "/page", RemoteAddr: ip, UserAgent: ua,
		Cookie: pow.CookieName + "=" + res.Token,
	})
	if d.Action != ActionAllow || d.Reason != "pow:token" {
		t.Fatalf("attack mode invalidated an existing token: %s/%s", d.Action, d.Reason)
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := pow.LoadOrCreateKey(t.TempDir() + "/ed25519.key")
	if err != nil {
		t.Fatal(err)
	}
	return k
}
