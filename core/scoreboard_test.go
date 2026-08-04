// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

func testBoard(t *testing.T) (*Scoreboard, store.Store) {
	t.Helper()
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	return NewScoreboard(st, slog.Default()), st
}

func scoreboardBlocked(t *testing.T, st store.Store, ip string) (string, bool) {
	t.Helper()
	v, ok, err := st.Get(context.Background(), BlockKey(ip))
	if err != nil {
		t.Fatal(err)
	}
	return store.BlockReason(v), ok
}

func TestThresholdBlocks(t *testing.T) {
	ctx := context.Background()
	board, st := testBoard(t)
	ip := "198.51.100.7"

	for i := 1; i <= 2; i++ {
		hit, err := board.RecordEvent(ctx, ip, "rule_match", 3, time.Minute, 15*time.Minute, time.Hour)
		if err != nil || hit {
			t.Fatalf("event %d: hit=%v err=%v, want no block yet", i, hit, err)
		}
	}
	if _, ok := scoreboardBlocked(t, st, ip); ok {
		t.Fatal("blocked before reaching the threshold")
	}
	hit, err := board.RecordEvent(ctx, ip, "rule_match", 3, time.Minute, 15*time.Minute, time.Hour)
	if err != nil || !hit {
		t.Fatalf("third event: hit=%v err=%v, want block", hit, err)
	}
	if reason, ok := scoreboardBlocked(t, st, ip); !ok || reason != "threshold:rule_match" {
		t.Fatalf("block = %q %v, want threshold:rule_match true", reason, ok)
	}

	// Events of a different type use separate counters.
	if hit, _ := board.RecordEvent(ctx, "198.51.100.8", "pow_fail", 3, time.Minute, time.Minute, time.Hour); hit {
		t.Fatal("different IP/type must not share the counter")
	}

	// Zero limit means "not configured".
	if hit, _ := board.RecordEvent(ctx, "198.51.100.9", "x", 0, time.Minute, time.Minute, time.Hour); hit {
		t.Fatal("limit 0 must never block")
	}
}

func TestBlockBackoff(t *testing.T) {
	ctx := context.Background()
	board, st := testBoard(t)
	ip := "203.0.113.5"

	// A block at base TTL is placed and readable.
	if err := board.Block(ctx, ip, "test", time.Hour, 4*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, ok := scoreboardBlocked(t, st, ip); !ok {
		t.Fatal("first block not placed")
	}

	// Backoff caps at maxBlockTTL. Using a short cap and a base at the cap, the
	// TTL never exceeds the cap regardless of offense count. We assert expiry
	// with a generous window so a slow/contended runner can't flake it.
	const cap = 300 * time.Millisecond
	capIP := "203.0.113.6"
	for i := 0; i < 5; i++ {
		_ = board.Block(ctx, capIP, "test", cap, cap)
	}
	if _, ok := scoreboardBlocked(t, st, capIP); !ok {
		t.Fatal("capped block should still be active immediately after placing")
	}
	time.Sleep(cap + 300*time.Millisecond)
	if _, ok := scoreboardBlocked(t, st, capIP); ok {
		t.Fatal("block outlived max_block_ttl cap")
	}

	// Unblock lifts an active block immediately.
	_ = board.Block(ctx, ip, "test", time.Hour, time.Hour)
	if err := board.Unblock(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if _, ok := scoreboardBlocked(t, st, ip); ok {
		t.Fatal("unblock did not lift the block")
	}
}

// TestBlockKeyCanonicalIPv6 pins the canonical store key for every textual
// form an IPv6 client can arrive as: mixed case, expanded zeros, and the
// IPv4-mapped form a dual-stack listener reports for a v4 client. A zone
// identifier is part of the address identity and survives; garbage passes
// through verbatim (fail-open).
func TestBlockKeyCanonicalIPv6(t *testing.T) {
	cases := map[string]string{
		"2001:0DB8:0000:0000:0000:0000:0000:0001": "block:2001:db8::1",
		"2001:DB8::1":         "block:2001:db8::1",
		"::FFFF:198.51.100.7": "block:198.51.100.7",
		"fe80::1%eth0":        "block:fe80::1%eth0",
		"not-an-ip":           "block:not-an-ip",
	}
	for in, want := range cases {
		if got := BlockKey(in); got != want {
			t.Errorf("BlockKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestThresholdBlocksIPv6SharedCounter: events arriving under different
// textual forms of one IPv6 address share a single counter, and the block is
// readable via any form. Without canonicalization each form would count
// separately and the threshold would never trip.
func TestThresholdBlocksIPv6SharedCounter(t *testing.T) {
	ctx := context.Background()
	board, st := testBoard(t)
	forms := []string{
		"2001:DB8::7",
		"2001:0db8:0000:0000:0000:0000:0000:0007",
		"2001:db8::7",
	}
	for i, form := range forms {
		hit, err := board.RecordEvent(ctx, form, "rule_match", 3, time.Minute, 15*time.Minute, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if want := i == len(forms)-1; hit != want {
			t.Fatalf("event %d (%s): hit=%v, want %v (forms must share one counter)", i+1, form, hit, want)
		}
	}
	if reason, ok := scoreboardBlocked(t, st, "2001:0DB8::0007"); !ok || reason != "threshold:rule_match" {
		t.Fatalf("block via yet another form = %q %v, want threshold:rule_match true", reason, ok)
	}

	// The IPv4-mapped form shares identity with the plain v4 address.
	for _, form := range []string{"::ffff:203.0.113.80", "203.0.113.80", "::FFFF:203.0.113.80"} {
		if hit, err := board.RecordEvent(ctx, form, "pow_fail", 3, time.Minute, time.Minute, time.Hour); err != nil {
			t.Fatal(err)
		} else if want := form == "::FFFF:203.0.113.80"; hit != want {
			t.Fatalf("%s: hit=%v, want %v", form, hit, want)
		}
	}
	if _, ok := scoreboardBlocked(t, st, "203.0.113.80"); !ok {
		t.Fatal("mapped-form events must land on the v4 identity's block")
	}
}

// TestBlockBackoffIPv6SharedOffenses: repeat blocks of the same IPv6 address
// under different textual forms share the backoff counter, so the second
// block doubles the TTL instead of restarting at base.
func TestBlockBackoffIPv6SharedOffenses(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	board := NewScoreboard(st, slog.Default())

	if err := board.Block(ctx, "2001:DB8::9", "flood", time.Hour, 4*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := board.Block(ctx, "2001:0db8::9", "flood", time.Hour, 4*time.Hour); err != nil {
		t.Fatal(err)
	}
	exp, ok := st.ExpiresAt(BlockKey("2001:db8::9"))
	if !ok || exp.IsZero() {
		t.Fatal("block not placed under the canonical key")
	}
	// Offense 2 doubles the 1h base to 2h; a split counter would leave it at 1h.
	if until := time.Until(exp); until < 90*time.Minute {
		t.Fatalf("second block via another textual form expires in %v, want ~2h (shared backoff counter)", until)
	}
}

// TestBlockBackoffNoOverflow guards the exponential backoff against a config
// with no cap (max_block_ttl <= 0). Without the hard ceiling the doubling
// overflows time.Duration negative around ~43 offenses, and a <= 0 TTL is
// stored as "no expiry" — a permanent, only-admin-removable block. The
// resulting TTL must stay positive and finite no matter how many offenses
// accrue, which we detect via the store's ExpiresAt.
func TestBlockBackoffNoOverflow(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	board := NewScoreboard(st, slog.Default())
	ip := "203.0.113.9"

	// 60 offenses with an uncapped config (maxBlockTTL = 0). 2^59 minutes would
	// wrap Duration negative several times over without the guard.
	for i := 0; i < 60; i++ {
		if err := board.Block(ctx, ip, "flood", 15*time.Minute, 0); err != nil {
			t.Fatalf("offense %d: %v", i, err)
		}
	}
	// The stored block must have a finite (non-zero) expiry. A zero expiry is
	// the "permanent" state the overflow produced — the exact bug.
	exp, ok := st.ExpiresAt(BlockKey(ip))
	if !ok {
		t.Fatal("block not placed")
	}
	if exp.IsZero() {
		t.Fatal("block is permanent (overflowed to a <=0 TTL) — no-cap backoff must still bound the TTL")
	}
	if until := time.Until(exp); until <= 0 || until > hardMaxBlockTTL+time.Minute {
		t.Fatalf("block TTL out of range: expires in %v, want (0, %v]", until, hardMaxBlockTTL)
	}
}
