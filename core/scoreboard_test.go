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
	return string(v), ok
}

func TestThresholdBlocks(t *testing.T) {
	ctx := context.Background()
	board, st := testBoard(t)
	ip := "198.51.100.7"

	for i := 1; i <= 2; i++ {
		hit, err := board.RecordEvent(ctx, ip, "signature", 3, time.Minute, 15*time.Minute, time.Hour)
		if err != nil || hit {
			t.Fatalf("event %d: hit=%v err=%v, want no block yet", i, hit, err)
		}
	}
	if _, ok := scoreboardBlocked(t, st, ip); ok {
		t.Fatal("blocked before reaching the threshold")
	}
	hit, err := board.RecordEvent(ctx, ip, "signature", 3, time.Minute, 15*time.Minute, time.Hour)
	if err != nil || !hit {
		t.Fatalf("third event: hit=%v err=%v, want block", hit, err)
	}
	if reason, ok := scoreboardBlocked(t, st, ip); !ok || reason != "threshold:signature" {
		t.Fatalf("block = %q %v, want threshold:signature true", reason, ok)
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
