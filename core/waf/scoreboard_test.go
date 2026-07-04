// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

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

func blocked(t *testing.T, st store.Store, ip string) (string, bool) {
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
	if _, ok := blocked(t, st, ip); ok {
		t.Fatal("blocked before reaching the threshold")
	}
	hit, err := board.RecordEvent(ctx, ip, "signature", 3, time.Minute, 15*time.Minute, time.Hour)
	if err != nil || !hit {
		t.Fatalf("third event: hit=%v err=%v, want block", hit, err)
	}
	if reason, ok := blocked(t, st, ip); !ok || reason != "threshold:signature" {
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

	// First offense: base TTL. We can't read TTLs from the interface, so use
	// the offense counter as the observable: each Block doubles from base.
	if err := board.Block(ctx, ip, "test", 10*time.Millisecond, 40*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, ok := blocked(t, st, ip); !ok {
		t.Fatal("first block not placed")
	}
	// Second offense: 20ms. Third: 40ms (capped). Verify the cap holds by
	// checking the block expires within ~the cap rather than 80ms+.
	_ = board.Block(ctx, ip, "test", 10*time.Millisecond, 40*time.Millisecond)
	_ = board.Block(ctx, ip, "test", 10*time.Millisecond, 40*time.Millisecond)
	_ = board.Block(ctx, ip, "test", 10*time.Millisecond, 40*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	if _, ok := blocked(t, st, ip); ok {
		t.Fatal("block outlived max_block_ttl cap")
	}

	// Unblock lifts an active block immediately.
	_ = board.Block(ctx, ip, "test", time.Hour, time.Hour)
	if err := board.Unblock(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if _, ok := blocked(t, st, ip); ok {
		t.Fatal("unblock did not lift the block")
	}
}
