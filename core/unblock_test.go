// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const unblockYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m
      thresholds: { pow_fail: 3/min, rule_match: off }
domains:
  slow.test:
    waf: { ip_behaviour: { thresholds: { pow_fail: 3/h } } }
    paths:
      /api/:
        waf: { ip_behaviour: { thresholds: { pow_fail: 2/s } } }
`

func unblockEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := loadTestConfig(t, unblockYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func blockedNow(t *testing.T, e *Engine, ip string) bool {
	t.Helper()
	_, blocked, err := e.BlockStatus(context.Background(), ip)
	if err != nil {
		t.Fatal(err)
	}
	return blocked
}

func offensesNow(t *testing.T, e *Engine, ip string) int64 {
	t.Helper()
	d, err := e.BlockDetailFor(context.Background(), ip)
	if err != nil {
		t.Fatal(err)
	}
	if d.Offenses == nil {
		return 0
	}
	return *d.Offenses
}

// TestUnblockClearsEventCounters is the regression for the bug that made
// unblock worse than doing nothing: the ev: counter that crossed the threshold
// survived the unblock at or above the limit, so the very next scored event
// re-blocked the IP, and blkct: made that re-block twice as long.
func TestUnblockClearsEventCounters(t *testing.T) {
	ctx := context.Background()
	e := unblockEngine(t)
	const ip = "198.51.100.44"

	for range 3 {
		e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	}
	if !blockedNow(t, e, ip) {
		t.Fatal("three pow_fail events at a 3/min threshold did not block")
	}
	if got := offensesNow(t, e, ip); got != 1 {
		t.Fatalf("offenses = %d after the first block, want 1", got)
	}

	reset, err := e.UnblockIP(ctx, ip, true)
	if err != nil {
		t.Fatal(err)
	}
	if reset.Incomplete {
		t.Fatal("reset reported incomplete against a healthy memory store")
	}
	if reset.EventKeys == 0 {
		t.Fatal("reset addressed no behaviour counters")
	}
	if !reset.BackoffReset {
		t.Fatal("reset_backoff was requested but not reported")
	}
	if blockedNow(t, e, ip) {
		t.Fatal("unblock did not lift the block")
	}
	if got := offensesNow(t, e, ip); got != 0 {
		t.Fatalf("offenses = %d after a backoff-resetting unblock, want 0", got)
	}

	// The whole point: one more event must not walk straight back into a block.
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	if blockedNow(t, e, ip) {
		t.Fatal("a single event re-blocked the IP: the counter that caused the block was not cleared")
	}

	// Release the reset window early: what follows is about the counters
	// themselves, and the guard would mask them. See
	// TestUnblockGuardHoldsOffScorers for the window's own behaviour.
	releaseUnblockGuard(t, e, ip)

	// The counter really restarted, rather than the threshold having moved:
	// three more events block again, and one would not.
	for range 2 {
		e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	}
	if blockedNow(t, e, ip) {
		t.Fatal("two events blocked at a 3/min threshold: the counter did not restart from zero")
	}
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	if !blockedNow(t, e, ip) {
		t.Fatal("three fresh events after the unblock did not block")
	}
	if got := offensesNow(t, e, ip); got != 1 {
		t.Fatalf("offenses = %d for the re-block, want 1 (the ladder was reset)", got)
	}
}

// releaseUnblockGuard ends the suppression window early, for tests that want
// to exercise the scoring path immediately after an unblock. It drops only the
// hold, which is exactly what expiry does; the generation stays, so a late
// block writer can still tell that an unblock ran across it.
func releaseUnblockGuard(t *testing.T, e *Engine, ip string) {
	t.Helper()
	if err := e.store.Delete(context.Background(), unblockHoldKey(canonIP(ip))); err != nil {
		t.Fatal(err)
	}
}

// TestUnblockGuardHoldsOffScorers: the reset cannot be made atomic against
// concurrent scorers with reads and deletes alone, so the unblock claims a
// short window in which no instance counts events for the IP or blocks it.
// Without that window a request that read a saturated counter before the reset
// simply writes its block after it, and the response says otherwise.
func TestUnblockGuardHoldsOffScorers(t *testing.T) {
	ctx := context.Background()
	e := unblockEngine(t)
	const ip = "198.51.100.64"

	for range 3 {
		e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	}
	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}

	// Well past the threshold, all inside the window: nothing counts, nothing
	// blocks. Not even the counter moves, or the first event after the window
	// lapsed would block on the backlog.
	for range 10 {
		e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "flooding the reset window")
	}
	if blockedNow(t, e, ip) {
		t.Fatal("scoring during the reset window re-blocked the IP")
	}
	// A direct block (the instant-block path, and what a peer instance's
	// scoreboard would do) is refused for the same reason.
	if err := e.board.Block(ctx, ip, "honeypot", time.Minute, time.Hour); err != nil {
		t.Fatal(err)
	}
	if blockedNow(t, e, ip) {
		t.Fatal("an automatic block landed during the reset window")
	}

	releaseUnblockGuard(t, e, ip)
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "first event after the window")
	if blockedNow(t, e, ip) {
		t.Fatal("the window's events were counted after all: one event past it blocked")
	}

	// Admin blocks are not gated: they do not go through the scoreboard, so an
	// operator who unblocks and then blocks by hand gets what they asked for.
	e2 := unblockEngine(t)
	const manual = "198.51.100.65"
	if _, err := e2.UnblockIP(ctx, manual, true); err != nil {
		t.Fatal(err)
	}
	if err := e2.BlockIP(ctx, manual, "operator changed their mind", time.Hour); err != nil {
		t.Fatal(err)
	}
	if !blockedNow(t, e2, manual) {
		t.Fatal("an admin block was suppressed by the reset window")
	}
}

// TestBlockWithdrawnWhenItRacesAnUnblock: a scorer that passed the guard check
// before the window opened still has its write land inside it. Block notices on
// the way out and takes the write back, which is the half of the convergence
// that does not depend on the unblock looking again.
func TestBlockWithdrawnWhenItRacesAnUnblock(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, false)
	const ip = "198.51.100.66"

	// The window opens after Block has passed its first check and written the
	// key, which is the schedule no number of checks before the write can
	// cover. Only the check on the way out can.
	var once sync.Once
	st.hookSet(func(key string) {
		if key != BlockKey(ip) {
			return
		}
		once.Do(func() {
			st.hookSet(nil)
			if err := e.board.CommitUnblock(ctx, ip, true); err != nil {
				t.Error(err)
			}
		})
	})
	if err := e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour); err != nil {
		t.Fatal(err)
	}
	if blockedNow(t, e, ip) {
		t.Fatal("a block written across an opening reset window was not withdrawn")
	}
}

// gateBlockWrite holds a Block that is already past its admission read just
// short of writing block:<ip>, and returns a channel that is closed once it is
// waiting there plus the release function. Everything the block did up to that
// point has happened; the atomic block/offense commit has not.
func gateBlockWrite(t *testing.T, st *hookedStore, key string) (waiting <-chan struct{}, release func()) {
	t.Helper()
	admitted := make(chan struct{})
	gate := make(chan struct{})
	var once sync.Once
	st.hookBeforeSet(func(k string) {
		if k != key {
			return
		}
		once.Do(func() {
			st.hookBeforeSet(nil)
			close(admitted)
			<-gate
		})
	})
	return admitted, func() { close(gate) }
}

// TestBlockWithdrawnLongAfterTheWindowLapsed is the schedule a window alone
// cannot cover, and the reason the unblock mark outlives the window it opens.
// A writer is admitted, stalls past the suppression window, and only then
// writes. Asking "is a window still open?" on the way out answers no and the
// block stands, after the unblock has already reported a clean result that
// nothing later can amend. Asking "did an unblock happen since I was
// admitted?" answers yes however late the write is.
func TestBlockWithdrawnLongAfterTheWindowLapsed(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, false)
	const ip = "198.51.100.67"

	// A window short enough to be waited out inside a test. Nothing else in the
	// coordination is scaled to it, which is the property being tested.
	e.board.unblockHold = 20 * time.Millisecond

	admitted, release := gateBlockWrite(t, st, BlockKey(ip))
	done := make(chan error, 1)
	go func() { done <- e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour) }()
	<-admitted

	reset, err := e.UnblockIP(ctx, ip, true)
	if err != nil {
		t.Fatal(err)
	}
	if reset.Incomplete {
		t.Error("the unblock reported incomplete with nothing outstanding it could see")
	}
	if blockedNow(t, e, ip) {
		t.Fatal("setup: the gated block cannot have landed yet")
	}

	time.Sleep(4 * e.board.unblockHold) // the writer resumes unguarded
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if blockedNow(t, e, ip) {
		t.Fatal("a block that resumed after the window lapsed survived an unblock that reported success")
	}
	// And it left nothing behind for the next block to double: the offense it
	// counted goes back with the write it was counted for.
	if got := offensesNow(t, e, ip); got != 0 {
		t.Fatalf("offenses = %d after a withdrawn block, want 0", got)
	}
}

// TestUnblockCoordinationIgnoresInstanceClocks: two instances share a store
// and disagree about the time. Anything that expresses the coordination as a
// wall-clock instant breaks both ways here. A peer running ahead subtracts a
// fresh unblock from its own later clock and calls the window expired, so it
// blocks the IP milliseconds after the unblock; a peer running behind writes
// an unblock stamped earlier than one that already happened, so "is this
// newer?" answers no and the stale block survives. The store answers both
// questions instead: it expires the hold, and it orders the generation.
func TestUnblockCoordinationIgnoresInstanceClocks(t *testing.T) {
	ctx := context.Background()
	e := unblockEngine(t)
	const ip = "198.51.100.70"

	// A second scoreboard on the same store, ten seconds ahead of the first.
	// Ten seconds is five hold windows: nothing derived from this clock could
	// consider a just-written hold live.
	ahead := NewScoreboard(e.store, slog.Default())
	ahead.now = func() time.Time { return time.Now().Add(10 * time.Second) }

	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}
	if err := ahead.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour); err != nil {
		t.Fatal(err)
	}
	if blockedNow(t, e, ip) {
		t.Fatal("a peer with a fast clock blocked an IP inside another instance's reset window")
	}

	// The other direction: a writer on the fast instance is admitted, and the
	// unblock that runs across it is written by the slow one. A comparison of
	// timestamps would see the "newer" unblock as older and let the block
	// stand; a generation the store increments cannot be read backwards.
	const late = "198.51.100.71"
	behind := NewScoreboard(e.store, slog.Default())
	behind.now = func() time.Time { return time.Now().Add(-10 * time.Second) }

	admitted, err := behind.unblockToken(ctx, late) // stands in for the read at admission
	if err != nil {
		t.Fatal(err)
	}
	if err := behind.HoldUnblock(ctx, late); err != nil {
		t.Fatal(err)
	}
	if gen, err := ahead.unblockToken(ctx, late); err != nil || gen == admitted {
		t.Fatalf("generation %q unchanged across an unblock from an instance with an earlier clock", gen)
	}
}

// TestGenerationNeverRepeatsAValueAWriterHasSeen: the generation only has to
// answer "did this change while I was working", and a counter cannot answer
// that across its own expiry. Its retention is set by whichever unblock
// created the key, not by the latest one (an increment preserves the original
// expiry), so it can lapse and be recreated at 1 while a writer admitted at 1
// an epoch ago is still parked. That writer reads the same value it started
// with and concludes nothing happened. A value that is fresh per unblock, and
// retained from that unblock, has no such coincidence to hit.
func TestGenerationNeverRepeatsAValueAWriterHasSeen(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, false)
	const ip = "198.51.100.73"

	e.board.unblockHold = 20 * time.Millisecond

	// An earlier unblock's generation, moments from expiring.
	if err := e.store.Set(ctx, unblockGenKey(ip), []byte("1"), 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	admitted, release := gateBlockWrite(t, st, BlockKey(ip))
	done := make(chan error, 1)
	go func() { done <- e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour) }()
	<-admitted

	time.Sleep(60 * time.Millisecond) // the epoch the writer was admitted in ends
	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if blockedNow(t, e, ip) {
		t.Fatal("the new generation reproduced the value the writer was admitted on, so a stale block survived")
	}
}

// TestSuppressionCoversTheWholeReset: the reset is an unbounded number of
// store round trips, so a window that merely starts it is not a window that
// covers it. Events landing in the gap refill a counter the reset has already
// cleared, and the rest of the unblock then lifts the block and reports
// success over the top of a saturated counter, which reblocks the IP the
// moment the window really does lapse.
func TestSuppressionCoversTheWholeReset(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, false)
	const ip = "198.51.100.74"

	e.board.unblockHold = 20 * time.Millisecond

	for range 3 {
		e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	}
	if !blockedNow(t, e, ip) {
		t.Fatal("setup: three pow_fail events should have blocked")
	}

	// Stall the reset for several hold periods immediately after the old
	// generation's current bucket is deleted, then score through the gap.
	// Those events belong to the preparatory generation and must become stale
	// at the final atomic unblock boundary.
	current := eventKey(EventPoWFail, ip, "", eventBucket(e.board.now(), time.Minute))
	var once sync.Once
	st.hook(func(key string) {
		if key != current {
			return
		}
		once.Do(func() {
			st.hook(nil)
			time.Sleep(4 * e.board.unblockHold)
			for range 3 {
				e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "scoring through a slow reset")
			}
		})
	})

	reset, err := e.UnblockIP(ctx, ip, true)
	if err != nil {
		t.Fatal(err)
	}
	if blockedNow(t, e, ip) {
		t.Fatal("still blocked after the unblock returned")
	}
	if reset.Incomplete {
		t.Error("the reset held its window for the whole run but reported incomplete")
	}

	// The counter is what the response implicitly claims: one event past the
	// window must not walk straight back into a block.
	releaseUnblockGuard(t, e, ip)
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "first event after the window")
	if blockedNow(t, e, ip) {
		t.Fatal("events scored during a slow reset refilled the counter it had cleared")
	}
}

// TestEventWritesAdmittedBeforeUnblockStayInTheirOldGeneration covers the
// read/write seam in RecordEvent. A presence check alone cannot stop an Incr
// that passed before the hold and lands after the reset deleted its bucket;
// generation-scoped keys make that late write irrelevant to current traffic.
func TestEventWritesAdmittedBeforeUnblockStayInTheirOldGeneration(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, false)
	const ip = "198.51.100.75"

	key := eventKey(EventPoWFail, ip, "", eventBucket(e.board.now(), time.Minute))
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	st.hookBeforeIncr(func(k string) {
		if k != key {
			return
		}
		entered <- struct{}{}
		<-release
	})

	done := make(chan struct{}, 3)
	for range 3 {
		go func() {
			e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "admitted before unblock")
			done <- struct{}{}
		}()
	}
	for range 3 {
		<-entered
	}
	reset, err := e.UnblockIP(ctx, ip, true)
	if err != nil {
		t.Fatal(err)
	}
	if reset.Incomplete {
		t.Fatal("healthy unblock reported incomplete")
	}
	close(release)
	for range 3 {
		<-done
	}

	releaseUnblockGuard(t, e, ip)
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "first current-generation event")
	if blockedNow(t, e, ip) {
		t.Fatal("late old-generation increments refilled the current event bucket")
	}
}

// TestOffenseIsRecordedOnlyForABlockThatStands. blkct: is one number shared by
// every writer, so a writer cannot give back "its" increment: subtracting one
// is indistinguishable from taking away somebody else's, and the writer that
// would want to is by definition the one working from the stalest view. The
// offense is therefore recorded last, once the block is known to stand, and
// nothing ever decrements it.
func TestOffenseIsRecordedOnlyForABlockThatStands(t *testing.T) {
	ctx := context.Background()

	// Withdrawn because an unblock ran across it: the block never counted, so
	// the reset the operator asked for is what the counter reflects.
	t.Run("withdrawn by an unblock", func(t *testing.T) {
		e, st := hookedEngine(t, false)
		const ip = "198.51.100.68"

		admitted, release := gateBlockWrite(t, st, BlockKey(ip))
		done := make(chan error, 1)
		go func() { done <- e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour) }()
		<-admitted

		reset, err := e.UnblockIP(ctx, ip, true)
		if err != nil {
			t.Fatal(err)
		}
		if !reset.BackoffReset {
			t.Fatal("setup: the unblock did not report the backoff reset")
		}
		release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if blockedNow(t, e, ip) {
			t.Fatal("the raced block was not withdrawn")
		}
		if got := offensesNow(t, e, ip); got != 0 {
			t.Fatalf("offenses = %d, want 0: a withdrawn block left the ladder the unblock reset", got)
		}
	})

	// Beaten to the key by a newer block: the newer one owns the counter now,
	// and the stale writer must leave it exactly as it found it. Compensating
	// here used to charge the newer block's offense to the loser of the race,
	// so the block stood but its next one no longer doubled.
	t.Run("beaten by a newer block", func(t *testing.T) {
		e, st := hookedEngine(t, false)
		const ip = "198.51.100.69"

		e.board.unblockHold = 20 * time.Millisecond // waited out inside the test

		admitted, release := gateBlockWrite(t, st, BlockKey(ip))
		done := make(chan error, 1)
		go func() { done <- e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour) }()
		<-admitted

		if _, err := e.UnblockIP(ctx, ip, true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * e.board.unblockHold)
		// A fresh scorer, with a current view, blocks the IP again.
		if err := e.board.Block(ctx, ip, "threshold:rule_match", time.Minute, time.Hour); err != nil {
			t.Fatal(err)
		}
		if got := offensesNow(t, e, ip); got != 1 {
			t.Fatalf("setup: offenses = %d after the newer block, want 1", got)
		}

		release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}

		reason, blocked, err := e.BlockStatus(ctx, ip)
		if err != nil {
			t.Fatal(err)
		}
		if !blocked || reason != "threshold:rule_match" {
			t.Fatalf("block = %q %v, want threshold:rule_match true: the stale writer overwrote a newer block", reason, blocked)
		}
		if got := offensesNow(t, e, ip); got != 1 {
			t.Fatalf("offenses = %d, want 1: the stale writer moved a counter it does not own", got)
		}
	})
}

// TestCommittedBlockPublishesOnlyWhileOwned covers the seam after the backend
// transaction returns. Ownership can still change before the caller reaches
// its enforcement notification; NotifyOwned serializes a final store
// validation with local add/remove notifications.
func TestCommittedBlockPublishesOnlyWhileOwned(t *testing.T) {
	ctx := context.Background()

	t.Run("unblock wins after commit", func(t *testing.T) {
		e, st := hookedEngine(t, false)
		const ip = "198.51.100.76"
		enf := enforce.New(enforce.Config{
			Mode: enforce.ModeAuthoritative, ReconcileInterval: time.Hour, MaxEntries: 128,
		}, e.store, nil, slog.Default())
		t.Cleanup(func() { _ = enf.Close() })
		e.SetEnforcer(enf)

		landed := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		st.hookSet(func(key string) {
			if key != BlockKey(ip) {
				return
			}
			once.Do(func() {
				close(landed)
				<-release
			})
		})
		done := make(chan error, 1)
		go func() { done <- e.board.Block(ctx, ip, "threshold:old", time.Minute, time.Hour) }()
		<-landed

		reset, err := e.UnblockIP(ctx, ip, true)
		if err != nil {
			t.Fatal(err)
		}
		if reset.Incomplete {
			t.Fatal("healthy unblock reported incomplete")
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if blockedNow(t, e, ip) {
			t.Fatal("store block survived the final unblock commit")
		}
		if got := offensesNow(t, e, ip); got != 0 {
			t.Fatalf("offenses = %d after reset, want 0", got)
		}
		if _, ok := enf.Lookup(ip); ok {
			t.Fatal("late block notification re-added the IP to the mirror")
		}
	})

	t.Run("newer block wins after commit", func(t *testing.T) {
		e, st := hookedEngine(t, false)
		const ip = "198.51.100.77"
		enf := enforce.New(enforce.Config{
			Mode: enforce.ModeAuthoritative, ReconcileInterval: time.Hour, MaxEntries: 128,
		}, e.store, nil, slog.Default())
		t.Cleanup(func() { _ = enf.Close() })
		e.SetEnforcer(enf)

		landed := make(chan struct{})
		release := make(chan struct{})
		var mu sync.Mutex
		first := true
		st.hookSet(func(key string) {
			if key != BlockKey(ip) {
				return
			}
			mu.Lock()
			gate := first
			first = false
			mu.Unlock()
			if gate {
				close(landed)
				<-release
			}
		})
		oldDone := make(chan error, 1)
		go func() { oldDone <- e.board.Block(ctx, ip, "threshold:old", time.Hour, 4*time.Hour) }()
		<-landed
		if err := e.board.Block(ctx, ip, "threshold:new", time.Minute, 4*time.Hour); err != nil {
			t.Fatal(err)
		}
		close(release)
		if err := <-oldDone; err != nil {
			t.Fatal(err)
		}

		reason, blocked, err := e.BlockStatus(ctx, ip)
		if err != nil || !blocked || reason != "threshold:new" {
			t.Fatalf("store block = %q %v %v, want threshold:new true nil", reason, blocked, err)
		}
		if reason, ok := enf.Lookup(ip); !ok || reason != "threshold:new" {
			t.Fatalf("mirror block = %q %v, want threshold:new true", reason, ok)
		}
		if got := offensesNow(t, e, ip); got != 2 {
			t.Fatalf("offenses = %d, want 2 committed blocks", got)
		}
	})
}

// TestStaleWriterCannotTouchANewerBlock: the writer that settles a raced block
// is by definition working from an old view, so "delete block:<ip>" is not the
// operation it wants. By the time it gets there the key can hold an operator's
// manual block placed after the unblock, which the docs promise takes effect
// immediately. It must neither overwrite that block on the way in nor delete
// it while cleaning up after itself.
func TestStaleWriterCannotTouchANewerBlock(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, false)
	const ip = "198.51.100.72"

	e.board.unblockHold = 20 * time.Millisecond // waited out inside the test

	admitted, release := gateBlockWrite(t, st, BlockKey(ip))
	done := make(chan error, 1)
	go func() { done <- e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour) }()
	<-admitted

	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * e.board.unblockHold) // the window an admin block never waited for anyway
	const manual = "operator changed their mind"
	if err := e.BlockIP(ctx, ip, manual, time.Hour); err != nil {
		t.Fatal(err)
	}

	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	reason, blocked, err := e.BlockStatus(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("a stale writer deleted the operator's block while withdrawing its own")
	}
	if reason != manual {
		t.Fatalf("block reason = %q, want %q: a stale writer overwrote the operator's block", reason, manual)
	}
}

// hookedStore intercepts Delete so a test can inject traffic into the exact
// instant an unblock is mid-reset, or make one prefix's deletes fail. The
// before-hooks stop a writer short of the store call itself, which is how a
// writer admitted before an unblock is held past it.
type hookedStore struct {
	store.Store
	mu         sync.Mutex
	onDelete   func(key string)
	onSet      func(key string)
	beforeSet  func(key string)
	beforeIncr func(key string)
	failDel    func(key string) error
}

func (h *hookedStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	h.mu.Lock()
	before := h.beforeSet
	h.mu.Unlock()
	if before != nil {
		before(key)
	}
	err := h.Store.Set(ctx, key, value, ttl)
	h.mu.Lock()
	hook := h.onSet
	h.mu.Unlock()
	if hook != nil {
		hook(key)
	}
	return err
}

// CompareAndSwap carries the same hooks as Set: a block write is a fenced
// write now, and the tests that gate or observe "the block landing" mean this.
func (h *hookedStore) CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	h.mu.Lock()
	before := h.beforeSet
	h.mu.Unlock()
	if before != nil {
		before(key)
	}
	swapped, err := h.Store.CompareAndSwap(ctx, key, old, new, ttl)
	h.mu.Lock()
	hook := h.onSet
	h.mu.Unlock()
	if hook != nil {
		hook(key)
	}
	return swapped, err
}

func (h *hookedStore) CommitBlock(ctx context.Context, commit store.BlockCommit) (store.BlockCommitResult, error) {
	h.mu.Lock()
	beforeSet, beforeIncr := h.beforeSet, h.beforeIncr
	h.mu.Unlock()
	if beforeSet != nil {
		beforeSet(commit.BlockKey)
	}
	if beforeIncr != nil {
		beforeIncr(commit.CounterKey)
	}
	out, err := h.Store.CommitBlock(ctx, commit)
	h.mu.Lock()
	hook := h.onSet
	h.mu.Unlock()
	if hook != nil && out.Committed {
		hook(commit.BlockKey)
	}
	return out, err
}

func (h *hookedStore) CommitEvent(ctx context.Context, commit store.EventCommit) (store.EventCommitResult, error) {
	h.mu.Lock()
	before := h.beforeIncr
	h.mu.Unlock()
	if before != nil {
		before(commit.CounterKey)
	}
	return h.Store.CommitEvent(ctx, commit)
}

func (h *hookedStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	h.mu.Lock()
	before := h.beforeIncr
	h.mu.Unlock()
	if before != nil {
		before(key)
	}
	return h.Store.Incr(ctx, key, ttl)
}

func (h *hookedStore) hookSet(f func(key string)) {
	h.mu.Lock()
	h.onSet = f
	h.mu.Unlock()
}

func (h *hookedStore) hookBeforeSet(f func(key string)) {
	h.mu.Lock()
	h.beforeSet = f
	h.mu.Unlock()
}

func (h *hookedStore) hookBeforeIncr(f func(key string)) {
	h.mu.Lock()
	h.beforeIncr = f
	h.mu.Unlock()
}

func (h *hookedStore) Delete(ctx context.Context, key string) error {
	h.mu.Lock()
	hook, fail := h.onDelete, h.failDel
	h.mu.Unlock()
	if fail != nil {
		if err := fail(key); err != nil {
			return err
		}
	}
	err := h.Store.Delete(ctx, key)
	if hook != nil {
		hook(key)
	}
	return err
}

func (h *hookedStore) hook(f func(key string)) {
	h.mu.Lock()
	h.onDelete = f
	h.mu.Unlock()
}

func (h *hookedStore) failDeletes(f func(key string) error) {
	h.mu.Lock()
	h.failDel = f
	h.mu.Unlock()
}

func hookedEngine(t *testing.T, withPoW bool) (*Engine, *hookedStore) {
	t.Helper()
	cfg := loadTestConfig(t, unblockYAML)
	mem := store.NewMemory()
	t.Cleanup(func() { mem.Close() })
	st := &hookedStore{Store: mem}
	var mgr *pow.Manager
	if withPoW {
		key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
		if err != nil {
			t.Fatal(err)
		}
		mgr = pow.NewManager(key, st)
	}
	e, err := NewEngine(cfg, st, mgr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, st
}

// TestUnblockOutlivesAConcurrentBlock covers the window an unblock opens
// against live traffic. The reset is several store round trips; while it runs,
// a request can be scored and place a fresh block. Whatever order those land
// in, the IP must end up unblocked, because that is what the response claims.
func TestUnblockOutlivesAConcurrentBlock(t *testing.T) {
	ctx := context.Background()

	// Case 1: the event lands while the counters are being cleared. This is
	// the one that used to escape: with the block deleted first, the still
	// saturated counter placed a new (doubled) block that the rest of the
	// reset knew nothing about, and DELETE reported blocked:false on a
	// blocked IP.
	t.Run("during the counter reset", func(t *testing.T) {
		e, st := hookedEngine(t, false)
		const ip = "198.51.100.60"
		for range 3 {
			e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
		}
		if !blockedNow(t, e, ip) {
			t.Fatal("setup: the IP should be blocked")
		}
		var once sync.Once
		st.hook(func(key string) {
			if !strings.HasPrefix(key, "ev:") {
				return
			}
			once.Do(func() {
				st.hook(nil) // the injected event must not re-enter the hook
				e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "raced the reset")
			})
		})
		reset, err := e.UnblockIP(ctx, ip, true)
		if err != nil {
			t.Fatal(err)
		}
		if blockedNow(t, e, ip) {
			t.Fatal("still blocked after the unblock returned")
		}
		if reset.Incomplete {
			t.Error("the reset absorbed the race but reported incomplete")
		}
	})

	// Case 2: a block lands after the lift anyway. The reset window stops every
	// writer that checks it, so this stands in for the one schedule it cannot
	// cover: a writer stalled longer than unblockGuardTTL between its checks,
	// whose write therefore arrives unguarded. Only the verification pass is
	// left to catch that, and it is why the reset is a convergence protocol
	// rather than a claim of atomicity.
	t.Run("after the block was lifted", func(t *testing.T) {
		e, st := hookedEngine(t, false)
		const ip = "198.51.100.61"
		for range 3 {
			e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
		}
		var once sync.Once
		st.hook(func(key string) {
			if key != BlockKey(ip) {
				return
			}
			once.Do(func() {
				st.hook(nil)
				// Written straight to the store, past both guard checks.
				if err := e.store.Set(ctx, BlockKey(ip), []byte("threshold:pow_fail"), time.Hour); err != nil {
					t.Error(err)
				}
			})
		})
		reset, err := e.UnblockIP(ctx, ip, true)
		if err != nil {
			t.Fatal(err)
		}
		if blockedNow(t, e, ip) {
			t.Fatal("a block placed after the lift survived the unblock")
		}
		if reset.Incomplete {
			t.Error("the verification pass cleared it but reported incomplete")
		}
	})
}

// TestUnblockReportsAFailedEscalationReset: the escalation counter is fronted
// by a write-behind cache, so clearing it locally says nothing about the
// shared copy. A shared delete that fails leaves the count to be merged back
// over the reset on the next flush, and the response must not have called that
// a cleared counter.
func TestUnblockReportsAFailedEscalationReset(t *testing.T) {
	ctx := context.Background()
	e, st := hookedEngine(t, true)
	const ip = "198.51.100.63"

	e.recent.add(RecentDecision{Time: time.Now(), Host: "x.test", IP: ip, Action: "challenge"})
	e.pow.BumpEscalation(ctx, "x.test", ip, time.Minute)
	e.pow.BumpFrameEscalation(ctx, "x.test", ip, time.Minute)
	if err := e.board.Block(ctx, ip, "threshold:challenge_farm", time.Minute, time.Hour); err != nil {
		t.Fatal(err)
	}

	errDown := errors.New("store down")
	st.failDeletes(func(key string) error {
		// Both escalation key spaces: the ordinary counter and the framed one
		// an unblock clears alongside it.
		if strings.HasPrefix(key, "chesc:") || strings.HasPrefix(key, "chfesc:") {
			return errDown
		}
		return nil
	})
	reset, err := e.UnblockIP(ctx, ip, true)
	if err != nil {
		t.Fatalf("a failed counter reset must not fail the unblock itself: %v", err)
	}
	if !reset.Incomplete {
		t.Error("a failed shared escalation delete was reported as a complete reset")
	}
	if reset.EscalationKeys != 0 {
		t.Errorf("escalation_keys = %d, want 0: nothing was actually cleared", reset.EscalationKeys)
	}
	// The block is still lifted: the operator's primary intent does not hinge
	// on a counter the daemon could not reach.
	if blockedNow(t, e, ip) {
		t.Error("the block survived an unblock that only failed to clear a counter")
	}
}

// TestUnblockClearsTheLeadingPeersBucket: buckets are absolute time slices, so
// an instance whose clock runs ahead of this one is already writing the next
// bucket, possibly all the way to the threshold. Clearing only the live and
// previous buckets leaves that one to re-block the IP the moment this
// process's clock reaches it.
func TestUnblockClearsTheLeadingPeersBucket(t *testing.T) {
	ctx := context.Background()
	e := unblockEngine(t)
	const ip = "198.51.100.62"
	const window = time.Minute // defaults: pow_fail 3/min

	// Stand in for the leading peer: fill the next bucket to the threshold.
	next := eventBucket(time.Now(), window) + 1
	for range 3 {
		if _, err := e.store.Incr(ctx, eventKey(EventPoWFail, ip, "", next), 2*window); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}

	// Advance into the peer's bucket and score once.
	e.board.now = func() time.Time { return time.Now().Add(window) }
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "first event of the new bucket")
	if blockedNow(t, e, ip) {
		t.Fatal("one event in the next bucket re-blocked the IP: the leading peer's counter survived the reset")
	}
}

// TestUnblockKeepsBackoffWhenAsked: the opt-out keeps the repeat-offender
// ladder for an IP being given another chance, while still clearing the event
// counters, since leaving those is the bug rather than a policy choice.
func TestUnblockKeepsBackoffWhenAsked(t *testing.T) {
	ctx := context.Background()
	e := unblockEngine(t)
	const ip = "198.51.100.45"

	for range 3 {
		e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	}
	reset, err := e.UnblockIP(ctx, ip, false)
	if err != nil {
		t.Fatal(err)
	}
	if reset.BackoffReset {
		t.Fatal("backoff was reset despite resetBackoff=false")
	}
	if got := offensesNow(t, e, ip); got != 1 {
		t.Fatalf("offenses = %d, want the history kept at 1", got)
	}
	e.ReportEvent(ctx, "x.test", ip, EventPoWFail, "bad nonce")
	if blockedNow(t, e, ip) {
		t.Fatal("the event counters must be cleared whatever resetBackoff says")
	}
}

// TestBehaviourWindows: the reset rebuilds ev: keys from the config, so every
// scope that can write one has to be represented (defaults, domains and
// paths: overlays alike), with "off" thresholds skipped since they never write.
func TestBehaviourWindows(t *testing.T) {
	cfg := loadTestConfig(t, unblockYAML)
	got := cfg.BehaviourWindows()

	want := map[BehaviourWindow]bool{
		{Event: "pow_fail", Window: time.Minute}: true, // defaults
		{Event: "pow_fail", Window: time.Hour}:   true, // slow.test
		{Event: "pow_fail", Window: time.Second}: true, // slow.test /api/
	}
	for _, w := range got {
		if w.Event == "rule_match" {
			t.Fatalf("an \"off\" threshold produced a window: %+v", w)
		}
		if !want[w] {
			continue // built-in defaults (tamper, bot_spoof, …) are fine
		}
		delete(want, w)
	}
	for w := range want {
		t.Errorf("missing window %+v", w)
	}

	// Deduped and sorted, so a log line or a truncated reset reads the same twice.
	for i := 1; i < len(got); i++ {
		if got[i-1].Event > got[i].Event ||
			(got[i-1].Event == got[i].Event && got[i-1].Window >= got[i].Window) {
			t.Fatalf("windows are not sorted and deduped: %+v then %+v", got[i-1], got[i])
		}
	}
}

// TestEscalationHosts: the chesc: keys to clear are rebuilt from the hosts
// this IP was actually acted on plus the configured vhosts, deduped through
// the same normalization the challenge path keys them with.
func TestEscalationHosts(t *testing.T) {
	e := unblockEngine(t)
	const ip = "198.51.100.46"

	// Ring hosts, including a host that is not configured at all and two
	// textual forms of one host.
	for _, host := range []string{"Shop.Example:443", "shop.example.", "slow.test"} {
		e.recent.add(RecentDecision{Time: time.Now(), Host: host, IP: ip, Action: "challenge"})
	}
	e.recent.add(RecentDecision{Time: time.Now(), Host: "other.test", IP: "198.51.100.47"})
	// A dual-stack listener records the same client in its IPv4-mapped form.
	e.recent.add(RecentDecision{Time: time.Now(), Host: "mapped.test", IP: "::ffff:" + ip})

	hosts, truncated := e.escalationHosts(e.Config(), ip)
	if truncated {
		t.Fatal("a handful of hosts hit the truncation cap")
	}
	seen := map[string]int{}
	for _, h := range hosts {
		seen[h]++
	}
	for _, want := range []string{"shop.example", "slow.test", "mapped.test"} {
		if seen[want] != 1 {
			t.Errorf("host %q appears %d times, want exactly 1", want, seen[want])
		}
	}
	if seen["other.test"] != 0 {
		t.Error("another IP's host leaked into the reset set")
	}
}

// TestEscalationHostsCapped: a config with more vhosts than one unblock clears
// must report the truncation rather than silently leaving counters behind.
func TestEscalationHostsCapped(t *testing.T) {
	e := unblockEngine(t)
	const ip = "198.51.100.48"
	for i := range maxEscalationResetHosts + 10 {
		e.recent.add(RecentDecision{
			Time: time.Now(), IP: ip,
			Host: "h" + strconv.Itoa(i) + ".test",
		})
	}
	hosts, truncated := e.escalationHosts(e.Config(), ip)
	if !truncated {
		t.Fatal("truncation not reported")
	}
	if len(hosts) != maxEscalationResetHosts {
		t.Fatalf("cleared %d hosts, want the cap of %d", len(hosts), maxEscalationResetHosts)
	}
}
