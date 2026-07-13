// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// inlineCounterCache runs flushes synchronously so the store state is
// deterministic within a test.
func inlineCounterCache(t *testing.T) (*CounterCache, Store) {
	t.Helper()
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)
	c.Go = func(f func()) { f() }
	return c, st
}

// TestCounterCacheCounts: sequential bumps return the running total and the
// store counter tracks it.
func TestCounterCacheCounts(t *testing.T) {
	c, st := inlineCounterCache(t)

	for i := int64(1); i <= 5; i++ {
		if n := c.Incr("k", time.Minute); n != i {
			t.Fatalf("bump %d returned %d", i, n)
		}
	}
	v, ok, err := st.Get(context.Background(), "k")
	if err != nil || !ok {
		t.Fatalf("store counter missing: ok=%v err=%v", ok, err)
	}
	if string(v) != "5" {
		t.Fatalf("store counter = %s, want 5", v)
	}
}

// TestCounterCacheExpiry: a bump after the entry's TTL restarts the count.
func TestCounterCacheExpiry(t *testing.T) {
	c, _ := inlineCounterCache(t)
	base := time.Now()
	c.now = func() time.Time { return base }

	c.Incr("k", time.Minute)
	c.Incr("k", time.Minute)

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after expiry = %d, want 1 (fresh window)", n)
	}
}

// TestCounterCacheAdoptsSharedTotal: the flush result overwrites the local
// count, so an instance converges on a counter other replicas advanced.
func TestCounterCacheAdoptsSharedTotal(t *testing.T) {
	c, st := inlineCounterCache(t)

	// Another replica already counted 5 events against this key.
	for range 5 {
		if _, err := st.Incr(context.Background(), "k", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	// Local bump returns the local view first, but the inline flush lands
	// the shared total (6), so the next bump continues from it.
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("first local bump = %d, want 1", n)
	}
	if n := c.Incr("k", time.Minute); n != 7 {
		t.Fatalf("bump after flush = %d, want 7 (shared total adopted)", n)
	}
}

// TestCounterCacheForget clears the counter locally and in the store.
func TestCounterCacheForget(t *testing.T) {
	c, st := inlineCounterCache(t)

	c.Incr("k", time.Minute)
	c.Incr("k", time.Minute)
	c.Forget("k")

	if _, ok, _ := st.Get(context.Background(), "k"); ok {
		t.Fatal("store counter survived Forget")
	}
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after Forget = %d, want 1", n)
	}
}

// failingStore errors on every op; the cache must keep counting locally.
type failingStore struct{ Store }

var errStoreDown = errors.New("store down")

func (failingStore) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errStoreDown
}
func (failingStore) IncrBy(context.Context, string, int64, time.Duration) (int64, error) {
	return 0, errStoreDown
}
func (failingStore) Delete(context.Context, string) error { return errStoreDown }

// TestCounterCacheStoreDown: a broken store degrades to per-instance
// counting instead of failing open.
func TestCounterCacheStoreDown(t *testing.T) {
	c := NewCounterCache(failingStore{})
	c.Go = func(f func()) { f() }

	for i := int64(1); i <= 3; i++ {
		if n := c.Incr("k", time.Minute); n != i {
			t.Fatalf("bump %d with store down returned %d", i, n)
		}
	}
	c.Forget("k")
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after Forget with store down = %d, want 1", n)
	}
}

// TestCounterCacheConcurrent exercises the mutex paths under the race
// detector with real background flushes.
func TestCounterCacheConcurrent(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				c.Incr("k", time.Minute)
			}
			c.Forget("k")
		})
	}
	wg.Wait()
}

// blockingStore lets a flush park inside Store.IncrBy until released, so a test
// can hold flush workers busy and observe how many the cache spawns and what
// delta each push carries.
type blockingStore struct {
	Store
	release chan struct{}
	incrs   atomic.Int64 // number of IncrBy calls
	gate    bool         // when true, block on release; else pass through
}

func (b *blockingStore) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	b.incrs.Add(1)
	if b.gate {
		<-b.release
	}
	return b.Store.IncrBy(ctx, key, delta, ttl)
}

// TestCounterCacheFlushWorkersBounded: a flood of distinct keys must not spawn
// an unbounded number of flush goroutines. With every flush parked in the
// store, live drain goroutines are capped at maxFlushWorkers regardless of how
// many keys are dirtied.
func TestCounterCacheFlushWorkersBounded(t *testing.T) {
	bs := &blockingStore{Store: NewMemory(), release: make(chan struct{}), gate: true}
	t.Cleanup(func() { close(bs.release); bs.Store.Close() })
	c := NewCounterCache(bs)

	var spawned atomic.Int64
	c.Go = func(f func()) {
		spawned.Add(1)
		go f()
	}

	// Dirty far more distinct keys than the worker cap; each flush blocks.
	for i := range 1000 {
		c.Incr(fmt.Sprintf("ip-%d", i), time.Minute)
	}

	// Wait for the drain goroutines to reach the parked store call, so the
	// in-flight count has settled at its ceiling before we assert.
	deadline := time.Now().Add(2 * time.Second)
	for bs.incrs.Load() < maxFlushWorkers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// The number of drain goroutines ever started must stay within the cap:
	// workers loop over the queue, they are not one-per-key. This is the
	// guarantee that a distinct-key flood cannot fan out unboundedly.
	if got := spawned.Load(); got > maxFlushWorkers {
		t.Fatalf("spawned %d drain goroutines, want <= %d (unbounded fan-out)", got, maxFlushWorkers)
	}
	// And at most maxFlushWorkers store calls are in flight at once; the rest
	// of the 1000 keys wait in the queue.
	if got := bs.incrs.Load(); got != maxFlushWorkers {
		t.Fatalf("store IncrBy in flight = %d, want exactly %d workers busy", got, maxFlushWorkers)
	}
}

// TestCounterCacheCoalescesLosslessly is the direct regression for the MR
// review: many rapid bumps of one key that coalesce before the flush runs must
// still reach the shared store as the full count, not a single event. The
// drainer is captured (not run), so all 50 bumps accumulate into one dirty
// entry; running the drainer once then pushes the whole delta of 50.
func TestCounterCacheCoalescesLosslessly(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	for range 50 {
		c.Incr("k", time.Minute)
	}
	// One drainer scheduled for the hot key; the 49 later bumps coalesced.
	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers, want 1 (bumps must coalesce)", len(pending))
	}
	pending[0]() // drain: pushes the full accumulated delta in one round

	v, ok, _ := st.Get(context.Background(), "k")
	if !ok || string(v) != "50" {
		t.Fatalf("shared store counter = %q (ok=%v), want 50 (no events lost)", v, ok)
	}
}

// TestCounterCacheSingleflight: while a key is being flushed, no second drainer
// flushes the same key concurrently. With one worker parked in the store, a
// fresh bump of the same key must not schedule another drainer or a second
// concurrent store round for it.
func TestCounterCacheSingleflight(t *testing.T) {
	bs := &blockingStore{Store: NewMemory(), release: make(chan struct{}), gate: true}
	t.Cleanup(func() { close(bs.release); bs.Store.Close() })
	c := NewCounterCache(bs)

	var spawned atomic.Int64
	c.Go = func(f func()) { spawned.Add(1); go f() }

	c.Incr("k", time.Minute) // schedules the one drainer; it parks in IncrBy
	deadline := time.Now().Add(time.Second)
	for bs.incrs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// Bump the same key while its flush is parked: must accumulate, not spawn.
	for range 5 {
		c.Incr("k", time.Minute)
	}
	time.Sleep(20 * time.Millisecond)
	if got := spawned.Load(); got != 1 {
		t.Fatalf("spawned %d drainers, want 1 (same key must not be flushed concurrently)", got)
	}
	if got := bs.incrs.Load(); got != 1 {
		t.Fatalf("concurrent store rounds for one key = %d, want 1 while first is in flight", got)
	}
}

// TestCounterCacheCoalescesInline: with the queue drained synchronously between
// bumps, a key already dirty-and-queued must not enqueue twice. Two bumps that
// both land while a flush is pending collapse to one scheduled drainer.
func TestCounterCacheCoalescesInline(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	// Capture drainers rather than run them, so both bumps happen while "k" is
	// still queued (not yet picked up by a drainer).
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	c.Incr("k", time.Minute) // queues "k", schedules one drainer
	c.Incr("k", time.Minute) // "k" already dirty -> coalesced, no new drainer

	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers for coalesced bumps, want 1", len(pending))
	}
}

// TestCounterCacheExpiredWindowNotFlushed: a bump whose window expired before
// its flush runs must not start a fresh store window. The counter is bumped,
// the clock advances past the deadline, then the drainer runs: it must skip the
// store push entirely, leaving no shared record.
func TestCounterCacheExpiredWindowNotFlushed(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)
	base := time.Now()
	c.now = func() time.Time { return base }

	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	c.Incr("k", time.Minute) // window ends at base+1m
	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers, want 1", len(pending))
	}
	// Advance past the window, then run the captured drainer.
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	pending[0]()

	if _, ok, _ := st.Get(context.Background(), "k"); ok {
		t.Fatal("expired-window bump was pushed to the store; it must be skipped")
	}
}

// TestCounterCacheMonotonicMerge: an out-of-order flush carrying a stale
// (smaller) shared total must never roll the local count backward. Two local
// bumps return 1 then 2; landing shared=2 then a late shared=1 must leave the
// next bump at 3, not 2.
func TestCounterCacheMonotonicMerge(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	seq := &seqIncrStore{}
	c.store = seq

	// Land shared=2 first (drives e.n to 2), then a stale shared=1 must not
	// lower it. flushIncr is the merge seam; call it directly with the values.
	c.Incr("k", time.Minute) // e.n = 1 locally
	c.Incr("k", time.Minute) // e.n = 2 locally

	seq.next.Store(2)
	c.flushIncr("k", 2, time.Minute) // shared=2 -> e.n stays 2
	seq.next.Store(1)
	c.flushIncr("k", 1, time.Minute) // stale shared=1 -> must NOT lower e.n

	if n := c.Incr("k", time.Minute); n != 3 {
		t.Fatalf("bump after stale flush = %d, want 3 (monotonic merge)", n)
	}
}

// seqIncrStore returns a caller-controlled value from IncrBy, modeling
// out-of-order flush completion carrying arbitrary shared totals.
type seqIncrStore struct {
	Store
	next atomic.Int64
}

func (s *seqIncrStore) IncrBy(context.Context, string, int64, time.Duration) (int64, error) {
	return s.next.Load(), nil
}
