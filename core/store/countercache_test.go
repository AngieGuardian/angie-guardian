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

// blockingStore lets a flush park inside Store.Incr until released, so a test
// can hold flush workers busy and observe how many the cache spawns.
type blockingStore struct {
	Store
	release chan struct{}
	incrs   atomic.Int64
}

func (b *blockingStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	b.incrs.Add(1)
	<-b.release
	return b.Store.Incr(ctx, key, ttl)
}

// TestCounterCacheFlushWorkersBounded: a flood of distinct keys must not spawn
// an unbounded number of flush goroutines. With every flush parked in the
// store, live drain goroutines are capped at maxFlushWorkers regardless of how
// many keys are dirtied.
func TestCounterCacheFlushWorkersBounded(t *testing.T) {
	bs := &blockingStore{Store: NewMemory(), release: make(chan struct{})}
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
	if got := bs.incrs.Load(); got > maxFlushWorkers {
		t.Fatalf("%d concurrent store Incrs, want <= %d", got, maxFlushWorkers)
	}
	if got := bs.incrs.Load(); got != maxFlushWorkers {
		t.Fatalf("store Incrs in flight = %d, want exactly %d workers busy", got, maxFlushWorkers)
	}
}

// TestCounterCacheCoalesces: many rapid bumps of one key do not each spawn
// their own store round. With flushes parked, the store calls for one hot key
// are bounded by the worker cap, not by the number of bumps: the 50 bumps here
// collapse to at most maxFlushWorkers in-flight rounds, and inline (below) to a
// single round while a flush holds the key.
func TestCounterCacheCoalesces(t *testing.T) {
	bs := &blockingStore{Store: NewMemory(), release: make(chan struct{})}
	t.Cleanup(func() { close(bs.release); bs.Store.Close() })
	c := NewCounterCache(bs)

	for range 50 {
		c.Incr("k", time.Minute)
	}
	deadline := time.Now().Add(time.Second)
	for bs.incrs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bs.incrs.Load(); got > maxFlushWorkers {
		t.Fatalf("store Incrs for one hot key = %d, want <= %d (bumps must coalesce)", got, maxFlushWorkers)
	}
}

// TestCounterCacheCoalescesInline: with the queue drained synchronously between
// bumps, a key already dirty-and-queued must not enqueue twice. Two bumps that
// both land while a flush is pending collapse to one store round.
func TestCounterCacheCoalescesInline(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	// Capture drainers rather than run them, so both bumps happen while "k" is
	// still queued (not yet picked up by a drainer).
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	c.Incr("k", time.Minute) // queues "k", schedules one drainer
	c.Incr("k", time.Minute) // "k" already queued -> coalesced, no new drainer

	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers for coalesced bumps, want 1", len(pending))
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

	// Capture flush drainers instead of running them, so we control completion
	// order. Each captured func drains one queued key against the seqStore.
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	seq := &seqIncrStore{Store: st}
	c.store = seq

	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump1 = %d, want 1", n)
	}
	if n := c.Incr("k", time.Minute); n != 2 {
		t.Fatalf("bump2 = %d, want 2", n)
	}

	// Land a stale shared=1 after a fresh shared=2. seqIncrStore returns an
	// increasing sequence, so we force the order by choosing what each drain
	// sees: run the drainer that will read 2, then inject a stale 1.
	if len(pending) == 0 {
		t.Fatal("no drainer scheduled")
	}
	seq.next.Store(2)
	pending[0]() // reads shared=2 -> e.n=2
	// Now a straggler flush from an earlier bump completes carrying shared=1.
	seq.next.Store(1)
	c.flush("k", dirtyEntry{ttl: time.Minute}) // reads shared=1, must NOT lower e.n

	if n := c.Incr("k", time.Minute); n != 3 {
		t.Fatalf("bump after stale flush = %d, want 3 (monotonic merge)", n)
	}
}

// seqIncrStore returns a caller-controlled value from Incr, modeling
// out-of-order flush completion carrying arbitrary shared totals.
type seqIncrStore struct {
	Store
	next atomic.Int64
}

func (s *seqIncrStore) Incr(context.Context, string, time.Duration) (int64, error) {
	return s.next.Load(), nil
}
