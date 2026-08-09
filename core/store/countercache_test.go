// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

func TestCounterCacheRemovesDirtyEntryAfterFlushOutcomes(t *testing.T) {
	for _, name := range []string{"success", "failure"} {
		t.Run(name, func(t *testing.T) {
			var st Store = failingStore{}
			if name == "success" {
				memory := NewMemory()
				t.Cleanup(func() { memory.Close() })
				st = memory
			}
			c := NewCounterCache(st)
			c.Go = func(f func()) { f() }
			if got := c.Incr("flush-outcome", time.Minute); got != 1 {
				t.Fatalf("Incr = %d, want 1", got)
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if len(c.dirty) != 0 {
				t.Fatalf("dirty entries = %d, want 0", len(c.dirty))
			}
		})
	}
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

// TestCounterCacheForgetSync clears both copies like Forget, and, unlike
// Forget, reports whether the shared delete landed. An operator reset that
// only queued the delete could be told the counter was cleared while the
// shared total survived for the next flush to merge back over it.
func TestCounterCacheForgetSync(t *testing.T) {
	ctx := context.Background()
	c, st := inlineCounterCache(t)

	c.Incr("k", time.Minute)
	c.Incr("k", time.Minute)
	if err := c.ForgetSync(ctx, "k"); err != nil {
		t.Fatalf("ForgetSync against a healthy store: %v", err)
	}
	if _, ok, _ := st.Get(ctx, "k"); ok {
		t.Fatal("store counter survived ForgetSync")
	}
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after ForgetSync = %d, want 1", n)
	}

	// A store that cannot delete must say so rather than reporting a clean
	// reset: Forget's queued delete is the path that swallowed this.
	down := NewCounterCache(failingStore{})
	down.Go = func(f func()) { f() }
	down.Incr("k", time.Minute)
	if err := down.ForgetSync(ctx, "k"); !errors.Is(err, errStoreDown) {
		t.Fatalf("ForgetSync with the store down = %v, want %v", err, errStoreDown)
	}
	// The local counter still resets: the caller decides what to do about the
	// shared one, and local enforcement should not stay stuck at the ceiling.
	if n := down.Incr("k", time.Minute); n != 1 {
		t.Fatalf("local bump after a failed ForgetSync = %d, want 1", n)
	}
}

// TestForgetSyncReportsUnclearableSketchState: a key shed into the overload
// sketch cannot be reset per key (cells are shared, so zeroing one would zero
// other live keys). ForgetSync must say so instead of returning nil while the
// local count stays pinned, because an operator reset is most likely to be
// needed in exactly the overload conditions that put keys there.
func TestForgetSyncReportsUnclearableSketchState(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	t.Cleanup(func() { mem.Close() })
	c := NewCounterCache(mem)
	c.Go = func(f func()) { f() }
	base := time.Now()
	c.now = func() time.Time { return base }

	// Fill the exact cache so a previously unseen key is shed to the sketch.
	c.mu.Lock()
	for i := range maxCounterEntries {
		key := fmt.Sprintf("protected-%d", i)
		c.m[key] = counterEntry{n: 1, expires: base.Add(time.Minute).UnixNano(), pending: 1}
	}
	c.mu.Unlock()

	const key = "chesc:example.com:198.51.100.9"
	for i := range 10 {
		if n := c.Incr(key, time.Minute); n != int64(i+1) {
			t.Fatalf("sketch count %d = %d", i+1, n)
		}
	}

	err := c.ForgetSync(ctx, key)
	if !errors.Is(err, ErrForgetIncomplete) {
		t.Fatalf("ForgetSync on a shed key = %v, want ErrForgetIncomplete", err)
	}
	// The report is the point: the count really does survive, so a caller that
	// took nil for an answer would have told an operator it was cleared.
	if n := c.Incr(key, time.Minute); n == 1 {
		t.Fatal("sketch state was cleared after all; the error is now wrong rather than conservative")
	}

	// A key the sketch never saw resets cleanly, so the signal is not just
	// "always incomplete once the sketch has anything in it".
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
	if err := c.ForgetSync(ctx, "chesc:example.com:203.0.113.77"); err != nil {
		t.Fatalf("ForgetSync on a key that was never shed = %v, want nil", err)
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
func (failingStore) IncrByDeadline(context.Context, string, int64, int64) (int64, bool, error) {
	return 0, false, errStoreDown
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

// Flush must not claim success when the store is down: the queue drains
// (every round fails and parks its delta back locally), yet nothing was
// pushed, and shutdown should log that instead of reporting a clean flush.
func TestCounterCacheFlushReportsUnpushedDeltas(t *testing.T) {
	c := NewCounterCache(failingStore{})
	c.Go = func(f func()) { f() }
	c.Incr("k", time.Minute)
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("flush with the store down returned nil; the delta was silently dropped")
	}
}

type failOnceStore struct {
	Store
	failed atomic.Bool
}

func (s *failOnceStore) IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (int64, bool, error) {
	if s.failed.CompareAndSwap(false, true) {
		return 0, false, errStoreDown
	}
	return s.Store.IncrByDeadline(ctx, key, delta, deadline)
}

func TestCounterCacheRetriesCompleteDeltaAfterStoreRecovery(t *testing.T) {
	mem := NewMemory()
	t.Cleanup(func() { mem.Close() })
	c := NewCounterCache(&failOnceStore{Store: mem})
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	for range 5 {
		c.Incr("k", time.Minute)
	}
	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers, want 1", len(pending))
	}
	pending[0]() // first store round fails; all five increments stay pending

	pending = nil
	c.Incr("k", time.Minute)
	if len(pending) != 1 {
		t.Fatalf("recovery scheduled %d drainers, want 1", len(pending))
	}
	pending[0]()
	v, ok, err := mem.Get(context.Background(), "k")
	if err != nil || !ok || string(v) != "6" {
		t.Fatalf("store total after recovery = %q (ok=%v err=%v), want 6", v, ok, err)
	}
}

func TestCounterCacheQueueOverflowDeltaIsRecovered(t *testing.T) {
	mem := NewMemory()
	t.Cleanup(func() { mem.Close() })
	c := NewCounterCache(mem)
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	// Simulate a saturated backlog without creating thousands of unrelated
	// store records. The key cannot enter dirty yet, so its delta must remain
	// attached to the local counter.
	c.mu.Lock()
	c.queue = make([]string, maxFlushQueue)
	c.workers = maxFlushWorkers
	c.mu.Unlock()
	for range 5 {
		c.Incr("overflow", time.Minute)
	}
	c.mu.Lock()
	if got := c.m["overflow"].pending; got != 5 {
		c.mu.Unlock()
		t.Fatalf("overflow pending delta = %d, want 5", got)
	}
	c.queue = nil
	c.workers = 0
	c.mu.Unlock()

	c.Incr("overflow", time.Minute)
	if len(pending) != 1 {
		t.Fatalf("recovery scheduled %d drainers, want 1", len(pending))
	}
	pending[0]()
	v, ok, err := mem.Get(context.Background(), "overflow")
	if err != nil || !ok || string(v) != "6" {
		t.Fatalf("store total after queue recovery = %q (ok=%v err=%v), want 6", v, ok, err)
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

// quiesced reports whether the cache has no pending work: nothing dirty, an
// empty queue, and no live drain workers. Used to wait for all background
// flushes to land before asserting the shared store total.
func (c *CounterCache) quiesced() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.dirty) == 0 && len(c.queue) == 0 && c.workers == 0
}

// TestCounterCachePropertyLossless is the property test for the coalescing and
// flush machinery. Many goroutines hammer a small set of hot keys, each with a
// long (non-expiring) window; once all background flushes have drained, every
// event a client counted must be present in the shared store: the store total
// for each key equals the number of Incr calls against it (N events must not
// collapse to 1 in the shared store).
//
// Note it does NOT assert cross-goroutine monotonicity of the values Incr
// returns: a flush that merges the shared total raises the local count, so a
// concurrent Incr operating on the pre-merge value can legitimately return a
// smaller number. The counter is not linearizable across goroutines and never
// claimed to be; the local merge's own monotonicity is covered by
// TestCounterCacheMonotonicMerge.
func TestCounterCachePropertyLossless(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	const (
		goroutines   = 12
		perGoroutine = 500
		keys         = 4
	)
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for i := range perGoroutine {
				c.Incr(fmt.Sprintf("k%d", (g+i)%keys), time.Hour) // long window: no expiry mid-test
			}
		})
	}
	wg.Wait()

	// Wait for every background flush to land.
	waitFor(t, c.quiesced)

	// Exactly goroutines*perGoroutine increments happened, distributed across
	// the keys. Recompute the per-key expected counts and compare to the store.
	expected := make(map[string]int64)
	for g := range goroutines {
		for i := range perGoroutine {
			expected[fmt.Sprintf("k%d", (g+i)%keys)]++
		}
	}
	var total int64
	for key, want := range expected {
		v, ok, err := st.Get(context.Background(), key)
		if err != nil || !ok {
			t.Fatalf("store missing hot key %s: ok=%v err=%v", key, ok, err)
		}
		got, _ := strconv.ParseInt(string(v), 10, 64)
		if got != want {
			t.Errorf("store total for %s = %d, want %d (events lost or double-counted)", key, got, want)
		}
		total += got
	}
	if total != goroutines*perGoroutine {
		t.Fatalf("store grand total = %d, want %d", total, int64(goroutines*perGoroutine))
	}
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

func (b *blockingStore) IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (int64, bool, error) {
	b.incrs.Add(1)
	if b.gate {
		<-b.release
	}
	return b.Store.IncrByDeadline(ctx, key, delta, deadline)
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

// TestCounterCacheCoalescesLosslessly: many rapid bumps of one key that
// coalesce before the flush runs must still reach the shared store as the full
// count, not a single event. The
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

// A queued old-window delta must not be relabelled with the deadline of the
// first bump in a fresh window. Only that fresh bump reaches the store.
func TestCounterCacheQueuedDeltaDoesNotCrossWindow(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)
	base := time.Now()
	c.now = func() time.Time { return base }

	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }
	if n := c.Incr("k", 20*time.Millisecond); n != 1 {
		t.Fatalf("old-window count = %d, want 1", n)
	}
	c.now = func() time.Time { return base.Add(40 * time.Millisecond) }
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("fresh-window count = %d, want 1", n)
	}
	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers, want 1", len(pending))
	}
	pending[0]()
	v, ok, err := st.Get(context.Background(), "k")
	if err != nil || !ok || string(v) != "1" {
		t.Fatalf("shared fresh-window count = %q ok=%v err=%v, want 1", v, ok, err)
	}
}

// Reaching the local map cap may evict clean cached totals, but it must retain
// a queue-overflowed hot key whose pending delta exists nowhere else.
func TestCounterCacheCapacityPreservesOverflowPending(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)
	base := time.Now()
	c.now = func() time.Time { return base }
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	c.mu.Lock()
	c.queue = make([]string, maxFlushQueue)
	c.workers = maxFlushWorkers
	c.mu.Unlock()
	for range 5 {
		c.Incr("hot", time.Minute)
	}

	// Fill the remaining cache with clean entries, then insert one more key to
	// exercise the capacity path. Only clean entries may be reclaimed.
	c.mu.Lock()
	for i := len(c.m); i < maxCounterEntries; i++ {
		c.m[fmt.Sprintf("clean-%d", i)] = counterEntry{n: 1, expires: base.Add(time.Minute).UnixNano()}
	}
	c.mu.Unlock()
	c.Incr("trigger", time.Minute)
	if n := c.Incr("hot", time.Minute); n != 6 {
		t.Fatalf("hot count after capacity trim = %d, want 6", n)
	}

	c.mu.Lock()
	c.queue = nil
	c.workers = 0
	c.mu.Unlock()
	if n := c.Incr("hot", time.Minute); n != 7 {
		t.Fatalf("hot count while retrying = %d, want 7", n)
	}
	if len(pending) == 0 {
		t.Fatal("pending hot delta did not schedule a recovery drainer")
	}
	for _, f := range pending {
		f()
	}
	v, ok, err := st.Get(context.Background(), "hot")
	if err != nil || !ok || string(v) != "7" {
		t.Fatalf("shared hot count = %q ok=%v err=%v, want 7", v, ok, err)
	}
}

// If every primary slot owns unpushed work, a new key is counted in the
// bounded overload sketch. It must keep increasing rather than fail open by
// returning the first-event count forever.
func TestCounterCacheProtectedCapacityCountsUnseenKey(t *testing.T) {
	c := NewCounterCache(failingStore{})
	base := time.Now()
	c.now = func() time.Time { return base }

	c.mu.Lock()
	for i := 0; i < maxCounterEntries; i++ {
		key := fmt.Sprintf("protected-%d", i)
		c.m[key] = counterEntry{n: 1, expires: base.Add(time.Minute).UnixNano(), pending: 1}
	}
	c.mu.Unlock()

	if n := c.Incr("new-attacker", time.Minute); n != 1 {
		t.Fatalf("first overflow count = %d, want 1", n)
	}
	if n := c.Incr("new-attacker", time.Minute); n != 2 {
		t.Fatalf("second overflow count = %d, want 2", n)
	}
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	if n := c.Incr("new-attacker", time.Minute); n != 1 {
		t.Fatalf("overflow count after expiry = %d, want 1", n)
	}
}

// A rotating-key flood during a store outage fills every slot with protected
// (pending-carrying) entries. Once their windows expire they must become
// reclaimable — the pending delta is unpushable anyway — or every future
// unseen key would be counted only by the overflow sketch until restart.
func TestCounterCacheReclaimsExpiredProtectedEntries(t *testing.T) {
	c := NewCounterCache(failingStore{})
	base := time.Now()
	c.now = func() time.Time { return base }

	c.mu.Lock()
	for i := 0; i < maxCounterEntries; i++ {
		key := fmt.Sprintf("flood-%d", i)
		c.m[key] = counterEntry{n: 1, expires: base.Add(time.Minute).UnixNano(), pending: 1}
	}
	c.nextRoomSweep = base.Add(time.Second).UnixNano()
	c.mu.Unlock()

	// Inside the flood window, before the next paced sweep: shed to the sketch.
	if n := c.Incr("fresh", time.Minute); n != 1 {
		t.Fatalf("overflow count = %d, want 1", n)
	}
	c.mu.Lock()
	_, cached := c.m["fresh"]
	c.mu.Unlock()
	if cached {
		t.Fatal("fresh key must be shed while every slot is live-protected")
	}

	// After the windows lapse, the sweep reclaims the expired protected entries
	// and new keys get exact primary-cache counting again.
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	if n := c.Incr("fresh2", time.Minute); n != 1 {
		t.Fatalf("post-reclaim count = %d, want 1", n)
	}
	c.mu.Lock()
	_, cached = c.m["fresh2"]
	size := len(c.m)
	c.mu.Unlock()
	if !cached {
		t.Fatal("expired protected entries were not reclaimed for a new key")
	}
	if size >= maxCounterEntries {
		t.Errorf("cache size %d still at capacity after reclaim", size)
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
	// lower it. flushIncr is the merge seam; call it directly with the live
	// window's deadline so the identity check passes.
	c.Incr("k", time.Minute) // e.n = 1 locally
	c.Incr("k", time.Minute) // e.n = 2 locally
	dl := c.windowDeadline("k")

	dc := &drainCtx{now: c.now}
	defer dc.close()
	seq.next.Store(2)
	c.flushIncr(dc, "k", 2, dl) // shared=2 -> e.n stays 2
	seq.next.Store(1)
	c.flushIncr(dc, "k", 1, dl) // stale shared=1 -> must NOT lower e.n

	if n := c.Incr("k", time.Minute); n != 3 {
		t.Fatalf("bump after stale flush = %d, want 3 (monotonic merge)", n)
	}
}

// TestCounterCacheStaleFlushNotMergedIntoNewWindow: a flush that blocks past
// its window's deadline must not pollute a fresh window that started
// meanwhile, neither by merging its return
// value nor by leaving a stale record in the store for the follow-up flush to
// pick up. The first flush is parked in the store; a real 20ms window elapses;
// a fresh 1s window opens; the stale flush is released and (because it delegates
// to the real backend) must be made a no-op by the store's deadline check,
// leaving the fresh window at its own count.
//
// This uses real time, not a fake clock, because the store enforces the
// deadline against its own clock: the cache and store must agree on "now".
func TestCounterCacheStaleFlushNotMergedIntoNewWindow(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	gs := &gateStore{Store: st, gate: make(chan struct{})}
	c := NewCounterCache(gs)

	c.Incr("k", 20*time.Millisecond) // window1, local n=1; drainer parks in the store
	waitFor(t, func() bool { return gs.entered.Load() == 1 })

	time.Sleep(40 * time.Millisecond) // let window1's deadline pass
	if n := c.Incr("k", time.Second); n != 1 {
		t.Fatalf("fresh window bump = %d, want 1", n)
	}
	close(gs.gate) // release the stale flush: it delegates and must be a no-op

	// Give the drainer time to complete the stale round and any follow-up.
	waitFor(t, func() bool {
		v, ok, _ := st.Get(context.Background(), "k")
		return ok && string(v) == "1"
	})
	if n := c.Incr("k", time.Second); n != 2 {
		t.Fatalf("fresh window bump after stale flush = %d, want 2 (stale write must not leak in)", n)
	}
}

// TestCounterCacheForgetHeldThroughDelete: while a Forget's Delete is in
// flight, an Incr on the same key must not be
// flushed concurrently by a second worker, and the fresh increment must survive
// after the delete completes (the delete is applied first, then the increment).
func TestCounterCacheForgetHeldThroughDelete(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	gd := &gateDelStore{Store: st, gate: make(chan struct{})}
	c := NewCounterCache(gd)

	var spawned atomic.Int64
	c.Go = func(f func()) { spawned.Add(1); go f() }

	c.Forget("k") // drainer parks in Delete
	waitFor(t, func() bool { return gd.delEntered.Load() == 1 })

	// Bump the same key while the delete is in flight.
	c.Incr("k", time.Minute)
	time.Sleep(30 * time.Millisecond) // give a (wrongly) spawned worker time to act

	if got := spawned.Load(); got != 1 {
		t.Fatalf("spawned %d drainers, want 1 (delete must hold the key)", got)
	}
	if got := gd.incrEntered.Load(); got != 0 {
		t.Fatalf("%d concurrent IncrBy while delete in flight, want 0", got)
	}

	// Release the delete; the held increment is then applied as a follow-up.
	close(gd.gate)
	waitFor(t, func() bool {
		v, ok, _ := st.Get(context.Background(), "k")
		return ok && string(v) == "1"
	})
	v, ok, _ := st.Get(context.Background(), "k")
	if !ok || string(v) != "1" {
		t.Fatalf("after delete+incr, shared store k = %q ok=%v, want 1 (fresh incr must survive)", v, ok)
	}
}

// windowDeadline reads the current window's absolute deadline (expires) for a
// key, so a test can call flushIncr with a matching deadline.
func (c *CounterCache) windowDeadline(key string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[key].expires
}

// TestCounterCacheIncrsAfterForget: increments arriving after a Forget (its
// delete still pending) are not lost or under-counted. The delete runs first,
// then the two fresh increments land, so the shared store ends at 2.
func TestCounterCacheIncrsAfterForget(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	// Seed a shared value so the delete is observable.
	if _, err := st.Incr(context.Background(), "k", time.Minute); err != nil {
		t.Fatal(err)
	}

	// Capture drainers so the Forget and both Incrs fold into one entry before
	// any flush runs.
	var pending []func()
	c.Go = func(f func()) { pending = append(pending, f) }

	c.Forget("k")            // del=true, delta=0; schedules one drainer
	c.Incr("k", time.Minute) // fresh window, delta=1 (del still pending)
	c.Incr("k", time.Minute) // delta=2
	if len(pending) != 1 {
		t.Fatalf("scheduled %d drainers, want 1 (all ops fold into one entry)", len(pending))
	}
	pending[0]() // delete first, then push delta=2

	v, ok, _ := st.Get(context.Background(), "k")
	if !ok || string(v) != "2" {
		t.Fatalf("shared store after Forget+2 Incrs = %q ok=%v, want 2", v, ok)
	}
}

// waitFor spins until cond holds or a short deadline elapses.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met within deadline")
	}
}

// seqIncrStore returns a caller-controlled value from IncrBy, modeling
// out-of-order flush completion carrying arbitrary shared totals.
type seqIncrStore struct {
	Store
	next atomic.Int64
}

func (s *seqIncrStore) IncrByDeadline(context.Context, string, int64, int64) (int64, bool, error) {
	return s.next.Load(), true, nil
}

// gateStore blocks the FIRST IncrByDeadline until released, then delegates it
// (and all later calls) to the embedded real store. Blocking the first call
// past its deadline and then letting it delegate is exactly the stale-flush
// scenario: the real store must make that delayed write a no-op, and the
// fresh-window follow-up must not pick up any leaked total.
type gateStore struct {
	Store
	gate    chan struct{}
	entered atomic.Int64
}

func (g *gateStore) IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (int64, bool, error) {
	if g.entered.Add(1) == 1 {
		<-g.gate
	}
	return g.Store.IncrByDeadline(ctx, key, delta, deadline)
}

// gateDelStore blocks inside Delete until released and counts IncrByDeadline
// entries, so a test can prove the key is held (no concurrent flush) during a
// slow delete.
type gateDelStore struct {
	Store
	gate        chan struct{}
	delEntered  atomic.Int64
	incrEntered atomic.Int64
}

func (g *gateDelStore) Delete(ctx context.Context, key string) error {
	g.delEntered.Add(1)
	<-g.gate
	return g.Store.Delete(ctx, key)
}

func (g *gateDelStore) IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (int64, bool, error) {
	g.incrEntered.Add(1)
	return g.Store.IncrByDeadline(ctx, key, delta, deadline)
}

// TestCounterCacheFlushPushesParkedDeltas: Flush must push deltas that never
// made it into the dirty backlog (queue overflow parked them in the local
// pending slot), so a shutdown does not lose the last windows' counts.
func TestCounterCacheFlushPushesParkedDeltas(t *testing.T) {
	mem := NewMemory()
	t.Cleanup(func() { mem.Close() })
	c := NewCounterCache(mem)

	// Saturate the backlog so the key's delta stays parked locally.
	c.mu.Lock()
	c.queue = make([]string, maxFlushQueue)
	c.workers = maxFlushWorkers
	c.mu.Unlock()
	for range 5 {
		c.Incr("parked", time.Minute)
	}
	c.mu.Lock()
	if got := c.m["parked"].pending; got != 5 {
		c.mu.Unlock()
		t.Fatalf("parked pending delta = %d, want 5", got)
	}
	// Drop the synthetic backlog; nothing real was queued.
	c.queue = c.queue[:0]
	c.workers = 0
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	v, ok, err := mem.Get(context.Background(), "parked")
	if err != nil || !ok || string(v) != "5" {
		t.Fatalf("store total after Flush = %q (ok=%v err=%v), want 5", v, ok, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.m["parked"].pending; got != 0 {
		t.Fatalf("pending after Flush = %d, want 0", got)
	}
}

// TestCounterCacheFlushSkipsExpiredWindows: a parked delta whose window has
// already ended must not be pushed at shutdown (the store would start a fresh
// window for events that belong to a dead one).
func TestCounterCacheFlushSkipsExpiredWindows(t *testing.T) {
	mem := NewMemory()
	t.Cleanup(func() { mem.Close() })
	c := NewCounterCache(mem)
	base := time.Now()
	c.now = func() time.Time { return base }

	c.mu.Lock()
	c.queue = make([]string, maxFlushQueue)
	c.workers = maxFlushWorkers
	c.mu.Unlock()
	c.Incr("expired", time.Minute)
	c.mu.Lock()
	c.queue = c.queue[:0]
	c.workers = 0
	c.mu.Unlock()

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, ok, _ := mem.Get(context.Background(), "expired"); ok {
		t.Fatal("expired window must not be pushed by Flush")
	}
}

// TestCounterCacheFlushHonorsContext: a hung store must not wedge shutdown;
// Flush returns the context error once its deadline passes.
func TestCounterCacheFlushHonorsContext(t *testing.T) {
	bs := &blockingStore{Store: NewMemory(), release: make(chan struct{}), gate: true}
	t.Cleanup(func() { close(bs.release); bs.Store.Close() })
	c := NewCounterCache(bs)

	c.Incr("k", time.Minute) // spawns a drainer that parks in the store
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush on a hung store = %v, want DeadlineExceeded", err)
	}
}

// A sweep that succeeds by freeing a handful of slots must not license an
// immediate re-sweep: under a sustained new-key flood the drains free a few
// entries at a time, and re-sweeping on every success turned into a full-map
// scan under c.mu every few insertions (a measured 3x challenge-issuance
// collapse). Between paced sweeps, at-capacity keys go to the overflow sketch.
// TestCounterCacheRoomSweepIsPaced pins rule 1 of makeCounterRoomLocked: a
// sweep that freed slots must not license an immediate re-sweep. Regressing
// that is what collapsed challenge issuance 3x in 16091b3, and it is invisible
// to every other test here, because the cache still behaves correctly while
// doing it, just far too slowly. Deterministic, not timing-based: the clock is
// faked and the map is filled to exactly capacity.
func TestCounterCacheRoomSweepIsPaced(t *testing.T) {
	c := NewCounterCache(failingStore{})
	// Inline drains: the test reassigns c.now mid-flight, and a background
	// drain goroutine reading the clock would race that write.
	c.Go = func(f func()) { f() }
	base := time.Now()
	c.now = func() time.Time { return base }

	c.mu.Lock()
	for i := 0; i < maxCounterEntries; i++ {
		key := fmt.Sprintf("flood-%d", i)
		e := counterEntry{n: 1, expires: base.Add(time.Minute).UnixNano(), pending: 1}
		if i == 0 {
			e.pending = 0 // exactly one evictable slot for the first sweep
		}
		c.m[key] = e
	}
	c.mu.Unlock()

	// First at-capacity insert: the sweep runs (never paced before), frees the
	// one clean slot, and caches the key.
	if n := c.Incr("first", time.Minute); n != 1 {
		t.Fatalf("first count = %d, want 1", n)
	}
	c.mu.Lock()
	_, cached := c.m["first"]
	// Hand the next sweep another evictable slot, so only pacing can stop it.
	e := c.m["flood-1"]
	e.pending = 0
	c.m["flood-1"] = e
	c.mu.Unlock()
	if !cached {
		t.Fatal("first key was not cached from the freed slot")
	}

	// Same second, map full again, an evictable entry available: the re-sweep
	// must be paced out and the key shed to the sketch.
	if n := c.Incr("second", time.Minute); n != 1 {
		t.Fatalf("second count = %d, want 1", n)
	}
	c.mu.Lock()
	_, cached = c.m["second"]
	c.mu.Unlock()
	if cached {
		t.Fatal("a successful sweep licensed an immediate re-sweep; pacing is gone")
	}

	// Once the pacing window passes, the sweep runs again and reclaims.
	c.now = func() time.Time { return base.Add(2 * time.Second) }
	if n := c.Incr("third", time.Minute); n != 1 {
		t.Fatalf("third count = %d, want 1", n)
	}
	c.mu.Lock()
	_, cached = c.m["third"]
	c.mu.Unlock()
	if !cached {
		t.Fatal("paced sweep did not run after its window elapsed")
	}
}

// TestCounterCacheNonPositiveTTLStillCounts pins the backstop for a caller bug
// that used to disable the counter silently.
//
// With ttl <= 0 the entry's expiry landed on now, so every bump saw an expired
// window and opened a fresh one: the running total answered 1 forever and
// flushKey discarded every delta as belonging to a closed window. Nothing could
// ever cross a limit and nothing ever reached the store, which for a counter
// whose only job is enforcing a limit is the worst available failure.
func TestCounterCacheNonPositiveTTLStillCounts(t *testing.T) {
	ctx := context.Background()
	for _, ttl := range []time.Duration{0, -time.Second} {
		st := NewMemory()
		c := NewCounterCache(st)
		var last int64
		for range 5 {
			last = c.Incr("k", ttl)
		}
		if last != 5 {
			t.Errorf("ttl=%v: Incr returned %d after 5 bumps, want 5 (a counter stuck at 1 enforces nothing)", ttl, last)
		}
		if err := c.Flush(ctx); err != nil {
			t.Fatalf("ttl=%v: flush: %v", ttl, err)
		}
		v, ok, err := st.Get(ctx, "k")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || string(v) != "5" {
			t.Errorf("ttl=%v: store holds %q (present=%v), want 5: the shared counter never received the deltas", ttl, v, ok)
		}
		st.Close()
	}
}
