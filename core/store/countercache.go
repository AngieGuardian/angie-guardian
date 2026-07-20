// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"hash/maphash"
	"sync"
	"time"
)

// CounterCache fronts Store.Incr for the per-IP event counters on the
// challenge hot path (issuance rate limit, farming escalation). Counting
// through the store directly costs one blocking write round per counter per
// request; on a durable backend that write can include an fsync, so every extra
// counter visibly cuts challenge issuance throughput. Instead the count is bumped in
// an in-process map and returned immediately, and the shared store counter is
// synced in the background: a flush pushes the accumulated local increments to
// the store with IncrBy and merges the store's total back, so replicas
// converge on the shared count and a restarted instance catches back up on its
// first flush.
//
// Background work is bounded and lossless. A request never spawns a goroutine
// directly: it accumulates a pending delta on the key and, at most
// maxFlushWorkers drain goroutines push dirty keys to the store. Repeated bumps
// of one key coalesce into a single store round that carries the whole delta
// (not one round per bump, and not one event surviving out of many). A key
// already being flushed is not flushed a second time concurrently; bumps that
// arrive mid-flush accumulate and trigger exactly one follow-up flush. When the
// dirty backlog is full a key's pending delta stays local (unpushed) rather
// than being dropped, so the local count keeps enforcing.
//
// The trade-offs are deliberate. Enforcement is exact for a client served by a
// single instance and trails the cross-instance total only by the delta not
// yet pushed. When the store is unreachable, or the backlog is saturated, the
// local count keeps enforcing, which is tighter than failing open. The merge is
// monotonic within a live TTL window, so an out-of-order flush can never roll
// the local count backward. Each key carries the absolute deadline of its
// window: a flush whose window has already expired is skipped, and a live one
// pushes using only the remaining TTL so a backlogged event cannot extend the
// window. Forget is best-effort: a delete still pending when the key is
// re-bumped can race, bounded by the work in flight at that moment.
type CounterCache struct {
	store Store

	// Go starts a drain goroutine. Tests replace it to drain inline, making
	// the store state deterministic.
	Go func(func())

	mu      sync.Mutex
	m       map[string]counterEntry
	dirty   map[string]*dirtyEntry // keys with unpushed work
	queue   []string               // FIFO of dirty keys awaiting a drainer
	workers int                    // live drain goroutines, capped at maxFlushWorkers
	// capacityProtected means the last attempt to make room found that every
	// entry carried unpushed work. New, previously unseen keys are then left
	// uncached until a drainer releases an entry; existing hot keys keep their
	// exact local count and reconciliation state.
	capacityProtected bool
	// overflow is a bounded count-min sketch used only while every primary
	// cache entry is protected by unpushed work. It keeps repeat requests from
	// an unseen key counting upward instead of returning 1 forever. Hash
	// collisions can only over-count, which is the safer overload failure mode
	// for rate limiting.
	overflow      [overflowCounterDepth][]overflowCounterCell
	overflowSeeds [overflowCounterDepth]maphash.Seed

	now func() time.Time
}

type counterEntry struct {
	n       int64
	expires int64 // unix nanoseconds
	pending int64 // increments retained locally while no dirty slot is available
}

type overflowCounterCell struct {
	n       int64
	expires int64
}

// dirtyEntry is the unpushed shared-store work for a key. delta is the number
// of local increments not yet pushed; a flush pushes exactly delta via IncrBy
// and clears it. deadline is the absolute end of the counter's window (unix
// nanos): a flush uses the remaining TTL, skips an expired window, and merges
// the shared total back only into that same window. del marks a pending Forget
// (a Delete that supersedes any accumulated delta).
//
// A key has a single owning drainer for the whole time it has pending work. The
// ownership invariant: a key is in c.dirty from the first op until its work
// fully drains, and it is in c.queue only while waiting to be picked up. A
// drainer removes it from the queue when it claims it, and markDirtyLocked never
// re-enqueues a key already in c.dirty, so at most one drainer ever holds it.
// Ops arriving while it is owned fold into the entry (a bump raises delta; a
// Forget sets del) and are handled by the owner's follow-up round. This is the
// per-key singleflight guarantee, and it holds across both increment and delete
// store rounds.
type dirtyEntry struct {
	delta    int64
	deadline int64
	del      bool
}

// maxCounterEntries bounds the local counter map. At capacity, clean cached
// totals are reclaimed in bulk; entries with unapplied work are never evicted.
// If every slot is protected, previously unseen keys are left uncached until
// a drainer makes room.
const maxCounterEntries = 1 << 17

const (
	overflowCounterDepth = 4
	overflowCounterWidth = 1 << 14
)

// maxFlushWorkers caps how many drain goroutines flush the shared store
// counter concurrently. It bounds the goroutine and store-concurrency cost of
// a flood: past this, extra dirty keys wait in the queue.
const maxFlushWorkers = 8

// maxFlushQueue bounds the backlog of dirty keys awaiting a drainer. When it
// is full a new key's delta stays local (unpushed to the shared store) while
// the local count keeps enforcing; this is the overload valve that keeps memory
// bounded under a distributed new-key flood. Already-dirty keys keep
// accumulating regardless, so no counted event is lost for a key already queued.
const maxFlushQueue = 1 << 14

// flushTimeout bounds a single store round so a hung store cannot wedge a
// drain goroutine. The request that dirtied the key has long been answered.
const flushTimeout = 5 * time.Second

func NewCounterCache(st Store) *CounterCache {
	c := &CounterCache{
		store: st,
		Go:    func(f func()) { go f() },
		m:     make(map[string]counterEntry),
		dirty: make(map[string]*dirtyEntry),
		now:   time.Now,
	}
	for i := range c.overflow {
		c.overflow[i] = make([]overflowCounterCell, overflowCounterWidth)
		c.overflowSeeds[i] = maphash.MakeSeed()
	}
	return c
}

// Incr counts one event under key and returns the running total, without
// blocking on the store. TTL semantics match Store.Incr: the first bump of a
// missing or expired key starts at 1 with the given ttl, later bumps keep
// the original expiry.
func (c *CounterCache) Incr(key string, ttl time.Duration) int64 {
	now := c.now().UnixNano()

	c.mu.Lock()
	e, ok := c.m[key]
	if !ok || now >= e.expires {
		if ok {
			// Reuse the expired key's slot. Its pending delta belongs to the old
			// window and is deliberately discarded here.
			delete(c.m, key)
			c.capacityProtected = false
		} else if !c.makeCounterRoomLocked() {
			// Every cached entry owns unpushed work. Evicting any of them would
			// lose reconciliation state. Count this previously unseen key in the
			// bounded overload sketch so repeated requests still trip the limiter.
			n := c.incrOverflowLocked(key, now, ttl)
			c.mu.Unlock()
			return n
		}
		e = counterEntry{expires: now + ttl.Nanoseconds()}
	}
	e.n++
	n := e.n
	if _, dirty := c.dirty[key]; !dirty {
		// A queue-overflowed key has no dirty entry. Keep its complete unpushed
		// delta in the bounded local counter until a later bump can enqueue it.
		e.pending++
	}
	c.m[key] = e
	spawn := c.markDirtyLocked(key, e.expires, false)
	c.mu.Unlock()

	if spawn {
		c.Go(c.drain)
	}
	return n
}

// incrOverflowLocked increments a count-min sketch. Returning the minimum of
// independent rows ensures collisions never under-count a key. Under a hash
// collision, the cell keeps the later deadline; this can conservatively hold
// an overload count longer but cannot reset a live key's window early.
// c.mu must be held.
func (c *CounterCache) incrOverflowLocked(key string, now int64, ttl time.Duration) int64 {
	minimum := int64(^uint64(0) >> 1)
	for i := range c.overflow {
		idx := maphash.String(c.overflowSeeds[i], key) & (overflowCounterWidth - 1)
		cell := &c.overflow[i][idx]
		if cell.n == 0 || (cell.expires > 0 && now >= cell.expires) {
			cell.n = 0
			cell.expires = 0
		}
		if ttl > 0 {
			cell.expires = max(cell.expires, now+ttl.Nanoseconds())
		}
		if cell.n < int64(^uint64(0)>>1) {
			cell.n++
		}
		minimum = min(minimum, cell.n)
	}
	return minimum
}

// makeCounterRoomLocked preserves every entry that still owns unpushed work
// (either queued/in-flight in dirty, or retained in counterEntry.pending after
// queue saturation) and bulk-evicts only clean cache entries. Bulk eviction
// makes the O(n) scan rare instead of paying it for every new key at capacity.
// If all entries are protected, new keys are shed until releaseLocked marks
// that capacity may be reclaimed again. c.mu must be held.
func (c *CounterCache) makeCounterRoomLocked() bool {
	if len(c.m) < maxCounterEntries {
		return true
	}
	if c.capacityProtected {
		return false
	}
	for key, e := range c.m {
		if e.pending == 0 && c.dirty[key] == nil {
			delete(c.m, key)
		}
	}
	if len(c.m) < maxCounterEntries {
		return true
	}
	c.capacityProtected = true
	return false
}

// Forget clears the counter locally and, in the background, in the store.
func (c *CounterCache) Forget(key string) {
	c.mu.Lock()
	delete(c.m, key)
	c.capacityProtected = false
	spawn := c.markDirtyLocked(key, 0, true)
	c.mu.Unlock()

	if spawn {
		c.Go(c.drain)
	}
}

// markDirtyLocked records one unit of pending shared-store work for key (a
// counted increment, or a delete when del is true) and ensures a drainer will
// pick it up. It coalesces losslessly: a key already dirty folds its work into
// the existing entry rather than enqueuing again, so N bumps become one store
// round carrying delta N. It returns true when the caller should start a new
// drainer (below the worker cap); otherwise a running drainer will reach the
// key. When the queue is saturated a brand-new key's work stays local (dropped
// from the shared push) but an already-dirty key keeps accumulating. c.mu must
// be held; the caller starts the drainer after unlocking so the inline test
// seam cannot re-enter the lock.
func (c *CounterCache) markDirtyLocked(key string, deadline int64, del bool) (spawn bool) {
	if d, ok := c.dirty[key]; ok {
		c.foldOpLocked(d, deadline, del)
		// A key already dirty is either queued or owned by a flushing drainer.
		// Either way no new drainer is needed: the queued key will be drained,
		// and the flushing owner re-checks the entry after its store round.
		return false
	}
	if len(c.queue) >= maxFlushQueue {
		return false // overload: this new key's push is dropped, local count enforces
	}
	d := &dirtyEntry{del: del, deadline: deadline}
	if !del {
		e := c.m[key]
		d.delta = e.pending
		e.pending = 0
		c.m[key] = e
	}
	c.dirty[key] = d
	c.queue = append(c.queue, key)
	if c.workers < maxFlushWorkers {
		c.workers++
		return true
	}
	return false
}

// foldOpLocked folds one new op into an existing dirty entry. A Forget
// supersedes any accumulated increments: the local counter was reset, so the
// shared one must be deleted, and the delta is cleared. An increment always
// raises the delta and adopts the current window's deadline; if a Forget is
// still pending (del set), del stays set so the delete runs first and these
// increments are applied as the owning drainer's follow-up round, leaving the
// store reflecting the fresh window. c.mu held.
func (c *CounterCache) foldOpLocked(d *dirtyEntry, deadline int64, del bool) {
	if del {
		d.del = true
		d.delta = 0
		return
	}
	if d.deadline != deadline {
		// A new local window opened while the old one was still queued or in
		// flight. Any unclaimed delta belongs exclusively to the expired window;
		// replace it rather than relabeling it with the fresh deadline.
		d.delta = 1
		d.deadline = deadline
		return
	}
	d.delta++
}

// drain flushes dirty keys until the queue is empty, then exits. Multiple
// drainers run concurrently up to maxFlushWorkers; each claims one key at a time
// and owns it (flushing set) across every store round for that key, so no other
// drainer touches it. Ops arriving mid-flush fold into the same entry and are
// handled by a follow-up round before the key is released.
func (c *CounterCache) drain() {
	for {
		c.mu.Lock()
		if len(c.queue) == 0 {
			c.workers--
			c.mu.Unlock()
			return
		}
		key := c.queue[0]
		c.queue = c.queue[1:]
		c.mu.Unlock()

		c.flushKey(key)
	}
}

// flushKey drains all pending work for a key it owns, looping until nothing is
// left, then releases the key. It holds the key (flushing set) across every
// store round via its dirty entry, so no other drainer touches it and any op
// arriving meanwhile folds into the entry and is handled here. A pending delete
// runs first (a Forget reset the local counter, so the shared one must go),
// then any follow-up increment for a fresh window is pushed. On a store error
// it moves the failed work back to the local pending delta and stops; a later
// bump retries the whole batch.
func (c *CounterCache) flushKey(key string) {
	for {
		c.mu.Lock()
		d := c.dirty[key]
		if d == nil {
			c.mu.Unlock()
			return
		}

		// Delete first: it supersedes any earlier increments.
		if d.del {
			d.del = false // consumed; a follow-up Incr may have set delta already
			c.mu.Unlock()
			if !c.flushDelete(key) {
				c.release(key)
				return
			}
			continue
		}

		if d.delta == 0 {
			spawn := c.releaseLocked(key) // nothing left: release the key
			c.mu.Unlock()
			if spawn {
				c.Go(c.drain)
			}
			return
		}

		now := c.now().UnixNano()
		if d.deadline != 0 && now >= d.deadline {
			// Window expired before we could push: drop the delta and do not
			// start a fresh store window. The next loop iteration releases the
			// key (or handles a delete / fresh delta that folded in meanwhile).
			d.delta = 0
			c.mu.Unlock()
			continue
		}

		// Claim the delta and this window's identity; ops arriving during the
		// store round below re-raise d.delta and loop us again.
		delta := d.delta
		deadline := d.deadline
		d.delta = 0
		c.mu.Unlock()

		if !c.flushIncr(key, delta, deadline) {
			c.preserveFailedIncr(key, delta, deadline)
			return
		}
	}
}

// preserveFailedIncr moves a failed claimed batch (plus increments that
// arrived during the store round) back into the local counter's pending
// delta. The dirty entry is released without an immediate retry loop; the
// next bump re-enqueues the complete pending amount. If a Forget arrived
// during the failed round it supersedes the increments, so its delete remains
// dirty and is re-queued through the normal release path.
func (c *CounterCache) preserveFailedIncr(key string, claimed, deadline int64) {
	c.mu.Lock()
	d := c.dirty[key]
	if d == nil {
		c.mu.Unlock()
		return
	}
	if d.del {
		spawn := c.releaseLocked(key)
		c.mu.Unlock()
		if spawn {
			c.Go(c.drain)
		}
		return
	}
	if e, ok := c.m[key]; ok {
		if e.expires == deadline {
			e.pending += claimed
		}
		if d.delta > 0 && e.expires == d.deadline {
			e.pending += d.delta
		}
		c.m[key] = e
	}
	delete(c.dirty, key)
	c.mu.Unlock()
}

// release relinquishes ownership of key: it deletes the dirty entry if it has
// no pending work, or re-queues it (spawning a drainer if needed) if an op
// landed after the owner decided to stop, so the key is never stranded. c.mu
// must NOT be held.
func (c *CounterCache) release(key string) {
	c.mu.Lock()
	spawn := c.releaseLocked(key)
	c.mu.Unlock()
	if spawn {
		c.Go(c.drain)
	}
}

// releaseLocked is release with c.mu held; it returns whether the caller should
// start a drainer after unlocking (never calls c.Go itself, so the inline test
// seam cannot re-enter the lock).
func (c *CounterCache) releaseLocked(key string) (spawn bool) {
	d := c.dirty[key]
	if d == nil {
		return false
	}
	if d.delta == 0 && !d.del {
		delete(c.dirty, key)
		c.capacityProtected = false
		return false
	}
	// Work landed after we gave up (e.g. a store error path): re-queue the key.
	c.queue = append(c.queue, key)
	if c.workers < maxFlushWorkers {
		c.workers++
		return true
	}
	return false
}

// flushIncr pushes delta increments for a window through the store's atomic
// deadline-aware op and merges the shared total back into that same window.
// Two things stop a slow flush from bleeding a stale total into a fresh window:
// the store skips the write entirely once the deadline has passed (so a delayed
// call cannot even create the next window's record), and the local merge is
// gated on the same window's identity (e.expires must still equal the deadline
// flushed). Reports whether the store round succeeded.
func (c *CounterCache) flushIncr(key string, delta, deadline int64) bool {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	shared, applied, err := c.store.IncrByDeadline(ctx, key, delta, deadline)
	if err != nil {
		return false
	}
	if !applied {
		// The store skipped the write because the window had already ended: the
		// delta is legitimately discarded, and there is nothing to merge (a fresh
		// window, if one exists, is a separate entry the loop handles next).
		return true
	}
	c.mu.Lock()
	if e, ok := c.m[key]; ok && e.expires == deadline && c.now().UnixNano() < e.expires && shared > e.n {
		e.n = shared
		c.m[key] = e
	}
	c.mu.Unlock()
	return true
}

// flushDelete removes the shared counter. Reports whether it succeeded.
func (c *CounterCache) flushDelete(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	return c.store.Delete(ctx, key) == nil
}
