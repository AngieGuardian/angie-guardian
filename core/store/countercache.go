// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"sync"
	"time"
)

// CounterCache fronts Store.Incr for the per-IP event counters on the
// challenge hot path (issuance rate limit, farming escalation). Counting
// through the store directly costs one blocking write round per counter per
// request; on bbolt that is an fsync'd batch round, so every extra counter
// visibly cuts challenge issuance throughput. Instead the count is bumped in
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

	now func() time.Time
}

type counterEntry struct {
	n       int64
	expires int64 // unix nanoseconds
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

// maxCounterEntries bounds memory the same way tokenCache does: when full,
// the map is wholesale-reset. Live counters repopulate from the store total
// on their next bump's flush, so a reset costs one under-counted request per
// hot key, not the counter state itself.
const maxCounterEntries = 1 << 17

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
	return &CounterCache{
		store: st,
		Go:    func(f func()) { go f() },
		m:     make(map[string]counterEntry),
		dirty: make(map[string]*dirtyEntry),
		now:   time.Now,
	}
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
		if len(c.m) >= maxCounterEntries {
			clear(c.m)
		}
		e = counterEntry{expires: now + ttl.Nanoseconds()}
	}
	e.n++
	n := e.n
	c.m[key] = e
	spawn := c.markDirtyLocked(key, e.expires, false)
	c.mu.Unlock()

	if spawn {
		c.Go(c.drain)
	}
	return n
}

// Forget clears the counter locally and, in the background, in the store.
func (c *CounterCache) Forget(key string) {
	c.mu.Lock()
	delete(c.m, key)
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
		d.delta = 1
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
	d.delta++
	d.deadline = deadline
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
// it releases the key and stops: the delta is not pushed, matching the
// documented degrade to per-instance enforcement when the store is unreachable.
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
		remaining := time.Duration(0)
		if deadline != 0 {
			remaining = time.Duration(deadline - now)
		}
		c.mu.Unlock()

		if !c.flushIncr(key, delta, deadline, remaining) {
			c.release(key)
			return
		}
	}
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

// flushIncr pushes delta increments for a window and merges the shared total
// back, but only into that same live window. Carrying the window's absolute
// deadline is what stops a slow flush from bleeding its (possibly large) shared
// total into a fresh window that started while it was blocked. Reports whether
// the store round succeeded.
func (c *CounterCache) flushIncr(key string, delta, deadline int64, remaining time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	shared, err := c.store.IncrBy(ctx, key, delta, remaining)
	if err != nil {
		return false
	}
	c.mu.Lock()
	// Merge monotonically, and only into the same window this delta belonged to:
	// e.expires must still equal the deadline we flushed. A new window has a
	// different expires, so a stale flush that outlived its window is rejected.
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
