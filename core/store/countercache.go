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
// nanos), so a flush uses the remaining TTL and skips an expired window. del
// marks a pending Forget (a Delete that supersedes any accumulated delta).
//
// A single drainer owns a key from the moment it is dequeued until its delta
// drains to zero: the entry stays in c.dirty (so it is never re-enqueued), and
// bumps arriving mid-flush raise delta in place and are pushed by the owning
// drainer's follow-up round. This is the per-key singleflight guarantee.
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
// pick it up. It coalesces losslessly: a key already dirty accumulates its
// delta in place rather than enqueuing again, so N bumps become one store round
// carrying delta N. It returns true when the caller should start a new drainer
// (below the worker cap); otherwise a running drainer will reach the key. When
// the queue is saturated a brand-new key's work stays local (dropped from the
// shared push) but an already-dirty key keeps accumulating. c.mu must be held;
// the caller starts the drainer after unlocking so the inline test seam cannot
// re-enter the lock.
func (c *CounterCache) markDirtyLocked(key string, deadline int64, del bool) (spawn bool) {
	if d, ok := c.dirty[key]; ok {
		if del {
			d.del = true // a Forget supersedes accumulated increments
			d.delta = 0
		} else if !d.del {
			d.delta++
			d.deadline = deadline
		}
		// If the key is mid-flush it is not in the queue; the owning drainer
		// re-checks it after the store round, so no new drainer is needed.
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

// drain flushes dirty keys until the queue is empty, then exits. Multiple
// drainers run concurrently up to maxFlushWorkers; each owns one key at a time
// and holds it (flushing=true) across the store round so no other drainer
// touches it. Bumps arriving mid-flush accumulate into the same entry and are
// pushed by a follow-up round before the key is released.
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

// flushKey pushes a key's accumulated work to the store, looping until no new
// work arrived while the previous round was in flight (at most one extra round
// per burst in practice, since bumps coalesce). It owns the key across each
// store round via the dirty entry, so no other drainer touches it. It releases
// the key (deletes the entry) when nothing is left to push, when the window has
// expired, or when a store round fails (the local count keeps enforcing, as it
// does whenever the store is unreachable).
func (c *CounterCache) flushKey(key string) {
	for {
		c.mu.Lock()
		d := c.dirty[key]
		switch {
		case d == nil:
			c.mu.Unlock()
			return
		case d.del:
			delete(c.dirty, key)
			c.mu.Unlock()
			c.flushDelete(key)
			return
		case d.delta == 0:
			delete(c.dirty, key) // nothing left to push: release the key
			c.mu.Unlock()
			return
		}
		now := c.now().UnixNano()
		if d.deadline != 0 && now >= d.deadline {
			delete(c.dirty, key) // window expired: drop the delta, do not extend
			c.mu.Unlock()
			return
		}
		// Claim the pending delta; bumps during the store round below re-raise
		// d.delta and loop us again.
		delta := d.delta
		d.delta = 0
		remaining := time.Duration(0)
		if d.deadline != 0 {
			remaining = time.Duration(d.deadline - now)
		}
		c.mu.Unlock()

		if !c.flushIncr(key, delta, remaining) {
			// Store round failed: release the key and stop. The delta is not
			// pushed to the shared counter, matching the documented degrade to
			// per-instance enforcement when the store is unreachable.
			c.mu.Lock()
			delete(c.dirty, key)
			c.mu.Unlock()
			return
		}
	}
}

// flushIncr pushes delta increments for a live window and merges the shared
// total back monotonically. Reports whether the store round succeeded.
func (c *CounterCache) flushIncr(key string, delta int64, remaining time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	shared, err := c.store.IncrBy(ctx, key, delta, remaining)
	if err != nil {
		return false
	}
	c.mu.Lock()
	// Merge monotonically within the live TTL window: an out-of-order or stale
	// flush must never lower the local count.
	if e, ok := c.m[key]; ok && c.now().UnixNano() < e.expires && shared > e.n {
		e.n = shared
		c.m[key] = e
	}
	c.mu.Unlock()
	return true
}

func (c *CounterCache) flushDelete(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	_ = c.store.Delete(ctx, key)
}
