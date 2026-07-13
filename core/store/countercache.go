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
// synced in the background: a flush merges the store's total back into the
// local count, so replicas converge on the shared count within one round trip
// and a restarted instance catches back up on its first bump.
//
// Background work is bounded. A request never spawns a goroutine directly:
// the key is marked dirty and, at most maxFlushWorkers drain goroutines pull
// dirty keys off a bounded queue and flush them. Repeated bumps of one key
// while its flush is pending coalesce into a single store round (per-key
// singleflight), and when the queue is full the shared flush for the extra key
// is dropped. So a new-client/challenge flood cannot amplify each request into
// its own outstanding store goroutine: the goroutine count is capped and the
// store round count is coalesced.
//
// The trade-offs are deliberate. Enforcement is exact for a client served by a
// single instance and trails the cross-instance total only by the flushes
// still pending. When the store is unreachable, or the flush queue is
// saturated, the local count keeps enforcing, which is tighter than failing
// open. The merge is monotonic within a live TTL window, so an out-of-order or
// stale flush can never roll the local count backward. Forget is best-effort:
// a delete still pending when the key is re-bumped can race, bounded by the
// work in flight at that moment.
type CounterCache struct {
	store Store

	// Go starts a drain goroutine. Tests replace it to drain inline, making
	// the store state deterministic.
	Go func(func())

	mu      sync.Mutex
	m       map[string]counterEntry
	dirty   map[string]dirtyEntry // keys whose shared counter needs a flush
	queue   []string              // FIFO of dirty keys awaiting a drainer
	workers int                   // live drain goroutines, capped at maxFlushWorkers

	now func() time.Time
}

type counterEntry struct {
	n       int64
	expires int64 // unix nanoseconds
}

// dirtyEntry is a pending shared-counter operation for a key: either an Incr
// with the given ttl, or a Delete (from Forget). The latest op for a key wins,
// so a Forget after some Incrs flushes as a single Delete.
type dirtyEntry struct {
	ttl time.Duration
	del bool
}

// maxCounterEntries bounds memory the same way tokenCache does: when full,
// the map is wholesale-reset. Live counters repopulate from the store total
// on their next bump's flush, so a reset costs one under-counted request per
// hot key, not the counter state itself.
const maxCounterEntries = 1 << 17

// maxFlushWorkers caps how many drain goroutines flush the shared store
// counter concurrently. It bounds the goroutine and store-concurrency cost of
// a flood: past this, extra dirty keys wait in the queue or, if it is full,
// have their shared flush dropped while the local count keeps enforcing.
const maxFlushWorkers = 8

// maxFlushQueue bounds the backlog of dirty keys awaiting a drainer. When it
// is full a new dirty key's shared flush is dropped (local enforcement
// continues); this is the overload valve that keeps memory bounded under a
// distributed new-key flood.
const maxFlushQueue = 1 << 14

// flushTimeout bounds a single store round so a hung store cannot wedge a
// drain goroutine. The request that dirtied the key has long been answered.
const flushTimeout = 5 * time.Second

func NewCounterCache(st Store) *CounterCache {
	return &CounterCache{
		store: st,
		Go:    func(f func()) { go f() },
		m:     make(map[string]counterEntry),
		dirty: make(map[string]dirtyEntry),
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
	spawn := c.markDirtyLocked(key, dirtyEntry{ttl: ttl})
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
	spawn := c.markDirtyLocked(key, dirtyEntry{del: true})
	c.mu.Unlock()

	if spawn {
		c.Go(c.drain)
	}
}

// markDirtyLocked records the latest pending shared-counter op for key and
// ensures a drainer will pick it up. It coalesces: a key already queued is not
// enqueued twice, so repeated bumps collapse to one store round. It returns
// true when the caller should start a new drainer (below the worker cap);
// otherwise the running drainers will reach the key. When the queue is
// saturated the op is dropped and only the local state (already updated by the
// caller) enforces. c.mu must be held; the caller starts the drainer after
// unlocking so the inline test seam cannot re-enter the lock.
func (c *CounterCache) markDirtyLocked(key string, d dirtyEntry) (spawn bool) {
	if _, queued := c.dirty[key]; queued {
		c.dirty[key] = d // update the pending op; key already in the queue
		return false
	}
	if len(c.queue) >= maxFlushQueue {
		return false // overload: drop the shared flush, local count still enforces
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
// drainers run concurrently up to maxFlushWorkers; each owns one key at a time.
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
		d := c.dirty[key]
		delete(c.dirty, key)
		c.mu.Unlock()

		c.flush(key, d)
	}
}

// flush runs one store round for key and merges the result back. On an Incr it
// merges the shared total monotonically into the live local entry; on a Delete
// (Forget) it removes the shared counter. A store error leaves the local state
// as the caller set it, degrading to per-instance enforcement.
func (c *CounterCache) flush(key string, d dirtyEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()

	if d.del {
		_ = c.store.Delete(ctx, key)
		return
	}

	shared, err := c.store.Incr(ctx, key, d.ttl)
	if err != nil {
		return // local count keeps enforcing
	}
	c.mu.Lock()
	// Merge monotonically within the live TTL window: an out-of-order or
	// stale flush (a smaller shared total, or one that predates local bumps
	// whose own flush is still pending) must never lower the local count.
	if e, ok := c.m[key]; ok && c.now().UnixNano() < e.expires && shared > e.n {
		e.n = shared
		c.m[key] = e
	}
	c.mu.Unlock()
}
