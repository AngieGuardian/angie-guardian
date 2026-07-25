// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"fmt"
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
	// nextRoomSweep paces the O(n) at-capacity room sweep: at most one full
	// scan per second, whatever the previous sweep achieved. A new key arriving
	// at capacity between sweeps is counted in the overflow sketch instead of
	// triggering a scan; existing hot keys keep their exact local count and
	// reconciliation state.
	//
	// The unconditional pacing is load-bearing. An earlier version re-swept
	// without pacing whenever the previous sweep had freed anything, and under
	// a rotating-key flood the drains free a handful of slots at a time, so the
	// sweep ran hundreds of times per second — a full-map scan under this
	// mutex, on the challenge hot path — and issuance throughput collapsed by
	// 3x (see BenchmarkChallengeIssue and the loadtest -warmup/-n mode).
	nextRoomSweep int64 // unix nanos: earliest next O(n) room sweep at capacity
	// overflow is a bounded count-min sketch used only while the primary cache
	// is at capacity with nothing reclaimable (or reclamation still paced out).
	// It keeps repeat requests from an unseen key counting upward instead of
	// returning 1 forever. Hash collisions can only over-count, which is the
	// safer overload failure mode for rate limiting.
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

// flushTimeout bounds a store round so a hung store cannot wedge a drain
// goroutine. The request that dirtied the key has long been answered. Rounds
// share a drainCtx, so the effective per-round deadline is between half and
// all of this.
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

// Flush pushes every unpushed live delta to the store and waits for the
// drainers to go idle, bounded by ctx. Call it at shutdown, after request
// traffic has stopped and before the store closes, so durable and shared
// backends do not lose the last windows' counts on every restart. It promotes
// deltas parked in the local pending slots (queue overflow, an earlier failed
// round) to dirty entries, deliberately ignoring the maxFlushQueue overload
// valve: that cap bounds steady-state memory, not a one-shot drain of work
// that already exists. Expired windows are dropped as always. The cache stays
// usable afterwards; a late Incr simply dirties keys again.
func (c *CounterCache) Flush(ctx context.Context) error {
	c.mu.Lock()
	now := c.now().UnixNano()
	spawn := 0
	for key, e := range c.m {
		if e.pending == 0 || now >= e.expires {
			continue
		}
		if _, owned := c.dirty[key]; owned {
			// An owning drainer is mid-flight; a pending slot here means a
			// failed round is being preserved concurrently. Its next bump
			// retries; stealing it now would race the owner.
			continue
		}
		c.dirty[key] = &dirtyEntry{delta: e.pending, deadline: e.expires}
		e.pending = 0
		c.m[key] = e
		c.queue = append(c.queue, key)
	}
	for c.workers < maxFlushWorkers && c.workers < len(c.queue) {
		c.workers++
		spawn++
	}
	c.mu.Unlock()
	for range spawn {
		c.Go(c.drain)
	}

	// Wait for quiescence: empty queue and no live drainers.
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		c.mu.Lock()
		idle := len(c.queue) == 0 && c.workers == 0
		c.mu.Unlock()
		if idle {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}

	// Quiescence means the queue drained, not that every push landed: a failed
	// store round parks its delta back in the entry's pending slot. The likely
	// real-world loss case is the store being unreachable at shutdown, so
	// count what is still unpushed and report it instead of claiming success.
	c.mu.Lock()
	left := 0
	now = c.now().UnixNano()
	for _, e := range c.m {
		if e.pending > 0 && now < e.expires {
			left++
		}
	}
	c.mu.Unlock()
	if left > 0 {
		return fmt.Errorf("%d counter keys still hold unpushed deltas after flush (store unreachable?)", left)
	}
	return nil
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

// makeCounterRoomLocked preserves every entry that still owns live unpushed
// work and bulk-evicts the rest: clean cached totals, and expired entries even
// when they retained a pending delta — the window is over, so that delta is
// unpushable anyway (flushKey drops expired windows). Without the expired-entry
// rule, a rotating-IP flood during a store outage would fill the cache with
// never-rebumped protected entries and permanently degrade all new keys to the
// overflow sketch.
//
// The scan runs at most once per second, unconditionally: a sweep that frees
// only the few slots the drains released since the last one must not license an
// immediate re-sweep, or a sustained new-key flood turns into a full-map scan
// under c.mu every few insertions (measured at 62% of all daemon CPU, a 3x
// issuance collapse). Keys shed between sweeps are counted by the overflow
// sketch, which is the designed degradation. The eviction test orders its cheap
// field checks before the c.dirty map lookup on purpose: in the saturated
// regime nearly every entry short-circuits on pending, and hashing 131k keys
// per sweep was most of the sweep's cost. c.mu must be held.
func (c *CounterCache) makeCounterRoomLocked() bool {
	if len(c.m) < maxCounterEntries {
		return true
	}
	now := c.now().UnixNano()
	if now < c.nextRoomSweep {
		return false
	}
	c.nextRoomSweep = now + time.Second.Nanoseconds()
	for key, e := range c.m {
		if (e.pending == 0 || now >= e.expires) && c.dirty[key] == nil {
			delete(c.m, key)
		}
	}
	return len(c.m) < maxCounterEntries
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
	// One reusable store-round context for the whole drain loop, refreshed when
	// under half its budget remains (see drainCtx). A fresh WithTimeout per
	// round costs a context, a timer and a cancel closure per flushed key,
	// which under a new-key flood made the background flusher one of the
	// daemon's largest allocation sources.
	dc := &drainCtx{now: c.now}
	defer dc.close()
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

		c.flushKey(dc, key)
	}
}

// drainCtx hands a drain goroutine its store-round contexts, reusing one until
// less than half of flushTimeout remains and then replacing it. Every round
// therefore still runs under a deadline between flushTimeout/2 and
// flushTimeout, so a hung store cannot wedge the goroutine, while the
// context/timer/cancel allocation is amortized over many flushed keys instead
// of paid per round. Owned by exactly one goroutine; not safe to share.
type drainCtx struct {
	ctx    context.Context
	cancel context.CancelFunc
	now    func() time.Time
}

func (d *drainCtx) get() context.Context {
	if d.ctx != nil {
		if deadline, ok := d.ctx.Deadline(); ok && deadline.Sub(d.now()) >= flushTimeout/2 {
			return d.ctx
		}
		d.cancel()
	}
	d.ctx, d.cancel = context.WithTimeout(context.Background(), flushTimeout)
	return d.ctx
}

func (d *drainCtx) close() {
	if d.cancel != nil {
		d.cancel()
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
func (c *CounterCache) flushKey(dc *drainCtx, key string) {
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
			if !c.flushDelete(dc, key) {
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

		if !c.flushIncr(dc, key, delta, deadline) {
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
func (c *CounterCache) flushIncr(dc *drainCtx, key string, delta, deadline int64) bool {
	shared, applied, err := c.store.IncrByDeadline(dc.get(), key, delta, deadline)
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
func (c *CounterCache) flushDelete(dc *drainCtx, key string) bool {
	return c.store.Delete(dc.get(), key) == nil
}
