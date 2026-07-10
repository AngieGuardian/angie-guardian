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
// an in-process map and returned immediately, and the shared store counter
// is incremented in the background: each flush overwrites the local count
// with the store's total, so replicas converge on the shared count within
// one round trip and a restarted instance catches back up on its first bump.
//
// The trade-offs are deliberate. Enforcement is exact for a client served by
// a single instance and trails the cross-instance total only by the flushes
// still in flight. When the store is unreachable the local count keeps
// enforcing, which is tighter than failing open. Forget is best-effort: a
// flush still in flight when the key is forgotten can resurrect a small
// residue in the store, bounded by the calls in flight at that moment.
type CounterCache struct {
	store Store

	// Go runs a background flush. Tests replace it to run flushes inline,
	// making the store state deterministic.
	Go func(func())

	mu sync.Mutex
	m  map[string]counterEntry

	now func() time.Time
}

type counterEntry struct {
	n       int64
	expires int64 // unix nanoseconds
}

// maxCounterEntries bounds memory the same way tokenCache does: when full,
// the map is wholesale-reset. Live counters repopulate from the store total
// on their next bump's flush, so a reset costs one under-counted request per
// hot key, not the counter state itself.
const maxCounterEntries = 1 << 17

// flushTimeout bounds a background flush so a hung store cannot pile up
// goroutines. The request that spawned the flush has long been answered.
const flushTimeout = 5 * time.Second

func NewCounterCache(st Store) *CounterCache {
	return &CounterCache{
		store: st,
		Go:    func(f func()) { go f() },
		m:     make(map[string]counterEntry),
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
	c.mu.Unlock()

	c.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		defer cancel()
		shared, err := c.store.Incr(ctx, key, ttl)
		if err != nil {
			return // local count keeps enforcing
		}
		c.mu.Lock()
		if e, ok := c.m[key]; ok && c.now().UnixNano() < e.expires {
			e.n = shared
			c.m[key] = e
		}
		c.mu.Unlock()
	})
	return n
}

// Forget clears the counter locally and, in the background, in the store.
func (c *CounterCache) Forget(key string) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()

	c.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		defer cancel()
		_ = c.store.Delete(ctx, key)
	})
}
