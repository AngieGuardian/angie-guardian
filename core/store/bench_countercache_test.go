// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"runtime"
	"strconv"
	"testing"
	"time"
)

// BenchmarkCounterCacheDirtyLifecycle isolates the map lifecycle that every
// new challenge counter key crosses when it enters and leaves dirty ownership.
// Store I/O and drain contexts are deliberately excluded; their
// backend-dependent allocations would hide the lifecycle this gate owns.
func BenchmarkCounterCacheDirtyLifecycle(b *testing.B) {
	const key = "challenge-counter-bench"
	deadline := time.Now().Add(time.Minute).UnixNano()
	c := &CounterCache{
		m:       make(map[string]counterEntry),
		dirty:   make(map[string]dirtyEntry),
		queue:   make([]string, 0, 1),
		workers: maxFlushWorkers,
		now:     time.Now,
	}

	cycle := func() {
		c.m[key] = counterEntry{pending: 1, expires: deadline}
		if c.markDirtyLocked(key, deadline, false) {
			b.Fatal("lifecycle benchmark unexpectedly requested a worker")
		}
		c.queue = c.queue[:0]
		d := c.dirty[key]
		d.delta = 0
		c.dirty[key] = d
		if c.releaseLocked(key) {
			b.Fatal("lifecycle benchmark unexpectedly requested a worker on release")
		}
	}

	cycle() // allocate map buckets outside the timed loop
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		cycle()
	}
}

// BenchmarkCounterCacheDirtyOwnedKey reports the other CounterCache workload:
// repeated operations on a key that is already queued or owned by a drainer.
// The sequential case exposes the value-map copy/update cost; the parallel
// case includes the same-key mutex contention production sees. This is a
// manual timing benchmark, not an allocation gate, and carries its own
// GOMAXPROCS matrix so both workload shapes stay visible in one run.
func BenchmarkCounterCacheDirtyOwnedKey(b *testing.B) {
	const key = "owned-challenge-counter"
	deadline := time.Now().Add(time.Minute).UnixNano()

	for _, procs := range []int{1, 2, 4, 8} {
		b.Run("GOMAXPROCS="+strconv.Itoa(procs), func(b *testing.B) {
			previous := runtime.GOMAXPROCS(procs)
			defer runtime.GOMAXPROCS(previous)

			newCache := func() *CounterCache {
				return &CounterCache{
					dirty: map[string]dirtyEntry{
						key: {delta: 1, deadline: deadline},
					},
				}
			}

			b.Run("Sequential", func(b *testing.B) {
				c := newCache()
				b.ReportAllocs()
				for b.Loop() {
					c.mu.Lock()
					c.markDirtyLocked(key, deadline, false)
					c.mu.Unlock()
				}
			})

			b.Run("Parallel", func(b *testing.B) {
				c := newCache()
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						c.mu.Lock()
						c.markDirtyLocked(key, deadline, false)
						c.mu.Unlock()
					}
				})
			})
		})
	}
}
