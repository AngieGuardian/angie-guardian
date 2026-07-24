// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package enforce

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

const shardCount = 32

type entry struct {
	reason     string
	expiresAt  int64 // unix nanos; 0 = no expiry
	insertedAt int64 // unix nanos; lets reconcile spare entries newer than its scan
}

type shard struct {
	mu sync.RWMutex
	m  map[netip.Addr]entry
}

// mirror is the bounded, sharded in-process view of the active block set.
// Lookups on the auth hot path vastly outnumber writes (blocks are rare), so
// sharded RWMutex maps win over a copy-on-write structure, which would pay a
// full map copy per insert during a block storm.
type mirror struct {
	shards      [shardCount]shard
	maxPerShard int
	dropped     atomic.Uint64

	// tombs records recent removals (addr -> removedAt unix nanos) so a
	// reconcile whose store scan predates a removal cannot resurrect the block
	// from its stale snapshot. Sinks get the same protection from the
	// generation + runner mutex; the mirror upsert path needs its own.
	tombMu sync.Mutex
	tombs  map[netip.Addr]int64
}

// maxTombstones bounds the removal log between reconciles (a reconcile prunes
// everything older than its scan). Past the cap the oldest entries go first:
// losing one only re-opens the pre-existing one-interval resurrection window
// for that address.
const maxTombstones = 4096

func newMirror(maxEntries int) *mirror {
	mr := &mirror{maxPerShard: max(maxEntries/shardCount, 1), tombs: make(map[netip.Addr]int64)}
	for i := range mr.shards {
		mr.shards[i].m = make(map[netip.Addr]entry)
	}
	return mr
}

// shardOf spreads addresses over shards with FNV-1a so v4 and v6 rotation
// both distribute; the map key hash alone does not pick the shard.
func shardOf(a netip.Addr) int {
	b := a.As16()
	h := uint32(2166136261)
	for _, c := range b {
		h = (h ^ uint32(c)) * 16777619
	}
	return int(h % shardCount)
}

// get returns the block reason for a live entry. Expired entries read as
// absent; the reconcile sweep removes them physically.
func (mr *mirror) get(a netip.Addr, now int64) (string, bool) {
	s := &mr.shards[shardOf(a)]
	s.mu.RLock()
	e, ok := s.m[a]
	s.mu.RUnlock()
	if !ok || (e.expiresAt != 0 && e.expiresAt <= now) {
		return "", false
	}
	return e.reason, true
}

// set inserts or updates an entry. A full shard first sheds its expired
// entries; if still full the insert is dropped (returns false) and that IP
// keeps enforcing through the store path instead, so capacity pressure can
// only ever cost the optimization, not the block.
func (mr *mirror) set(a netip.Addr, e entry) bool {
	s := &mr.shards[shardOf(a)]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[a]; !exists && len(s.m) >= mr.maxPerShard {
		for k, old := range s.m {
			if old.expiresAt != 0 && old.expiresAt <= e.insertedAt {
				delete(s.m, k)
			}
		}
		if len(s.m) >= mr.maxPerShard {
			mr.dropped.Add(1)
			return false
		}
	}
	s.m[a] = e
	return true
}

func (mr *mirror) remove(a netip.Addr, now int64) {
	s := &mr.shards[shardOf(a)]
	s.mu.Lock()
	delete(s.m, a)
	s.mu.Unlock()

	mr.tombMu.Lock()
	if len(mr.tombs) >= maxTombstones {
		oldestAddr, oldest := a, now
		for k, t := range mr.tombs {
			if t < oldest {
				oldestAddr, oldest = k, t
			}
		}
		delete(mr.tombs, oldestAddr)
	}
	mr.tombs[a] = now
	mr.tombMu.Unlock()
}

// removedSince reports whether a was removed at or after scanStart, pruning
// tombstones too old to matter for this or any later scan.
func (mr *mirror) removedSince(a netip.Addr, scanStart int64) bool {
	mr.tombMu.Lock()
	defer mr.tombMu.Unlock()
	t, ok := mr.tombs[a]
	if ok && t < scanStart {
		delete(mr.tombs, a)
		return false
	}
	return ok
}

// pruneTombstones drops removals older than scanStart: every future scan
// starts later, so they can never veto an upsert again.
func (mr *mirror) pruneTombstones(scanStart int64) {
	mr.tombMu.Lock()
	for k, t := range mr.tombs {
		if t < scanStart {
			delete(mr.tombs, k)
		}
	}
	mr.tombMu.Unlock()
}

// reconcile converges the mirror on the scanned authoritative set: every
// scanned entry is upserted with its real expiry, and entries absent from the
// scan are removed unless they were written through after the scan started
// (those are newer truth than the scan). Symmetrically, an entry removed at or
// after the scan started is newer truth than the snapshot and is not
// re-inserted; without that, an admin unblock landing mid-reconcile would be
// silently undone until the next scan.
func (mr *mirror) reconcile(active map[netip.Addr]entry, scanStart int64, scannedAll bool) bool {
	if scannedAll {
		for i := range mr.shards {
			s := &mr.shards[i]
			s.mu.Lock()
			for k, e := range s.m {
				if _, ok := active[k]; !ok && e.insertedAt < scanStart {
					delete(s.m, k)
				}
			}
			s.mu.Unlock()
		}
	}
	complete := scannedAll
	for k, e := range active {
		if mr.removedSince(k, scanStart) {
			continue
		}
		if !mr.set(k, e) {
			complete = false
		}
	}
	mr.pruneTombstones(scanStart)
	return complete
}

func (mr *mirror) count() int {
	n := 0
	for i := range mr.shards {
		s := &mr.shards[i]
		s.mu.RLock()
		n += len(s.m)
		s.mu.RUnlock()
	}
	return n
}
