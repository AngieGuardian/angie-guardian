// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package botverify

import (
	"container/list"
	"hash/maphash"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const localShards = 32
const localPerShard = 256

// Identity is an immutable, forward-confirmed identity snapshot. Hostnames
// stay private so callers cannot alter another request's cached verdict.
type Identity struct {
	status    Status
	hostnames []string
}

func (i Identity) Status() Status { return i.status }
func (i Identity) MatchesDomains(domains []string) bool {
	return (Result{Hostnames: i.hostnames}).MatchesDomains(domains)
}
func (i Identity) result() Result {
	return Result{Status: i.status, Hostnames: slices.Clone(i.hostnames)}
}

// CacheMetrics is attached once at startup, before serving requests.
type CacheMetrics interface {
	BotCacheLookup(path string, hit bool)
	BotCacheEntries(delta int)
}

type localEntry struct {
	addr     netip.Addr
	identity Identity
	expires  time.Time
}
type localShard struct {
	mu      sync.RWMutex
	entries map[netip.Addr]*list.Element
	lru     list.List
}
type localCache struct {
	seed    maphash.Seed
	shards  [localShards]localShard
	now     func() time.Time
	metrics CacheMetrics
}

func newLocalCache() *localCache {
	c := &localCache{seed: maphash.MakeSeed(), now: time.Now}
	for i := range c.shards {
		c.shards[i].entries = make(map[netip.Addr]*list.Element)
	}
	return c
}
func (c *localCache) shard(a netip.Addr) *localShard {
	return &c.shards[maphash.Comparable(c.seed, a)%localShards]
}
func (c *localCache) observe(path string, hit bool) {
	if c.metrics != nil {
		c.metrics.BotCacheLookup(path, hit)
	}
}
func (c *localCache) count(delta int) {
	if c.metrics != nil {
		c.metrics.BotCacheEntries(delta)
	}
}
func (c *localCache) get(a netip.Addr, shed bool) (Identity, bool) {
	sh := c.shard(a)
	if shed {
		// No writer queue, eviction, refresh, store access or DNS on this path.
		if !sh.mu.TryRLock() {
			c.observe("shed", false)
			return Identity{}, false
		}
		el, ok := sh.entries[a]
		var identity Identity
		if ok {
			e := el.Value.(localEntry)
			ok = e.expires.After(c.now())
			identity = e.identity
		}
		sh.mu.RUnlock()
		c.observe("shed", ok)
		return identity, ok
	}
	sh.mu.Lock()
	el, ok := sh.entries[a]
	var identity Identity
	if ok {
		e := el.Value.(localEntry)
		if !e.expires.After(c.now()) {
			delete(sh.entries, a)
			sh.lru.Remove(el)
			c.count(-1)
			ok = false
		} else {
			sh.lru.MoveToFront(el)
			identity = e.identity
		}
	}
	sh.mu.Unlock()
	c.observe("normal", ok)
	return identity, ok
}
func (c *localCache) put(a netip.Addr, res Result, expires time.Time) {
	if expires.IsZero() || !expires.After(c.now()) {
		return
	}
	identity := Identity{status: res.Status, hostnames: slices.Clone(res.Hostnames)}
	sh := c.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if el, ok := sh.entries[a]; ok {
		el.Value = localEntry{a, identity, expires}
		sh.lru.MoveToFront(el)
		return
	}
	if len(sh.entries) >= localPerShard {
		// Bounded sweep only on writes; the overload reader never maintains LRU.
		now := c.now()
		for addr, el := range sh.entries {
			if !el.Value.(localEntry).expires.After(now) {
				delete(sh.entries, addr)
				sh.lru.Remove(el)
				c.count(-1)
			}
		}
		if len(sh.entries) >= localPerShard {
			el := sh.lru.Back()
			delete(sh.entries, el.Value.(localEntry).addr)
			sh.lru.Remove(el)
			c.count(-1)
		}
	}
	sh.entries[a] = sh.lru.PushFront(localEntry{a, identity, expires})
	c.count(1)
}

// LookupCached is local-only and never waits for verification or a cache lock.
// A miss, expired entry or contended shard is unavailable, not an impostor.
func (v *Verifier) LookupCached(ip string) (Identity, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		v.local.observe("shed", false)
		return Identity{}, false
	}
	return v.local.get(a.Unmap(), true)
}

func (v *Verifier) SetMetrics(m CacheMetrics) { v.local.metrics = m }
