// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ShardedMemory is the in-process Store for development, testing and
// single-instance setups that can afford to lose state on restart. It splits the
// keyspace across N shards, each with its own mutex, so concurrent writes to
// different keys contend only within one shard instead of behind a single
// process-wide lock (which would serialize every spent-marker CAS and counter
// increment — the write bottleneck under a fresh-client flood).
//
// High-volume general keys (challenge:*, spent1:*, counters) are sharded. The
// low-volume scannable namespaces — block:* (needs an O(index) ScanActiveBlocks)
// and posture votes (need a cross-key max) — live in a single central struct.
//
// Reads lazy-expire on access (delete-on-read under the write lock), so an
// expired key is filtered even before the janitor sweeps it.
type ShardedMemory struct {
	shards    []shard
	mask      uint32
	central   shardCentral
	done      chan struct{}
	closeOnce sync.Once
}

// entry is one stored value with its optional expiry (zero = no expiry).
type entry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

func (e entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// postureVote is one instance's fleet-posture vote with its expiry.
type postureVote struct {
	level     int
	expiresAt time.Time
}

// expiry converts a TTL to an absolute deadline (zero TTL => permanent).
func expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}

// NewMemory returns an in-process Store. It is an alias for NewShardedMemory(0)
// (default shard count): the store is in-memory and lost on restart, and the
// name keeps callers that only care about "an in-memory store" unchanged.
func NewMemory() *ShardedMemory { return NewShardedMemory(0) }

type shard struct {
	mu sync.Mutex
	m  map[string]entry
}

type shardCentral struct {
	mu           sync.Mutex
	m            map[string]entry
	activeBlocks map[string]struct{}
	postureVotes map[string]postureVote
}

const defaultShards = 256

// NewShardedMemory builds a sharded in-memory Store. shards is rounded up to the
// next power of two (so key routing is a mask, not a modulo); shards <= 0 uses
// defaultShards.
func NewShardedMemory(shards int) *ShardedMemory {
	n := nextPow2(shards)
	s := &ShardedMemory{
		shards: make([]shard, n),
		mask:   uint32(n - 1),
		central: shardCentral{
			m:            make(map[string]entry),
			activeBlocks: make(map[string]struct{}),
			postureVotes: make(map[string]postureVote),
		},
		done: make(chan struct{}),
	}
	for i := range s.shards {
		s.shards[i].m = make(map[string]entry)
	}
	go s.janitor()
	return s
}

func nextPow2(n int) int {
	if n <= 0 {
		n = defaultShards
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// fnv1a32 is an alloc-free FNV-1a hash over the key, used only to pick a shard.
func fnv1a32(s string) uint32 {
	const offset32 = 2166136261
	const prime32 = 16777619
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}

// isCentral reports whether a key lives in the central struct rather than a
// shard. Only the block: index namespace qualifies; posture votes are stored on
// the central struct directly by their own methods, not by key.
func isCentral(key string) bool { return strings.HasPrefix(key, "block:") }

func (s *ShardedMemory) shardFor(key string) *shard {
	return &s.shards[fnv1a32(key)&s.mask]
}

// lockShardKeys locks the unique non-central shards for keys in a stable order.
// Multi-key block/unblock commits take central.mu first and these locks second;
// every other operation holds at most one of them, so this ordering cannot
// deadlock while still making the cross-key mutation atomic.
func (s *ShardedMemory) lockShardKeys(keys ...string) func() {
	idxs := make([]int, 0, len(keys))
	for _, key := range keys {
		if !isCentral(key) {
			idxs = append(idxs, int(fnv1a32(key)&s.mask))
		}
	}
	slices.Sort(idxs)
	idxs = slices.Compact(idxs)
	for _, idx := range idxs {
		s.shards[idx].mu.Lock()
	}
	return func() {
		for i := len(idxs) - 1; i >= 0; i-- {
			s.shards[idxs[i]].mu.Unlock()
		}
	}
}

func (s *ShardedMemory) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			for i := range s.shards {
				sh := &s.shards[i]
				sh.mu.Lock()
				for k, e := range sh.m {
					if e.expired(now) {
						delete(sh.m, k)
					}
				}
				sh.mu.Unlock()
			}
			s.central.mu.Lock()
			for k, e := range s.central.m {
				if e.expired(now) {
					delete(s.central.m, k)
					delete(s.central.activeBlocks, k)
				}
			}
			for id, vote := range s.central.postureVotes {
				if !vote.expiresAt.IsZero() && now.After(vote.expiresAt) {
					delete(s.central.postureVotes, id)
				}
			}
			s.central.mu.Unlock()
		}
	}
}

// getShard is the lazy-expire-on-read helper for a shard map; the caller holds
// the shard lock. Mirrors Memory.get for a single map.
func getShard(m map[string]entry, key string) (entry, bool) {
	e, ok := m[key]
	if !ok || e.expired(time.Now()) {
		delete(m, key)
		return entry{}, false
	}
	return e, true
}

// getCentral is Memory.get for the central struct: it also drops the stale key
// from the activeBlocks index on expiry. The caller holds central.mu.
func (s *ShardedMemory) getCentral(key string) (entry, bool) {
	e, ok := s.central.m[key]
	if !ok || e.expired(time.Now()) {
		delete(s.central.m, key)
		delete(s.central.activeBlocks, key)
		return entry{}, false
	}
	return e, true
}

func (s *ShardedMemory) Get(_ context.Context, key string) ([]byte, bool, error) {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		e, ok := s.getCentral(key)
		if !ok {
			return nil, false, nil
		}
		return bytes.Clone(e.value), true, nil
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := getShard(sh.m, key)
	if !ok {
		return nil, false, nil
	}
	return bytes.Clone(e.value), true, nil
}

func (s *ShardedMemory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		s.central.m[key] = entry{value: bytes.Clone(value), expiresAt: expiry(ttl)}
		// isCentral already restricts this to block:, but keep the explicit prefix
		// check so the index rule matches Memory.Set exactly.
		if strings.HasPrefix(key, "block:") {
			s.central.activeBlocks[key] = struct{}{}
		}
		return nil
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.m[key] = entry{value: bytes.Clone(value), expiresAt: expiry(ttl)}
	return nil
}

func (s *ShardedMemory) Delete(_ context.Context, key string) error {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		delete(s.central.m, key)
		delete(s.central.activeBlocks, key)
		return nil
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	delete(sh.m, key)
	return nil
}

func (s *ShardedMemory) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.IncrBy(ctx, key, 1, ttl)
}

func (s *ShardedMemory) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	var deadline int64
	if ttl > 0 {
		deadline = time.Now().Add(ttl).UnixNano()
	}
	n, _, err := s.IncrByDeadline(ctx, key, delta, deadline)
	return n, err
}

func (s *ShardedMemory) IncrByDeadline(_ context.Context, key string, delta, deadline int64) (int64, bool, error) {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		return incrByDeadline(s.central.m, s.getCentral, key, delta, deadline)
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	get := func(k string) (entry, bool) { return getShard(sh.m, k) }
	return incrByDeadline(sh.m, get, key, delta, deadline)
}

// incrByDeadline is the shared IncrByDeadline body, parameterised over a map and
// its lazy-expire getter so the shard and central paths stay identical to
// Memory.IncrByDeadline (rules 2/3/4). The caller holds the relevant lock.
func incrByDeadline(m map[string]entry, get func(string) (entry, bool), key string, delta, deadline int64) (int64, bool, error) {
	now := time.Now()
	// (2) A flush delayed past its window's deadline is a no-op: it must not
	// create or extend a record for a window that has already ended.
	if deadline != 0 && now.UnixNano() >= deadline {
		if e, ok := get(key); ok {
			n, err := strconv.ParseInt(string(e.value), 10, 64)
			return n, false, err
		}
		return 0, false, nil
	}
	e, ok := get(key)
	if !ok {
		// (3) Fresh key: create at delta expiring exactly at the deadline.
		var exp time.Time
		if deadline != 0 {
			exp = time.Unix(0, deadline)
		}
		m[key] = entry{value: []byte(strconv.FormatInt(delta, 10)), expiresAt: exp}
		return delta, true, nil
	}
	// (4) Existing live key: add delta, keep the original expiry.
	n, err := strconv.ParseInt(string(e.value), 10, 64)
	if err != nil {
		return 0, false, err
	}
	n += delta
	e.value = []byte(strconv.FormatInt(n, 10))
	m[key] = e
	return n, true, nil
}

func (s *ShardedMemory) CompareAndSwap(_ context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		e, ok := s.getCentral(key)
		if old == nil {
			if ok {
				return false, nil
			}
		} else if !ok || !bytes.Equal(e.value, old) {
			return false, nil
		}
		s.central.m[key] = entry{value: bytes.Clone(new), expiresAt: expiry(ttl)}
		// A fenced block write is still a block write, so it indexes like Set
		// (store.go ActiveBlockScanner contract). Incr still must not.
		if strings.HasPrefix(key, "block:") {
			s.central.activeBlocks[key] = struct{}{}
		}
		return true, nil
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := getShard(sh.m, key)
	if old == nil {
		if ok {
			return false, nil
		}
	} else if !ok || !bytes.Equal(e.value, old) {
		return false, nil
	}
	sh.m[key] = entry{value: bytes.Clone(new), expiresAt: expiry(ttl)}
	return true, nil
}

func (s *ShardedMemory) CompareAndDelete(_ context.Context, key string, old []byte) (bool, error) {
	if old == nil {
		return false, nil // nothing to take back
	}
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		e, ok := s.getCentral(key)
		if !ok || !bytes.Equal(e.value, old) {
			return false, nil
		}
		delete(s.central.m, key)
		delete(s.central.activeBlocks, key)
		return true, nil
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := getShard(sh.m, key)
	if !ok || !bytes.Equal(e.value, old) {
		return false, nil
	}
	delete(sh.m, key)
	return true, nil
}

func (s *ShardedMemory) CommitBlock(_ context.Context, c BlockCommit) (BlockCommitResult, error) {
	if !isCentral(c.BlockKey) {
		return BlockCommitResult{}, fmt.Errorf("CommitBlock requires a block key, got %q", c.BlockKey)
	}
	s.central.mu.Lock()
	defer s.central.mu.Unlock()
	unlock := s.lockShardKeys(c.GuardKey, c.HoldKey, c.CounterKey)
	defer unlock()

	if _, held := getShard(s.shardFor(c.HoldKey).m, c.HoldKey); held {
		return BlockCommitResult{Refusal: BlockRefusalHold}, nil
	}
	guardShard := s.shardFor(c.GuardKey)
	guard, guardOK := getShard(guardShard.m, c.GuardKey)
	if c.GuardValue == nil {
		if guardOK {
			return BlockCommitResult{Refusal: BlockRefusalGeneration}, nil
		}
	} else if !guardOK || !bytes.Equal(guard.value, c.GuardValue) {
		return BlockCommitResult{Refusal: BlockRefusalGeneration}, nil
	}

	curBlock, blockOK := s.getCentral(c.BlockKey)
	if c.ExpectedBlock == nil {
		if blockOK {
			return BlockCommitResult{Refusal: BlockRefusalBlock}, nil
		}
	} else if !blockOK || !bytes.Equal(curBlock.value, c.ExpectedBlock) {
		return BlockCommitResult{Refusal: BlockRefusalBlock}, nil
	}

	counterShard := s.shardFor(c.CounterKey)
	curCounter, counterOK := getShard(counterShard.m, c.CounterKey)
	offenses := int64(1)
	var counterExpiry time.Time
	if counterOK {
		offenses = counterValue(curCounter.value) + 1
		counterExpiry = curCounter.expiresAt
	} else {
		counterExpiry = expiry(c.CounterTTL)
	}
	ttl := blockBackoffTTL(c.BaseTTL, c.MaxTTL, offenses)
	counterShard.m[c.CounterKey] = entry{
		value:     []byte(strconv.FormatInt(offenses, 10)),
		expiresAt: counterExpiry,
	}
	s.central.m[c.BlockKey] = entry{value: bytes.Clone(c.NewBlock), expiresAt: expiry(ttl)}
	s.central.activeBlocks[c.BlockKey] = struct{}{}
	return BlockCommitResult{Committed: true, Offenses: offenses, TTL: ttl}, nil
}

func (s *ShardedMemory) CommitEvent(_ context.Context, c EventCommit) (EventCommitResult, error) {
	holdShard := s.shardFor(c.HoldKey)
	counterShard := s.shardFor(c.CounterKey)
	if holdShard == counterShard {
		holdShard.mu.Lock()
		defer holdShard.mu.Unlock()
	} else {
		// Use the array order as the global shard-lock order. This hot path
		// avoids the allocating general-purpose lockShardKeys helper.
		holdIndex := int(fnv1a32(c.HoldKey) & s.mask)
		counterIndex := int(fnv1a32(c.CounterKey) & s.mask)
		if holdIndex > counterIndex {
			holdShard, counterShard = counterShard, holdShard
		}
		holdShard.mu.Lock()
		counterShard.mu.Lock()
		defer holdShard.mu.Unlock()
		defer counterShard.mu.Unlock()
		// Restore semantic names after ordering the locks.
		holdShard = s.shardFor(c.HoldKey)
		counterShard = s.shardFor(c.CounterKey)
	}
	if _, held := getShard(holdShard.m, c.HoldKey); held {
		return EventCommitResult{}, nil
	}
	deadline := int64(0)
	if c.CounterTTL > 0 {
		deadline = time.Now().Add(c.CounterTTL).UnixNano()
	}
	get := func(k string) (entry, bool) { return getShard(counterShard.m, k) }
	value, applied, err := incrByDeadline(counterShard.m, get, c.CounterKey, 1, deadline)
	return EventCommitResult{Committed: applied, Value: value}, err
}

func (s *ShardedMemory) CommitUnblock(_ context.Context, c UnblockCommit) error {
	if !isCentral(c.BlockKey) {
		return fmt.Errorf("CommitUnblock requires a block key, got %q", c.BlockKey)
	}
	s.central.mu.Lock()
	defer s.central.mu.Unlock()
	unlock := s.lockShardKeys(c.HoldKey, c.GenerationKey, c.CounterKey)
	defer unlock()

	holdShard := s.shardFor(c.HoldKey)
	holdShard.m[c.HoldKey] = entry{value: bytes.Clone(c.HoldValue), expiresAt: expiry(c.HoldTTL)}
	genShard := s.shardFor(c.GenerationKey)
	genShard.m[c.GenerationKey] = entry{
		value:     bytes.Clone(c.Generation),
		expiresAt: expiry(c.GenerationTTL),
	}
	delete(s.central.m, c.BlockKey)
	delete(s.central.activeBlocks, c.BlockKey)
	if c.ResetBackoff {
		delete(s.shardFor(c.CounterKey).m, c.CounterKey)
	}
	return nil
}

func (s *ShardedMemory) Scan(ctx context.Context, prefix string) ([]KV, error) {
	out, _, err := s.ScanLimit(ctx, prefix, 0)
	return out, err
}

// ScanLimit gathers matching live keys from every shard and the central map
// (one lock at a time — never two at once), then sorts globally. Because a
// global sort cannot early-exit per shard, limit over-collects and truncates
// after sorting. Admin/reporting only, so the fan-out cost is acceptable.
func (s *ShardedMemory) ScanLimit(_ context.Context, prefix string, limit int) ([]KV, bool, error) {
	now := time.Now()
	var out []KV
	gather := func(m map[string]entry) {
		for k, e := range m {
			if !strings.HasPrefix(k, prefix) || e.expired(now) {
				continue
			}
			out = append(out, KV{Key: k, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt})
		}
	}
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		gather(sh.m)
		sh.mu.Unlock()
	}
	s.central.mu.Lock()
	gather(s.central.m)
	s.central.mu.Unlock()

	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	if limit > 0 && len(out) > limit {
		return out[:limit], false, nil
	}
	return out, true, nil
}

// ScanActiveBlocks walks only the central block index, so its cost is
// independent of unrelated (sharded) keys. Verbatim Memory.ScanActiveBlocks.
func (s *ShardedMemory) ScanActiveBlocks(_ context.Context, prefix string, limit int) ([]KV, bool, error) {
	if prefix != "block:" {
		return nil, false, ErrCapabilityUnsupported
	}
	s.central.mu.Lock()
	defer s.central.mu.Unlock()
	now := time.Now()
	size := len(s.central.activeBlocks)
	if limit > 0 {
		size = min(size, limit)
	}
	out := make([]KV, 0, size)
	complete := true
	for key := range s.central.activeBlocks {
		e, ok := s.central.m[key]
		if !ok || e.expired(now) {
			delete(s.central.activeBlocks, key)
			delete(s.central.m, key)
			continue
		}
		out = append(out, KV{Key: key, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
			complete = false
			break
		}
	}
	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	return out, complete, nil
}

func (s *ShardedMemory) SetPostureVote(_ context.Context, instanceID string, level int, ttl time.Duration) error {
	if level < 1 || level > 2 || ttl <= 0 {
		return fmt.Errorf("invalid posture vote level=%d ttl=%v", level, ttl)
	}
	s.central.mu.Lock()
	defer s.central.mu.Unlock()
	s.central.postureVotes[instanceID] = postureVote{level: level, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *ShardedMemory) DeletePostureVote(_ context.Context, instanceID string) error {
	s.central.mu.Lock()
	defer s.central.mu.Unlock()
	delete(s.central.postureVotes, instanceID)
	return nil
}

func (s *ShardedMemory) MaxPostureVote(_ context.Context, excludeInstanceID string) (int, error) {
	s.central.mu.Lock()
	defer s.central.mu.Unlock()
	now := time.Now()
	maxLevel := 0
	for id, vote := range s.central.postureVotes {
		if !vote.expiresAt.IsZero() && now.After(vote.expiresAt) {
			delete(s.central.postureVotes, id)
			continue
		}
		if id != excludeInstanceID && vote.level > maxLevel {
			maxLevel = vote.level
		}
	}
	return maxLevel, nil
}

// Close stops the janitor. Idempotent: extra calls are no-ops.
func (s *ShardedMemory) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	return nil
}

// ExpiresAt returns the expiry of a live key and whether it exists, mirroring
// Memory.ExpiresAt for parity tests.
func (s *ShardedMemory) ExpiresAt(key string) (time.Time, bool) {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		e, ok := s.getCentral(key)
		if !ok {
			return time.Time{}, false
		}
		return e.expiresAt, true
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := getShard(sh.m, key)
	if !ok {
		return time.Time{}, false
	}
	return e.expiresAt, true
}
