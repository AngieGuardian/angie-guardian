// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/pebble/v2"
)

// Pebble is a store.Store backed by CockroachDB's Pebble LSM engine. Pebble has
// no native TTL, CAS or atomic increment, so this adapter emulates all three:
//
//   - TTL: every value is prefixed with an 8-byte big-endian unix-nanos expiry
//     (0 = permanent); a key whose expiry has passed reads as absent.
//   - CAS / IncrByDeadline: serialized per key by a sharded application mutex,
//     since Pebble offers no conditional/atomic read-modify-write (Merge cannot
//     express compare-and-set). All writers to a key take the same shard lock,
//     so the Get+Set critical section is atomic within this process. This is a
//     single-node primitive: the DB directory is exclusively locked, so a second
//     process cannot open it, and cross-instance single-spend is the fleet
//     store's job, not this one's.
//
// Prefix Scan uses a bounded, natively-sorted iterator (no post-sort).
//
// Because expiry is read-time only, a janitor sweeps the keyspace periodically
// and physically deletes expired records; without it every challenge, spent
// marker and counter would live on disk forever and scans would degrade as
// they skip an ever-growing corpse pile.
type Pebble struct {
	db        *pebble.DB
	writeOpts *pebble.WriteOptions
	locks     shardLocks

	done      chan struct{}
	janitorWG sync.WaitGroup
	closeOnce sync.Once
}

// PebbleOptions selects the durability profile.
type PebbleOptions struct {
	// Sync fsyncs the WAL on every write (durable, slower). When false, writes
	// are appended to the WAL but not fsynced (fast; a power/OS crash loses the
	// unflushed tail, acceptable for the bounded <=TTL replay window).
	Sync bool
}

// NewPebble opens (or creates) a Pebble store at dir.
func NewPebble(dir string, opts PebbleOptions) (*Pebble, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: pebbleNoopLogger{}})
	if err != nil {
		return nil, err
	}
	wo := pebble.NoSync
	if opts.Sync {
		wo = pebble.Sync
	}
	p := &Pebble{db: db, writeOpts: wo, locks: newShardLocks(), done: make(chan struct{})}
	p.janitorWG.Add(1)
	go p.janitor()
	return p, nil
}

// pebbleJanitorInterval paces the expired-record sweep. Each sweep is a full
// keyspace iteration, but with the janitor running the keyspace stays bounded
// by live records plus at most one interval's worth of freshly expired ones.
const pebbleJanitorInterval = time.Minute

func (p *Pebble) janitor() {
	defer p.janitorWG.Done()
	ticker := time.NewTicker(pebbleJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.sweepExpired()
		}
	}
}

// sweepExpired physically deletes every record whose expiry has passed. Each
// candidate is re-checked under its shard lock before deletion, since it may
// have been rewritten live after the iterator snapshot. Deletes are unsynced
// on purpose: losing one to a crash only re-exposes an expired record, which
// reads as absent anyway and is re-collected by the next sweep.
func (p *Pebble) sweepExpired() {
	iter, err := p.db.NewIter(nil)
	if err != nil {
		return
	}
	var expired [][]byte
	now := time.Now().UnixNano()
	for iter.First(); iter.Valid(); iter.Next() {
		exp, _, ok := splitExpiry(iter.Value())
		if !ok || (exp != 0 && exp <= now) {
			expired = append(expired, append([]byte(nil), iter.Key()...))
		}
	}
	_ = iter.Close()
	for _, key := range expired {
		unlock := p.locks.lock(key)
		if _, _, ok, err := p.getExpiry(key); err == nil && !ok {
			_ = p.db.Delete(key, pebble.NoSync)
		}
		unlock()
	}
}

func (p *Pebble) Get(_ context.Context, key string) ([]byte, bool, error) {
	return p.get([]byte(key))
}

// get reads and expiry-decodes a key. The Pebble value slice and its closer are
// only valid until Close, so the payload is copied out first.
func (p *Pebble) get(key []byte) ([]byte, bool, error) {
	raw, closer, err := p.db.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	val := append([]byte(nil), raw...)
	_ = closer.Close()
	payload, ok := decodeExpiry(val)
	if !ok {
		return nil, false, nil
	}
	return payload, true, nil
}

func (p *Pebble) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	kb := []byte(key)
	// Take the key's shard lock so a Set cannot land between the read and write
	// of a concurrent CompareAndSwap/IncrByDeadline on the same key (which would
	// let that CAS succeed against a value this Set already replaced). Every
	// mutation for a key must serialize through the same lock.
	unlock := p.locks.lock(kb)
	defer unlock()
	return p.db.Set(kb, encodeExpiry(value, ttl), p.writeOpts)
}

func (p *Pebble) Delete(_ context.Context, key string) error {
	kb := []byte(key)
	unlock := p.locks.lock(kb)
	defer unlock()
	return p.db.Delete(kb, p.writeOpts)
}

func (p *Pebble) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return p.IncrBy(ctx, key, 1, ttl)
}

func (p *Pebble) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	var deadline int64
	if ttl > 0 {
		deadline = time.Now().Add(ttl).UnixNano()
	}
	n, _, err := p.IncrByDeadline(ctx, key, delta, deadline)
	return n, err
}

func (p *Pebble) IncrByDeadline(_ context.Context, key string, delta, deadline int64) (int64, bool, error) {
	kb := []byte(key)
	unlock := p.locks.lock(kb)
	defer unlock()
	return incrByDeadlineEmulated(p.getExpiry, p.setDeadline, kb, delta, deadline)
}

// getExpiry is get plus the stored expiry (unix nanos, 0 = permanent).
func (p *Pebble) getExpiry(key []byte) ([]byte, int64, bool, error) {
	raw, closer, err := p.db.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	val := append([]byte(nil), raw...)
	_ = closer.Close()
	exp, payload, ok := splitExpiry(val)
	if !ok || (exp != 0 && exp <= time.Now().UnixNano()) {
		return nil, 0, false, nil
	}
	return payload, exp, true, nil
}

// setDeadline writes value expiring at an absolute unix-nanos deadline.
func (p *Pebble) setDeadline(key, value []byte, deadline int64) error {
	return p.db.Set(key, encodeExpiryDeadline(value, deadline), p.writeOpts)
}

func (p *Pebble) CompareAndSwap(_ context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	kb := []byte(key)
	unlock := p.locks.lock(kb)
	defer unlock()
	return compareAndSwapEmulated(p.get, p.rawSet, kb, old, new, ttl)
}

func (p *Pebble) CompareAndDelete(_ context.Context, key string, old []byte) (bool, error) {
	kb := []byte(key)
	unlock := p.locks.lock(kb)
	defer unlock()
	del := func(k []byte) error { return p.db.Delete(k, p.writeOpts) }
	return compareAndDeleteEmulated(p.get, del, kb, old)
}

func (p *Pebble) CommitBlock(_ context.Context, c BlockCommit) (BlockCommitResult, error) {
	blockKey := []byte(c.BlockKey)
	counterKey := []byte(c.CounterKey)
	guardKey := []byte(c.GuardKey)
	holdKey := []byte(c.HoldKey)
	unlock := p.locks.lockMany(blockKey, counterKey, guardKey, holdKey)
	defer unlock()

	if _, holdOK, err := p.get(holdKey); err != nil {
		return BlockCommitResult{}, err
	} else if holdOK {
		return BlockCommitResult{Refusal: BlockRefusalHold}, nil
	}
	guard, guardOK, err := p.get(guardKey)
	if err != nil {
		return BlockCommitResult{}, err
	}
	if c.GuardValue == nil {
		if guardOK {
			return BlockCommitResult{Refusal: BlockRefusalGeneration}, nil
		}
	} else if !guardOK || !bytesEqual(guard, c.GuardValue) {
		return BlockCommitResult{Refusal: BlockRefusalGeneration}, nil
	}
	block, blockOK, err := p.get(blockKey)
	if err != nil {
		return BlockCommitResult{}, err
	}
	if c.ExpectedBlock == nil {
		if blockOK {
			return BlockCommitResult{Refusal: BlockRefusalBlock}, nil
		}
	} else if !blockOK || !bytesEqual(block, c.ExpectedBlock) {
		return BlockCommitResult{Refusal: BlockRefusalBlock}, nil
	}

	counter, counterExpiry, counterOK, err := p.getExpiry(counterKey)
	if err != nil {
		return BlockCommitResult{}, err
	}
	offenses := int64(1)
	if counterOK {
		offenses = counterValue(counter) + 1
	} else if c.CounterTTL > 0 {
		counterExpiry = time.Now().Add(c.CounterTTL).UnixNano()
	}
	ttl := blockBackoffTTL(c.BaseTTL, c.MaxTTL, offenses)

	batch := p.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(counterKey,
		encodeExpiryDeadline([]byte(strconv.FormatInt(offenses, 10)), counterExpiry), nil); err != nil {
		return BlockCommitResult{}, err
	}
	if err := batch.Set(blockKey, encodeExpiry(c.NewBlock, ttl), nil); err != nil {
		return BlockCommitResult{}, err
	}
	if err := batch.Commit(p.writeOpts); err != nil {
		return BlockCommitResult{}, err
	}
	return BlockCommitResult{Committed: true, Offenses: offenses, TTL: ttl}, nil
}

func (p *Pebble) CommitEvent(_ context.Context, c EventCommit) (EventCommitResult, error) {
	counterKey := []byte(c.CounterKey)
	holdKey := []byte(c.HoldKey)
	unlock := p.locks.lockMany(counterKey, holdKey)
	defer unlock()

	if _, holdOK, err := p.get(holdKey); err != nil {
		return EventCommitResult{}, err
	} else if holdOK {
		return EventCommitResult{}, nil
	}
	counter, counterExpiry, counterOK, err := p.getExpiry(counterKey)
	if err != nil {
		return EventCommitResult{}, err
	}
	value := int64(1)
	if counterOK {
		value = counterValue(counter) + 1
	} else if c.CounterTTL > 0 {
		counterExpiry = time.Now().Add(c.CounterTTL).UnixNano()
	}
	if err := p.setDeadline(counterKey, []byte(strconv.FormatInt(value, 10)), counterExpiry); err != nil {
		return EventCommitResult{}, err
	}
	return EventCommitResult{Committed: true, Value: value}, nil
}

func (p *Pebble) CommitUnblock(_ context.Context, c UnblockCommit) error {
	holdKey := []byte(c.HoldKey)
	generationKey := []byte(c.GenerationKey)
	blockKey := []byte(c.BlockKey)
	counterKey := []byte(c.CounterKey)
	unlock := p.locks.lockMany(holdKey, generationKey, blockKey, counterKey)
	defer unlock()

	batch := p.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(holdKey, encodeExpiry(c.HoldValue, c.HoldTTL), nil); err != nil {
		return err
	}
	if err := batch.Set(generationKey, encodeExpiry(c.Generation, c.GenerationTTL), nil); err != nil {
		return err
	}
	if err := batch.Delete(blockKey, nil); err != nil {
		return err
	}
	if c.ResetBackoff {
		if err := batch.Delete(counterKey, nil); err != nil {
			return err
		}
	}
	return batch.Commit(p.writeOpts)
}

// rawSet writes an already-formed value with the given TTL under the caller's
// shard lock (used by the emulated CAS/incr helpers).
func (p *Pebble) rawSet(key, value []byte, ttl time.Duration) error {
	return p.db.Set(key, encodeExpiry(value, ttl), p.writeOpts)
}

func (p *Pebble) Scan(ctx context.Context, prefix string) ([]KV, error) {
	out, _, err := p.ScanLimit(ctx, prefix, 0)
	return out, err
}

// ScanLimit returns up to limit live keys with the prefix, in sorted order.
// complete is false when more matching keys exist beyond limit. Pebble's
// iterator is natively sorted, so results need no post-sort.
func (p *Pebble) ScanLimit(_ context.Context, prefix string, limit int) ([]KV, bool, error) {
	iter, err := p.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(prefix),
		UpperBound: prefixUpperBound([]byte(prefix)),
	})
	if err != nil {
		return nil, false, err
	}
	defer iter.Close()
	now := time.Now().UnixNano()
	var out []KV
	for iter.First(); iter.Valid(); iter.Next() {
		exp, payload, ok := splitExpiry(iter.Value())
		if !ok || (exp != 0 && exp <= now) {
			continue
		}
		if limit > 0 && len(out) == limit {
			return out, false, iter.Error() // more matches exist
		}
		out = append(out, KV{
			Key:       string(append([]byte(nil), iter.Key()...)),
			Value:     append([]byte(nil), payload...),
			ExpiresAt: expiryTime(exp),
		})
	}
	return out, true, iter.Error()
}

// ScanActiveBlocks reuses the sorted prefix scan: the block-key range is
// contiguous, so this visits only those keys, not the whole keyspace.
func (p *Pebble) ScanActiveBlocks(ctx context.Context, prefix string, limit int) ([]KV, bool, error) {
	return p.ScanLimit(ctx, prefix, limit)
}

// SetPostureVote / DeletePostureVote / MaxPostureVote implement the fleet
// posture primitive over the general keyspace, under a reserved prefix.
func (p *Pebble) SetPostureVote(ctx context.Context, instanceID string, level int, ttl time.Duration) error {
	return setPostureVoteVia(ctx, p, instanceID, level, ttl)
}
func (p *Pebble) DeletePostureVote(ctx context.Context, instanceID string) error {
	return p.Delete(ctx, postureVoteKey(instanceID))
}
func (p *Pebble) MaxPostureVote(ctx context.Context, excludeInstanceID string) (int, error) {
	return maxPostureVoteVia(ctx, p, excludeInstanceID)
}

// Close stops the janitor and closes the DB. Idempotent: extra calls are no-ops.
func (p *Pebble) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.done)
		p.janitorWG.Wait()
		err = p.db.Close()
	})
	return err
}

// pebbleNoopLogger silences Pebble's internal info/fatal logging, which would
// otherwise print operational lines (e.g. "Found 0 WALs") to stderr.
type pebbleNoopLogger struct{}

func (pebbleNoopLogger) Infof(string, ...any)  {}
func (pebbleNoopLogger) Errorf(string, ...any) {}
func (pebbleNoopLogger) Fatalf(string, ...any) {}

// --- shared posture-vote helpers (built on the Store surface) ---

// posturePrefix namespaces fleet posture votes within the general keyspace. It
// is chosen to be distinct from block:/challenge:/spent1:/counter keys.
const posturePrefix = "guardian-posture:"

func postureVoteKey(instanceID string) string { return posturePrefix + instanceID }

// setPostureVoteVia stores one instance's posture vote (level 1..2) with a TTL,
// via a store's Set. Shared by the durable backends that keep votes in the
// general keyspace rather than a dedicated bucket.
func setPostureVoteVia(ctx context.Context, s Store, instanceID string, level int, ttl time.Duration) error {
	if level < 1 || level > 2 || ttl <= 0 {
		return fmt.Errorf("invalid posture vote level=%d ttl=%v", level, ttl)
	}
	return s.Set(ctx, postureVoteKey(instanceID), []byte{byte(level)}, ttl)
}

// maxPostureVoteVia returns the highest live posture level excluding the caller's
// own instance, via a prefix Scan (expired votes are already filtered by TTL).
func maxPostureVoteVia(ctx context.Context, s Store, excludeInstanceID string) (int, error) {
	kvs, err := s.Scan(ctx, posturePrefix)
	if err != nil {
		return 0, err
	}
	exclude := postureVoteKey(excludeInstanceID)
	maxLevel := 0
	for _, kv := range kvs {
		if kv.Key == exclude || len(kv.Value) != 1 {
			continue
		}
		if lvl := int(kv.Value[0]); lvl > maxLevel {
			maxLevel = lvl
		}
	}
	return maxLevel, nil
}

// --- shared helpers for the emulated-TTL / emulated-CAS backends ---

// encodeExpiry prefixes value with an 8-byte big-endian unix-nanos deadline
// (0 = permanent) derived from ttl.
func encodeExpiry(value []byte, ttl time.Duration) []byte {
	var exp uint64
	if ttl > 0 {
		exp = uint64(time.Now().Add(ttl).UnixNano())
	}
	buf := make([]byte, 8+len(value))
	binary.BigEndian.PutUint64(buf[:8], exp)
	copy(buf[8:], value)
	return buf
}

// splitExpiry separates the expiry prefix from the payload without a copy. ok is
// false for a malformed (too-short) record.
func splitExpiry(raw []byte) (exp int64, payload []byte, ok bool) {
	if len(raw) < 8 {
		return 0, nil, false
	}
	return int64(binary.BigEndian.Uint64(raw[:8])), raw[8:], true
}

// decodeExpiry returns the payload of a stored value, or ok=false if the record
// is malformed or already expired.
func decodeExpiry(raw []byte) ([]byte, bool) {
	exp, payload, ok := splitExpiry(raw)
	if !ok {
		return nil, false
	}
	if exp != 0 && exp <= time.Now().UnixNano() {
		return nil, false
	}
	return payload, true
}

// expiryTime converts a stored unix-nanos deadline (0 = permanent) to a KV
// ExpiresAt time.
func expiryTime(exp int64) time.Time {
	if exp == 0 {
		return time.Time{}
	}
	return time.Unix(0, exp)
}

// prefixUpperBound returns the smallest key strictly greater than any key with
// the given prefix, or nil (unbounded) when the prefix is empty or all 0xff.
func prefixUpperBound(prefix []byte) []byte {
	end := append([]byte(nil), prefix...)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xff {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}

// shardLocks is a fixed set of mutexes; a key hashes to one, so writers to the
// same key serialize while unrelated keys proceed in parallel. Used by the
// backends that must emulate atomic CAS/incr in the application layer.
type shardLocks struct {
	mus  []sync.Mutex
	mask uint32
}

func newShardLocks() shardLocks {
	const n = 256
	return shardLocks{mus: make([]sync.Mutex, n), mask: n - 1}
}

func (s *shardLocks) lock(key []byte) func() {
	mu := &s.mus[fnv1a32(string(key))&s.mask]
	mu.Lock()
	return mu.Unlock
}

func (s *shardLocks) lockMany(keys ...[]byte) func() {
	idxs := make([]int, 0, len(keys))
	for _, key := range keys {
		idxs = append(idxs, int(fnv1a32(string(key))&s.mask))
	}
	slices.Sort(idxs)
	idxs = slices.Compact(idxs)
	for _, idx := range idxs {
		s.mus[idx].Lock()
	}
	return func() {
		for i := len(idxs) - 1; i >= 0; i-- {
			s.mus[idxs[i]].Unlock()
		}
	}
}

// getFunc / rawSetFunc are the read + raw-write primitives the emulated helpers
// compose, so Pebble and goleveldb share one CAS/incr implementation.
type getFunc func(key []byte) ([]byte, bool, error)
type rawSetFunc func(key, value []byte, ttl time.Duration) error

// getExpiryFunc reads a key and also reports its stored expiry as unix nanos
// (0 = permanent), so IncrByDeadline can preserve an existing live key's window.
type getExpiryFunc func(key []byte) (value []byte, exp int64, ok bool, err error)

// rawSetDeadlineFunc writes a value expiring at an absolute unix-nanos deadline
// (0 = permanent), so a preserved expiry is written back exactly, not re-derived.
type rawSetDeadlineFunc func(key, value []byte, deadline int64) error

// compareAndSwapEmulated implements store.CompareAndSwap for a backend with no
// atomic RMW. The caller must already hold the key's shard lock.
func compareAndSwapEmulated(get getFunc, set rawSetFunc, key, old, new []byte, ttl time.Duration) (bool, error) {
	cur, ok, err := get(key)
	if err != nil {
		return false, err
	}
	if old == nil {
		if ok {
			return false, nil
		}
	} else if !ok || !bytesEqual(cur, old) {
		return false, nil
	}
	if err := set(key, new, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// rawDeleteFunc removes a key outright, the primitive compareAndDeleteEmulated
// composes with a read.
type rawDeleteFunc func(key []byte) error

// compareAndDeleteEmulated implements store.CompareAndDelete for a backend with
// no atomic RMW. The caller must already hold the key's shard lock.
func compareAndDeleteEmulated(get getFunc, del rawDeleteFunc, key, old []byte) (bool, error) {
	if old == nil {
		return false, nil // nothing to take back
	}
	cur, ok, err := get(key)
	if err != nil {
		return false, err
	}
	if !ok || !bytesEqual(cur, old) {
		return false, nil
	}
	if err := del(key); err != nil {
		return false, err
	}
	return true, nil
}

// incrByDeadlineEmulated implements store.IncrByDeadline (rules 2/3/4) for a
// backend with no atomic RMW. The caller must already hold the key's shard lock.
// get reports the stored expiry so a live key keeps its original window; set
// writes an absolute deadline so that preserved window is written back exactly.
func incrByDeadlineEmulated(get getExpiryFunc, set rawSetDeadlineFunc, key []byte, delta, deadline int64) (int64, bool, error) {
	now := time.Now().UnixNano()
	cur, storedExp, ok, err := get(key)
	if err != nil {
		return 0, false, err
	}
	// (2) Deadline already past: no write; report current value (0 if absent).
	if deadline != 0 && now >= deadline {
		if !ok {
			return 0, false, nil
		}
		n, perr := strconv.ParseInt(string(cur), 10, 64)
		return n, false, perr
	}
	if !ok {
		// (3) Fresh key: create at delta expiring exactly at the deadline.
		if err := set(key, []byte(strconv.FormatInt(delta, 10)), deadline); err != nil {
			return 0, false, err
		}
		return delta, true, nil
	}
	// (4) Existing live key: add delta, preserving its existing expiry.
	n, perr := strconv.ParseInt(string(cur), 10, 64)
	if perr != nil {
		return 0, false, perr
	}
	n += delta
	if err := set(key, []byte(strconv.FormatInt(n, 10)), storedExp); err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// encodeExpiryDeadline is encodeExpiry given an absolute unix-nanos deadline
// (0 = permanent) instead of a relative TTL.
func encodeExpiryDeadline(value []byte, deadline int64) []byte {
	buf := make([]byte, 8+len(value))
	if deadline < 0 {
		deadline = 0
	}
	binary.BigEndian.PutUint64(buf[:8], uint64(deadline))
	copy(buf[8:], value)
	return buf
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
