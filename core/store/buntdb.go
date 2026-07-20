// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/buntdb"
)

// BuntDB is a store.Store backed by tidwall/buntdb (in-memory index with an
// append-only file). It is single-writer: every write runs inside an exclusive
// db.Update transaction, so Get+Set within one Update is atomic and CAS/incr need
// no extra locking, but concurrent writes serialize (the throughput ceiling under
// a flood). Values are base64-encoded because BuntDB stores strings and its AOF
// is a text format: raw control bytes (e.g. []byte{1}) would corrupt reload.
// TTL is a duration; a live key's expiry is preserved by reading tx.TTL first.
// Single-node only.
type BuntDB struct {
	db *buntdb.DB
}

// BuntDBOptions selects the durability profile.
type BuntDBOptions struct {
	// Sync fsyncs on every commit (SyncPolicy Always, durable). When false, uses
	// SyncPolicy EverySecond (~1s durability window, much faster under a flood).
	Sync bool
}

// NewBuntDB opens (or creates) a BuntDB store at path. Pass ":memory:" for a
// non-persistent store.
func NewBuntDB(path string, opts BuntDBOptions) (*BuntDB, error) {
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, err
	}
	var cfg buntdb.Config
	if err := db.ReadConfig(&cfg); err != nil {
		_ = db.Close()
		return nil, err
	}
	if opts.Sync {
		cfg.SyncPolicy = buntdb.Always
	} else {
		cfg.SyncPolicy = buntdb.EverySecond
	}
	// A shrink pass rewriting the AOF mid-run would skew benchmarks; disable it.
	cfg.AutoShrinkDisabled = true
	if err := db.SetConfig(cfg); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BuntDB{db: db}, nil
}

var buntEnc = base64.RawStdEncoding

func buntEncode(v []byte) string { return buntEnc.EncodeToString(v) }
func buntDecode(s string) []byte {
	b, err := buntEnc.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// setOpts builds the TTL options for a relative duration (nil = no expiry).
func setOpts(ttl time.Duration) *buntdb.SetOptions {
	if ttl <= 0 {
		return nil
	}
	return &buntdb.SetOptions{Expires: true, TTL: ttl}
}

func (b *BuntDB) Get(_ context.Context, key string) ([]byte, bool, error) {
	var out []byte
	var found bool
	err := b.db.View(func(tx *buntdb.Tx) error {
		v, err := tx.Get(key)
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		out = buntDecode(v)
		found = true
		return nil
	})
	return out, found, err
}

func (b *BuntDB) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	return b.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, buntEncode(value), setOpts(ttl))
		return err
	})
}

func (b *BuntDB) Delete(_ context.Context, key string) error {
	return b.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil
		}
		return err
	})
}

func (b *BuntDB) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return b.IncrBy(ctx, key, 1, ttl)
}

func (b *BuntDB) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	var deadline int64
	if ttl > 0 {
		deadline = time.Now().Add(ttl).UnixNano()
	}
	v, _, err := b.IncrByDeadline(ctx, key, delta, deadline)
	return v, err
}

func (b *BuntDB) IncrByDeadline(_ context.Context, key string, delta, deadline int64) (int64, bool, error) {
	var out int64
	var applied bool
	err := b.db.Update(func(tx *buntdb.Tx) error {
		now := time.Now().UnixNano()
		cur, err := tx.Get(key)
		found := true
		if errors.Is(err, buntdb.ErrNotFound) {
			found = false
		} else if err != nil {
			return err
		}
		// (2) Deadline already past: no write; report current (0 if absent).
		if deadline != 0 && now >= deadline {
			if found {
				out, err = strconv.ParseInt(string(buntDecode(cur)), 10, 64)
				if err != nil {
					return err
				}
			}
			return nil
		}
		if !found {
			// (3) Fresh key: create at delta expiring at the deadline.
			out = delta
			applied = true
			_, _, err := tx.Set(key, buntEncode([]byte(strconv.FormatInt(delta, 10))), deadlineOpts(deadline, now))
			return err
		}
		// (4) Existing live key: add delta, keep its existing expiry. BuntDB TTL
		// is a duration, so read the remaining TTL and reuse it verbatim.
		v, err := strconv.ParseInt(string(buntDecode(cur)), 10, 64)
		if err != nil {
			return err
		}
		out = v + delta
		applied = true
		opts, err := preservedOpts(tx, key)
		if err != nil {
			return err
		}
		_, _, err = tx.Set(key, buntEncode([]byte(strconv.FormatInt(out, 10))), opts)
		return err
	})
	if err != nil {
		return 0, false, err
	}
	return out, applied, nil
}

// deadlineOpts builds SetOptions expiring at an absolute unix-nanos deadline
// (0 = no expiry).
func deadlineOpts(deadline, now int64) *buntdb.SetOptions {
	if deadline == 0 {
		return nil
	}
	return setOpts(time.Duration(deadline - now))
}

// preservedOpts reads a key's current remaining TTL and returns SetOptions that
// reapply it, so an update keeps the original expiry (BuntDB otherwise clears it
// when opts is nil). Returns nil (no expiry) when the key is persistent.
func preservedOpts(tx *buntdb.Tx, key string) (*buntdb.SetOptions, error) {
	d, err := tx.TTL(key)
	if err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if d < 0 { // -1 == no expiry
		return nil, nil
	}
	return &buntdb.SetOptions{Expires: true, TTL: d}, nil
}

func (b *BuntDB) CompareAndSwap(_ context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	var swapped bool
	err := b.db.Update(func(tx *buntdb.Tx) error {
		cur, err := tx.Get(key)
		exists := true
		if errors.Is(err, buntdb.ErrNotFound) {
			exists = false
		} else if err != nil {
			return err
		}
		if old == nil {
			if exists {
				return nil // create-only: key present, no swap
			}
		} else if !exists || !bytesEqual(buntDecode(cur), old) {
			return nil
		}
		swapped = true
		_, _, err = tx.Set(key, buntEncode(new), setOpts(ttl))
		return err
	})
	return swapped, err
}

func (b *BuntDB) Scan(ctx context.Context, prefix string) ([]KV, error) {
	out, _, err := b.ScanLimit(ctx, prefix, 0)
	return out, err
}

// ScanLimit returns up to limit live keys with the prefix, sorted ascending
// (BuntDB iterates its key index in order). complete is false when more matching
// keys exist beyond limit.
func (b *BuntDB) ScanLimit(_ context.Context, prefix string, limit int) ([]KV, bool, error) {
	var out []KV
	complete := true
	err := b.db.View(func(tx *buntdb.Tx) error {
		var iterErr error
		err := tx.AscendGreaterOrEqual("", prefix, func(k, v string) bool {
			if !strings.HasPrefix(k, prefix) {
				return false // past the prefix range; stop
			}
			if limit > 0 && len(out) == limit {
				complete = false
				return false // more matches exist beyond the limit
			}
			var d time.Duration
			d, iterErr = tx.TTL(k)
			if iterErr != nil && !errors.Is(iterErr, buntdb.ErrNotFound) {
				return false
			}
			iterErr = nil
			var exp time.Time
			if d > 0 {
				exp = time.Now().Add(d)
			}
			out = append(out, KV{Key: k, Value: buntDecode(v), ExpiresAt: exp})
			return true
		})
		if err != nil {
			return err
		}
		return iterErr
	})
	return out, complete, err
}

// ScanActiveBlocks reuses the sorted prefix scan over the contiguous block-key
// range, so it does not walk the whole keyspace.
func (b *BuntDB) ScanActiveBlocks(ctx context.Context, prefix string, limit int) ([]KV, bool, error) {
	return b.ScanLimit(ctx, prefix, limit)
}

func (b *BuntDB) SetPostureVote(ctx context.Context, instanceID string, level int, ttl time.Duration) error {
	return setPostureVoteVia(ctx, b, instanceID, level, ttl)
}
func (b *BuntDB) DeletePostureVote(ctx context.Context, instanceID string) error {
	return b.Delete(ctx, postureVoteKey(instanceID))
}
func (b *BuntDB) MaxPostureVote(ctx context.Context, excludeInstanceID string) (int, error) {
	return maxPostureVoteVia(ctx, b, excludeInstanceID)
}

func (b *BuntDB) Close() error { return b.db.Close() }
