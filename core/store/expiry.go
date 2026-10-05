// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/redis/go-redis/v9"
	"github.com/tidwall/buntdb"
)

// ExpiryReader reads a value and its deadline from the same backend snapshot.
// Absent or expired keys return ok=false. A live permanent key has a zero
// ExpiresAt. Returned bytes are owned by the caller. This optional capability
// lets local caches preserve expiry without changing the Store contract.
type ExpiryReader interface {
	GetWithExpiry(context.Context, string) (KV, bool, error)
}

var _ = []ExpiryReader{(*ShardedMemory)(nil), (*BuntDB)(nil), (*Pebble)(nil), (*Redis)(nil), (*Instrumented)(nil)}

func (s *ShardedMemory) GetWithExpiry(_ context.Context, key string) (KV, bool, error) {
	if isCentral(key) {
		s.central.mu.Lock()
		defer s.central.mu.Unlock()
		e, ok := s.getCentral(key)
		if !ok {
			return KV{}, false, nil
		}
		return KV{Key: key, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt}, true, nil
	}
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := getShard(sh.m, key)
	if !ok {
		return KV{}, false, nil
	}
	return KV{Key: key, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt}, true, nil
}

func (b *BuntDB) GetWithExpiry(_ context.Context, key string) (KV, bool, error) {
	start := time.Now()
	var kv KV
	var found bool
	err := b.db.View(func(tx *buntdb.Tx) error {
		raw, err := tx.Get(key)
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		ttl, err := tx.TTL(key)
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		kv = KV{Key: key, Value: buntDecode(raw)}
		if ttl >= 0 {
			kv.ExpiresAt = start.Add(ttl)
		}
		found = kv.ExpiresAt.IsZero() || kv.ExpiresAt.After(time.Now())
		return nil
	})
	return kv, found, err
}

func (p *Pebble) GetWithExpiry(_ context.Context, key string) (KV, bool, error) {
	raw, closer, err := p.db.Get([]byte(key))
	if errors.Is(err, pebble.ErrNotFound) {
		return KV{}, false, nil
	}
	if err != nil {
		return KV{}, false, err
	}
	defer closer.Close()
	exp, payload, ok := splitExpiry(raw)
	if !ok || (exp != 0 && exp <= time.Now().UnixNano()) {
		return KV{}, false, nil
	}
	return KV{Key: key, Value: bytes.Clone(payload), ExpiresAt: expiryTime(exp)}, true, nil
}

// GET and PTTL must refer to the same version of the key, not separate reads
// around another replica's SET. A zero PTTL is too close to expiry to reuse.
var redisGetWithExpiry = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return {} end
local ttl = redis.call('PTTL', KEYS[1])
if ttl == -2 or ttl == 0 then return {} end
return {value, ttl}
`)

func (s *Redis) GetWithExpiry(ctx context.Context, key string) (KV, bool, error) {
	start := time.Now()
	reply, err := redisGetWithExpiry.Run(ctx, s.rdb, []string{key}).Slice()
	if err != nil {
		return KV{}, false, err
	}
	if len(reply) == 0 {
		return KV{}, false, nil
	}
	if len(reply) != 2 {
		return KV{}, false, errors.New("invalid expiry read response")
	}
	raw, ok := reply[0].(string)
	ttl, ttlOK := reply[1].(int64)
	if !ok || !ttlOK || ttl < -1 {
		return KV{}, false, errors.New("invalid expiry read response")
	}
	kv := KV{Key: key, Value: []byte(raw)}
	if ttl >= 0 {
		kv.ExpiresAt = start.Add(time.Duration(ttl) * time.Millisecond)
	}
	if !kv.ExpiresAt.IsZero() && !kv.ExpiresAt.After(time.Now()) {
		return KV{}, false, nil
	}
	return kv, true, nil
}

func (s *Instrumented) GetWithExpiry(ctx context.Context, key string) (KV, bool, error) {
	inner, ok := s.inner.(ExpiryReader)
	if !ok {
		return KV{}, false, ErrCapabilityUnsupported
	}
	start := time.Now()
	kv, found, err := inner.GetWithExpiry(ctx, key)
	s.observeOptional("get", start, err)
	return kv, found, err
}
