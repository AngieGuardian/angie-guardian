// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a shared Store backed by Redis/Valkey — the multi-instance
// backend: all Guardian replicas behind a load balancer point at the same
// server so any instance sees any other's blocks and spent challenges.
// TTLs are native; Incr and CompareAndSwap use small Lua scripts so their
// semantics match the memory and bbolt backends exactly (atomic, TTL-aware).
type Redis struct {
	rdb *redis.Client
}

// RedisOptions configures the connection.
type RedisOptions struct {
	Addr     string
	Password string
	DB       int
}

func NewRedis(opts RedisOptions) (*Redis, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     opts.Addr,
		Password: opts.Password,
		DB:       opts.DB,
		// The block lookup runs on every request, so a hung Redis must not
		// stall the auth hot path: keep per-op and pool-wait timeouts tight so
		// the engine's fail-open kicks in within tens of ms, not go-redis's
		// multi-second defaults. Pool is generous for the 50k req/s target.
		DialTimeout:  1 * time.Second,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		PoolTimeout:  200 * time.Millisecond,
		PoolSize:     256,
		MinIdleConns: 16,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, err
	}
	return &Redis{rdb: rdb}, nil
}

// NewRedisFromClient wraps an existing client (used by tests with miniredis).
func NewRedisFromClient(rdb *redis.Client) *Redis { return &Redis{rdb: rdb} }

func (s *Redis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := s.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

func (s *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	// ttl <= 0 means no expiry, which is exactly redis.KeepTTL's opposite:
	// pass 0 to SET for "no expiration".
	if ttl < 0 {
		ttl = 0
	}
	return s.rdb.Set(ctx, key, value, ttl).Err()
}

func (s *Redis) Delete(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, key).Err()
}

// incrScript: INCR, and set the TTL only when the key was just created (v==1),
// so an existing time-bucketed counter keeps its original expiry — matching
// the memory/bbolt Incr contract. ARGV[1] is the TTL in milliseconds (0 = none).
var incrScript = redis.NewScript(`
local v = redis.call('INCR', KEYS[1])
if v == 1 and tonumber(ARGV[1]) > 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return v
`)

func (s *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return incrScript.Run(ctx, s.rdb, []string{key}, ttl.Milliseconds()).Int64()
}

// casScript: atomic compare-and-swap. ARGV[1]=old (or empty marker), ARGV[2]=new,
// ARGV[3]=ttl ms (0=none), ARGV[4]="1" when old is nil (create-only). Returns
// 1 on swap, 0 otherwise.
var casScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
local createOnly = ARGV[4] == '1'
if createOnly then
  if cur then return 0 end
else
  if not cur or cur ~= ARGV[1] then return 0 end
end
if tonumber(ARGV[3]) > 0 then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
else
  redis.call('SET', KEYS[1], ARGV[2])
end
return 1
`)

func (s *Redis) CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	createOnly := "0"
	oldArg := ""
	if old == nil {
		createOnly = "1"
	} else {
		oldArg = string(old)
	}
	n, err := casScript.Run(ctx, s.rdb, []string{key},
		oldArg, string(new), ttl.Milliseconds(), createOnly).Int64()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// globEscape neutralizes SCAN MATCH glob metacharacters so a prefix is always
// matched literally (our key prefixes are plain, but be correct regardless).
func globEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`, "]", `\]`)
	return r.Replace(s)
}

func (s *Redis) Scan(ctx context.Context, prefix string) ([]KV, error) {
	// SCAN walks the whole keyspace and filters server-side; fine for an
	// occasional admin read, unfit for the hot path (see the interface doc).
	var keys []string
	iter := s.rdb.Scan(ctx, 0, globEscape(prefix)+"*", 512).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	// Fetch values + TTLs in one pipelined round trip.
	gets := make([]*redis.StringCmd, len(keys))
	ttls := make([]*redis.DurationCmd, len(keys))
	_, err := s.rdb.Pipelined(ctx, func(p redis.Pipeliner) error {
		for i, k := range keys {
			gets[i] = p.Get(ctx, k)
			ttls[i] = p.PTTL(ctx, k)
		}
		return nil
	})
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	now := time.Now()
	var out []KV
	for i, k := range keys {
		v, err := gets[i].Bytes()
		if errors.Is(err, redis.Nil) {
			continue // expired between SCAN and GET
		}
		if err != nil {
			return nil, err
		}
		var exp time.Time
		if ttl := ttls[i].Val(); ttl > 0 {
			exp = now.Add(ttl)
		}
		out = append(out, KV{Key: k, Value: v, ExpiresAt: exp})
	}
	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

func (s *Redis) Close() error { return s.rdb.Close() }
