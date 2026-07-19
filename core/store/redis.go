// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a shared Store backed by Redis/Valkey: the multi-instance
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

// incrByDeadlineScript: INCRBY delta against an absolute deadline (ARGV[2],
// unix milliseconds; 0 = no expiry), enforced atomically on the server clock in
// a single script. It returns {value, applied} where applied is 1 when the
// write happened and 0 when it was skipped. If the deadline has passed the op
// is skipped and the current value is returned (0 if absent), so a flush
// delayed past its window cannot pollute the next one. A fresh key is created
// expiring exactly at the deadline via PEXPIREAT, so a late create cannot
// outlive its window. Existence is checked before the increment (rather than
// inferring it from the result) so a delta that happens to equal the
// pre-existing value cannot be mistaken for a fresh key. ARGV[1] is the delta.
var incrByDeadlineScript = redis.NewScript(`
local deadline = tonumber(ARGV[2])
if deadline > 0 then
  local t = redis.call('TIME')
  local nowms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
  if nowms >= deadline then
    local cur = redis.call('GET', KEYS[1])
    if cur then return {tonumber(cur), 0} end
    return {0, 0}
  end
end
local fresh = redis.call('EXISTS', KEYS[1]) == 0
local v = redis.call('INCRBY', KEYS[1], ARGV[1])
if fresh and deadline > 0 then
  redis.call('PEXPIREAT', KEYS[1], deadline)
end
return {v, 1}
`)

func (s *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.IncrBy(ctx, key, 1, ttl)
}

func (s *Redis) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	var deadline int64
	if ttl > 0 {
		deadline = time.Now().Add(ttl).UnixNano()
	}
	n, _, err := s.IncrByDeadline(ctx, key, delta, deadline)
	return n, err
}

func (s *Redis) IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (int64, bool, error) {
	res, err := incrByDeadlineScript.Run(ctx, s.rdb, []string{key}, delta, deadlineMillis(deadline)).Slice()
	if err != nil {
		return 0, false, err
	}
	// The script returns {value, applied}; redis integers arrive as int64.
	if len(res) != 2 {
		return 0, false, fmt.Errorf("incrByDeadline: unexpected script result %v", res)
	}
	value, ok1 := res[0].(int64)
	applied, ok2 := res[1].(int64)
	if !ok1 || !ok2 {
		return 0, false, fmt.Errorf("incrByDeadline: non-integer script result %v", res)
	}
	return value, applied == 1, nil
}

// deadlineMillis converts an absolute unix-nano deadline to the unix-millis the
// Lua script expects, where 0 means "no expiry". It rounds UP to the next whole
// millisecond: redis expiry is millisecond-granular, so truncating a deadline
// down could land it in the current (or a past) millisecond and expire the key
// immediately, while a positive TTL must always yield a genuine future expiry.
func deadlineMillis(deadline int64) int64 {
	if deadline <= 0 {
		return 0
	}
	ms := (deadline + int64(time.Millisecond) - 1) / int64(time.Millisecond) // ceil
	if ms > 0 {
		return ms
	}
	return 1
}

// pexpireArg converts a relative Go TTL to the millisecond argument the CAS
// script expects, where 0 means "no expiry". A positive TTL below one
// millisecond would truncate to 0 and make the key permanent, so it is floored
// to 1ms; a non-positive TTL passes through as the 0 no-expiry sentinel.
func pexpireArg(ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	if ms := ttl.Milliseconds(); ms > 0 {
		return ms
	}
	return 1
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
		oldArg, string(new), pexpireArg(ttl), createOnly).Int64()
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
	out, _, err := s.ScanLimit(ctx, prefix, 0)
	return out, err
}

// ScanLimit bounds the returned live set for background consumers whose own
// state is capped. Redis SCAN order is unspecified, so complete explicitly
// tells the caller whether the result was truncated.
func (s *Redis) ScanLimit(ctx context.Context, prefix string, limit int) ([]KV, bool, error) {
	// SCAN walks the whole keyspace and filters server-side; fine for an
	// occasional admin read, unfit for the hot path (see the interface doc).
	// Fetch each SCAN batch before advancing. Building one 2*N-command
	// pipeline for the entire keyspace can consume unbounded client and Redis
	// memory during reconciliation or an admin listing.
	const batchSize = 512
	keys := make([]string, 0, batchSize)
	var out []KV
	now := time.Now()
	iter := s.rdb.Scan(ctx, 0, globEscape(prefix)+"*", 512).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
		if len(keys) == batchSize {
			batch, err := s.scanValues(ctx, keys, now)
			if err != nil {
				return nil, false, err
			}
			out = append(out, batch...)
			if limit > 0 && len(out) > limit {
				out = out[:limit]
				slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
				return out, false, nil
			}
			keys = keys[:0]
		}
	}
	if err := iter.Err(); err != nil {
		return nil, false, err
	}
	if len(keys) > 0 {
		batch, err := s.scanValues(ctx, keys, now)
		if err != nil {
			return nil, false, err
		}
		out = append(out, batch...)
	}

	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	return out, true, nil
}

// scanValues fetches one bounded batch of values and TTLs.
func (s *Redis) scanValues(ctx context.Context, keys []string, now time.Time) ([]KV, error) {
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

	out := make([]KV, 0, len(keys))
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
	return out, nil
}

func (s *Redis) Close() error { return s.rdb.Close() }
