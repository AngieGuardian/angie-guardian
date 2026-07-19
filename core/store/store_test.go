// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type scanCountingHook struct {
	scans       atomic.Int64
	zranges     atomic.Int64
	maxPipeline atomic.Int64
}

type discardRecorder struct{}

func (discardRecorder) StoreOp(string, float64, error) {}

func (h *scanCountingHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *scanCountingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.FullName() == "scan" {
			h.scans.Add(1)
		}
		if cmd.FullName() == "zrange" {
			h.zranges.Add(1)
		}
		return next(ctx, cmd)
	}
}

func (h *scanCountingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for old := h.maxPipeline.Load(); int64(len(cmds)) > old; old = h.maxPipeline.Load() {
			if h.maxPipeline.CompareAndSwap(old, int64(len(cmds))) {
				break
			}
		}
		return next(ctx, cmds)
	}
}

// backend pairs a Store with a way to make a TTL of d elapse. Real-clock
// backends sleep; miniredis has a manual clock that must be fast-forwarded.
type backend struct {
	store   Store
	advance func(d time.Duration)
}

func sleepAdvance(d time.Duration) { time.Sleep(d) }

func backends(t *testing.T) map[string]backend {
	t.Helper()
	b, err := NewBolt(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	return map[string]backend{
		"memory": {NewMemory(), sleepAdvance},
		"bbolt":  {b, sleepAdvance},
		"redis":  {NewRedisFromClient(rdb), func(d time.Duration) { mr.FastForward(d + d/2) }},
	}
}

func TestStoreConformance(t *testing.T) {
	ctx := context.Background()
	for name, be := range backends(t) {
		s, advance := be.store, be.advance
		t.Run(name, func(t *testing.T) {
			defer s.Close()

			// Get/Set round trip, no TTL.
			if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
				t.Fatal(err)
			}
			v, ok, err := s.Get(ctx, "k")
			if err != nil || !ok || string(v) != "v" {
				t.Fatalf("get = %q %v %v, want v true nil", v, ok, err)
			}

			// Missing key.
			if _, ok, _ := s.Get(ctx, "nope"); ok {
				t.Fatal("missing key reported present")
			}

			// "Still present" is checked with a long TTL and a separate key, so
			// a slow/contended runner can never expire it before we read it
			// back (the CI flake that a 20ms TTL caused).
			if err := s.Set(ctx, "long", []byte("x"), time.Hour); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := s.Get(ctx, "long"); !ok {
				t.Fatal("fresh long-TTL key should be present")
			}

			// Expiry direction: a short TTL, then advance past it. 500ms is far
			// larger than any plausible scheduling pause, so the "still there"
			// window before advance() is not asserted on the short key.
			const shortTTL = 500 * time.Millisecond
			if err := s.Set(ctx, "ttl", []byte("x"), shortTTL); err != nil {
				t.Fatal(err)
			}
			advance(shortTTL + 200*time.Millisecond)
			if _, ok, _ := s.Get(ctx, "ttl"); ok {
				t.Fatal("expired key reported present")
			}

			// Delete is idempotent.
			if err := s.Delete(ctx, "k"); err != nil {
				t.Fatal(err)
			}
			if err := s.Delete(ctx, "k"); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := s.Get(ctx, "k"); ok {
				t.Fatal("deleted key reported present")
			}

			// Incr: starts at 1 and counts up within one long window (so a slow
			// runner can't expire the counter mid-loop)...
			for want := int64(1); want <= 3; want++ {
				n, err := s.Incr(ctx, "ctr", time.Hour)
				if err != nil || n != want {
					t.Fatalf("incr = %d %v, want %d nil", n, err, want)
				}
			}
			// ...and a separate short-lived counter restarts after its window.
			if n, _ := s.Incr(ctx, "ctr2", shortTTL); n != 1 {
				t.Fatalf("first incr = %d, want 1", n)
			}
			advance(shortTTL + 200*time.Millisecond)
			if n, _ := s.Incr(ctx, "ctr2", time.Minute); n != 1 {
				t.Fatalf("incr after expiry = %d, want 1", n)
			}

			// IncrBy: a fresh key starts at delta with the given TTL; an
			// existing key adds delta and keeps its original expiry; and it
			// composes with Incr (delta 1).
			if n, err := s.IncrBy(ctx, "byctr", 5, time.Hour); err != nil || n != 5 {
				t.Fatalf("first IncrBy = %d %v, want 5 nil", n, err)
			}
			if n, _ := s.IncrBy(ctx, "byctr", 3, time.Hour); n != 8 {
				t.Fatalf("IncrBy on existing = %d, want 8", n)
			}
			if n, _ := s.Incr(ctx, "byctr", time.Hour); n != 9 {
				t.Fatalf("Incr after IncrBy = %d, want 9", n)
			}
			// A fresh short-lived IncrBy counter restarts after its window,
			// proving the fresh key got the TTL.
			if n, _ := s.IncrBy(ctx, "byctr2", 4, shortTTL); n != 4 {
				t.Fatalf("first short IncrBy = %d, want 4", n)
			}
			advance(shortTTL + 200*time.Millisecond)
			if n, _ := s.IncrBy(ctx, "byctr2", 2, time.Minute); n != 2 {
				t.Fatalf("IncrBy after expiry = %d, want 2 (window did not reset)", n)
			}

			// IncrByDeadline: the four atomic properties that keep a delayed
			// per-window flush from polluting the next window.
			nowNanos := func() int64 { return time.Now().UnixNano() }
			// (3) Absent key -> created at delta, applied=true, expiring AT the
			// deadline: after the window elapses it is gone.
			dl := nowNanos() + shortTTL.Nanoseconds()
			if n, applied, err := s.IncrByDeadline(ctx, "dl", 3, dl); err != nil || n != 3 || !applied {
				t.Fatalf("fresh IncrByDeadline = %d applied=%v err=%v, want 3 true nil", n, applied, err)
			}
			// (4) Existing live key -> delta added, applied=true, expiry kept.
			if n, applied, _ := s.IncrByDeadline(ctx, "dl", 2, nowNanos()+time.Hour.Nanoseconds()); n != 5 || !applied {
				t.Fatalf("live IncrByDeadline = %d applied=%v, want 5 true", n, applied)
			}
			advance(shortTTL + 200*time.Millisecond)
			if _, ok, _ := s.Get(ctx, "dl"); ok {
				t.Fatal("IncrByDeadline fresh key did not expire at its deadline")
			}
			// (2) Deadline already in the past -> no write, applied=false, and
			// the value reflects the (absent) key as 0.
			past := nowNanos() - time.Minute.Nanoseconds()
			if n, applied, err := s.IncrByDeadline(ctx, "dlpast", 7, past); err != nil || applied || n != 0 {
				t.Fatalf("expired IncrByDeadline = %d applied=%v err=%v, want 0 false nil", n, applied, err)
			}
			if _, ok, _ := s.Get(ctx, "dlpast"); ok {
				t.Fatal("expired IncrByDeadline wrote a key; it must skip entirely")
			}
			// (2) again, but the key already exists and is live: the past-deadline
			// call must not mutate it, and must report the current value.
			if _, _, err := s.IncrByDeadline(ctx, "dllive", 4, nowNanos()+time.Hour.Nanoseconds()); err != nil {
				t.Fatal(err)
			}
			if n, applied, _ := s.IncrByDeadline(ctx, "dllive", 100, past); applied || n != 4 {
				t.Fatalf("past-deadline on live key = %d applied=%v, want 4 false (no mutation)", n, applied)
			}
			if v, _, _ := s.Get(ctx, "dllive"); string(v) != "4" {
				t.Fatalf("past-deadline mutated a live key: value = %q, want 4", v)
			}

			// CAS create-only (old == nil).
			ok, err = s.CompareAndSwap(ctx, "cas", nil, []byte("a"), 0)
			if err != nil || !ok {
				t.Fatalf("create-only CAS on absent key = %v %v, want true nil", ok, err)
			}
			ok, _ = s.CompareAndSwap(ctx, "cas", nil, []byte("b"), 0)
			if ok {
				t.Fatal("create-only CAS on existing key must fail")
			}

			// CAS swap: succeeds once, second identical swap fails (spent-flag semantics).
			ok, _ = s.CompareAndSwap(ctx, "cas", []byte("a"), []byte("spent"), 0)
			if !ok {
				t.Fatal("CAS with matching old must swap")
			}
			ok, _ = s.CompareAndSwap(ctx, "cas", []byte("a"), []byte("spent"), 0)
			if ok {
				t.Fatal("CAS with stale old must fail — this is the anti-replay guarantee")
			}
			v, _, _ = s.Get(ctx, "cas")
			if string(v) != "spent" {
				t.Fatalf("cas value = %q, want spent", v)
			}

			// Scan: live keys with the prefix only, key-sorted, values intact,
			// expired entries filtered even before any sweeper runs.
			for k, val := range map[string]string{"scan:a": "1", "scan:b": "2", "other": "x"} {
				if err := s.Set(ctx, k, []byte(val), time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Set(ctx, "scan:dead", []byte("gone"), shortTTL); err != nil {
				t.Fatal(err)
			}
			advance(shortTTL + 200*time.Millisecond)
			if err := s.Set(ctx, "scan:perm", []byte("3"), 0); err != nil {
				t.Fatal(err)
			}
			kvs, err := s.Scan(ctx, "scan:")
			if err != nil {
				t.Fatal(err)
			}
			if len(kvs) != 3 || kvs[0].Key != "scan:a" || kvs[1].Key != "scan:b" || kvs[2].Key != "scan:perm" {
				t.Fatalf("scan keys = %+v, want [scan:a scan:b scan:perm]", kvs)
			}
			if string(kvs[0].Value) != "1" || string(kvs[2].Value) != "3" {
				t.Fatalf("scan values = %q %q, want 1 3", kvs[0].Value, kvs[2].Value)
			}
			if kvs[0].ExpiresAt.IsZero() {
				t.Error("TTL'd key must report a non-zero ExpiresAt")
			}
			if !kvs[2].ExpiresAt.IsZero() {
				t.Errorf("permanent key must report a zero ExpiresAt, got %v", kvs[2].ExpiresAt)
			}
			if got, _ := s.Scan(ctx, "nothing:"); len(got) != 0 {
				t.Fatalf("scan of absent prefix = %+v, want empty", got)
			}
		})
	}
}

func TestBoltPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persist.db")

	s, err := NewBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, "durable", []byte("yes"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := NewBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	v, ok, err := s2.Get(ctx, "durable")
	if err != nil || !ok || string(v) != "yes" {
		t.Fatalf("value did not survive reopen: %q %v %v", v, ok, err)
	}
}

func TestBoltRejectsTTLThatWouldBecomePermanent(t *testing.T) {
	s, err := NewBolt(filepath.Join(t.TempDir(), "overflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ttl, err := time.ParseDuration("2562047h")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Set(ctx, "set", []byte("v"), ttl); err == nil {
		t.Fatal("oversized positive Set TTL was accepted as a permanent record")
	}
	if _, err := s.IncrBy(ctx, "incr", 1, ttl); err == nil {
		t.Fatal("oversized positive IncrBy TTL was accepted as a permanent record")
	}
	if _, err := s.CompareAndSwap(ctx, "cas", nil, []byte("v"), ttl); err == nil {
		t.Fatal("oversized positive CAS TTL was accepted as a permanent record")
	}
	for _, key := range []string{"set", "incr", "cas"} {
		if _, ok, err := s.Get(ctx, key); err != nil || ok {
			t.Fatalf("rejected TTL wrote %q: ok=%v err=%v", key, ok, err)
		}
	}
}

// TestRedisSubMillisecondTTL: a positive sub-millisecond TTL must not truncate
// to the 0 "no expiry" sentinel and make the counter permanent. IncrBy and
// CompareAndSwap both go through the TTL-aware Lua scripts, so both must keep a
// finite expiry for a tiny positive TTL.
func TestRedisSubMillisecondTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := NewRedisFromClient(rdb)
	ctx := context.Background()

	// IncrBy sub-ms: the key must never be permanent. Under the absolute-
	// deadline path a sub-ms window may either land a ~1ms expiry or be treated
	// as already elapsed (skipped); both are fine, a permanent key (PTTL == -1)
	// is not. Whatever it is, it must be gone after the window.
	if _, err := s.IncrBy(ctx, "ctr", 1, 500*time.Microsecond); err != nil {
		t.Fatal(err)
	}
	// go-redis PTTL: -1ns = key exists but has no expiry (permanent); -2ns = missing.
	if pttl, _ := rdb.PTTL(ctx, "ctr").Result(); pttl == -1 {
		t.Fatal("IncrBy sub-ms TTL made the key permanent (PTTL == -1)")
	}
	mr.FastForward(2 * time.Millisecond)
	if _, ok, _ := s.Get(ctx, "ctr"); ok {
		t.Fatal("sub-ms TTL counter did not expire; it became permanent")
	}

	// CAS uses a relative TTL floored to >=1ms, so it deterministically keeps a
	// finite expiry (the original 9181 truncation-to-permanent bug).
	if ok, err := s.CompareAndSwap(ctx, "cas", nil, []byte("v"), 500*time.Microsecond); err != nil || !ok {
		t.Fatalf("CAS create = %v %v, want true nil", ok, err)
	}
	if pttl := mr.TTL("cas"); pttl <= 0 {
		t.Fatalf("CAS sub-ms TTL: key TTL = %v, want a finite positive expiry (not permanent)", pttl)
	}
}

func TestRedisScanLimitBoundsResultAndReportsCompleteness(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := NewRedisFromClient(rdb)
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	for i := range 600 {
		if err := s.Set(ctx, fmt.Sprintf("limit:%04d", i), []byte("x"), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	kvs, complete, err := s.ScanLimit(ctx, "limit:", 100)
	if err != nil {
		t.Fatal(err)
	}
	if complete || len(kvs) != 100 {
		t.Fatalf("limited scan: len=%d complete=%v, want 100/false", len(kvs), complete)
	}
	kvs, complete, err = s.ScanLimit(ctx, "limit:", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !complete || len(kvs) != 600 {
		t.Fatalf("complete scan: len=%d complete=%v, want 600/true", len(kvs), complete)
	}
}

func TestAllBackendsBoundLimitedScans(t *testing.T) {
	ctx := context.Background()
	for name, be := range backends(t) {
		t.Run(name, func(t *testing.T) {
			defer be.store.Close()
			limited, ok := be.store.(LimitedScanner)
			if !ok {
				t.Fatal("backend does not implement LimitedScanner")
			}
			for i := range 3 {
				if err := be.store.Set(ctx, fmt.Sprintf("bounded:%d", i), []byte("x"), time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			kvs, complete, err := limited.ScanLimit(ctx, "bounded:", 2)
			if err != nil {
				t.Fatal(err)
			}
			if complete || len(kvs) != 2 {
				t.Fatalf("ScanLimit = len %d complete %v, want 2/false", len(kvs), complete)
			}
		})
	}
}

func TestAllBackendsPostureVotesAreFleetMaxAndExpire(t *testing.T) {
	ctx := context.Background()
	for name, be := range backends(t) {
		t.Run(name, func(t *testing.T) {
			defer be.store.Close()
			votes, ok := be.store.(PostureVotes)
			if !ok {
				t.Fatal("backend does not implement PostureVotes")
			}
			// Populate unrelated state heavily enough to catch an accidental use
			// of the general key map/bucket/keyspace in targeted tests and profiles.
			for i := range 128 {
				if err := be.store.Set(ctx, fmt.Sprintf("challenge:%04d", i), []byte("x"), time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if err := votes.SetPostureVote(ctx, "a", 1, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := votes.SetPostureVote(ctx, "b", 2, 500*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if got, err := votes.MaxPostureVote(ctx, "a"); err != nil || got != 2 {
				t.Fatalf("max excluding a = %d, %v; want 2, nil", got, err)
			}
			if got, err := votes.MaxPostureVote(ctx, "b"); err != nil || got != 1 {
				t.Fatalf("max excluding b = %d, %v; want 1, nil", got, err)
			}
			be.advance(700 * time.Millisecond)
			if got, err := votes.MaxPostureVote(ctx, ""); err != nil || got != 1 {
				t.Fatalf("max after attack expiry = %d, %v; want 1, nil", got, err)
			}
			if err := votes.DeletePostureVote(ctx, "a"); err != nil {
				t.Fatal(err)
			}
			if got, err := votes.MaxPostureVote(ctx, ""); err != nil || got != 0 {
				t.Fatalf("max after delete = %d, %v; want 0, nil", got, err)
			}
		})
	}
}

func TestAllBackendsActiveBlockIndexIgnoresUnrelatedKeys(t *testing.T) {
	ctx := context.Background()
	for name, be := range backends(t) {
		t.Run(name, func(t *testing.T) {
			defer be.store.Close()
			indexed, ok := be.store.(ActiveBlockScanner)
			if !ok {
				t.Fatal("backend does not implement ActiveBlockScanner")
			}
			for i := range 128 {
				if err := be.store.Set(ctx, fmt.Sprintf("challenge:%04d", i), []byte("noise"), time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if err := be.store.Set(ctx, "block:192.0.2.1", []byte("one"), time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := be.store.Set(ctx, "block:192.0.2.2", []byte("two"), time.Hour); err != nil {
				t.Fatal(err)
			}
			kvs, complete, err := indexed.ScanActiveBlocks(ctx, "block:", 1)
			if err != nil || len(kvs) != 1 || complete {
				t.Fatalf("limited active scan = %+v complete=%v err=%v; want one/incomplete/nil", kvs, complete, err)
			}
			kvs, _, err = indexed.ScanActiveBlocks(ctx, "block:", 10)
			if err != nil || len(kvs) != 2 {
				t.Fatalf("active scan = %+v err=%v; want two blocks", kvs, err)
			}
			if err := be.store.Delete(ctx, "block:192.0.2.1"); err != nil {
				t.Fatal(err)
			}
			kvs, _, err = indexed.ScanActiveBlocks(ctx, "block:", 10)
			if err != nil || len(kvs) != 1 || kvs[0].Key != "block:192.0.2.2" {
				t.Fatalf("active scan after delete = %+v err=%v", kvs, err)
			}
		})
	}
}

func TestRedisIndexedOperationsNeverScanGeneralKeyspace(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	hook := &scanCountingHook{}
	rdb.AddHook(hook)
	s := NewRedisFromClient(rdb)
	t.Cleanup(func() { s.Close() })
	ctx := t.Context()

	if err := s.Set(ctx, "block:192.0.2.10", []byte("indexed"), time.Hour); err != nil {
		t.Fatal(err)
	}
	kvs, complete, err := s.ScanActiveBlocks(ctx, "block:", 10)
	if err != nil || !complete || len(kvs) != 1 || kvs[0].Key != "block:192.0.2.10" {
		t.Fatalf("indexed scan = %+v complete=%v err=%v", kvs, complete, err)
	}

	// A stale index member is healed through bounded GET/ZREM work. It makes
	// this snapshot incomplete, but must not trigger a generic keyspace scan.
	if err := rdb.ZAdd(ctx, redisBlockIndex, redis.Z{
		Score: float64(time.Now().Add(time.Hour).UnixMilli()), Member: "block:192.0.2.99",
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if _, complete, err = s.ScanActiveBlocks(ctx, "block:", 10); err != nil || complete {
		t.Fatalf("stale-member scan complete=%v err=%v; want incomplete/nil", complete, err)
	}
	if _, complete, err = s.ScanActiveBlocks(ctx, "block:", 10); err != nil || !complete {
		t.Fatalf("healed index complete=%v err=%v; want complete/nil", complete, err)
	}
	if err := s.SetPostureVote(ctx, "replica-a", 2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.MaxPostureVote(ctx, ""); err != nil || got != 2 {
		t.Fatalf("posture max = %d, %v", got, err)
	}
	if got := hook.scans.Load(); got != 0 {
		t.Fatalf("indexed operations used Redis SCAN %d times", got)
	}
}

func TestRedisBlockIndexUsesServerClockForExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	// Put Redis a day behind the application. Pruning with local time would
	// immediately erase the otherwise-live one-hour block's index member.
	mr.SetTime(time.Now().Add(-24 * time.Hour))
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := NewRedisFromClient(rdb)
	t.Cleanup(func() { s.Close() })
	ctx := t.Context()
	if err := s.Set(ctx, "block:198.51.100.8", []byte("live"), time.Hour); err != nil {
		t.Fatal(err)
	}
	kvs, complete, err := s.ScanActiveBlocks(ctx, "block:", 10)
	if err != nil || !complete || len(kvs) != 1 {
		t.Fatalf("skewed-clock active scan = %+v complete=%v err=%v", kvs, complete, err)
	}
}

func TestRedisStaleHealPreservesConcurrentlyRecreatedBlock(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := NewRedisFromClient(rdb)
	t.Cleanup(func() { s.Close() })
	ctx := t.Context()
	const key = "block:198.51.100.9"

	// Model the exact race window: an indexed GET observed the old key as
	// missing, then Set recreated both the key and membership before healing.
	if err := s.Set(ctx, key, []byte("recreated"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := redisHealBlockIndexScript.Run(ctx, rdb,
		[]string{redisBlockIndex, redisBlockIndexGeneration}, key).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := rdb.ZScore(ctx, redisBlockIndex, key).Result(); err != nil {
		t.Fatalf("conditional heal removed recreated block membership: %v", err)
	}
}

func TestRedisActiveIndexBatchesValueFetch(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	hook := &scanCountingHook{}
	rdb.AddHook(hook)
	s := NewRedisFromClient(rdb)
	t.Cleanup(func() { s.Close() })
	ctx := t.Context()
	for i := range 600 {
		if err := s.Set(ctx, fmt.Sprintf("block:198.51.%d.%d", i/256, i%256), []byte("x"), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	kvs, complete, err := s.ScanActiveBlocks(ctx, "block:", 1000)
	if err != nil || !complete || len(kvs) != 600 {
		t.Fatalf("active scan len=%d complete=%v err=%v", len(kvs), complete, err)
	}
	if got := hook.maxPipeline.Load(); got == 0 || got > 2*512 {
		t.Fatalf("largest value-fetch pipeline = %d, want 1..1024", got)
	}
	if got := hook.zranges.Load(); got < 2 {
		t.Fatalf("indexed key enumeration used %d ZRANGE page(s), want at least 2", got)
	}
	if got := hook.scans.Load(); got != 0 {
		t.Fatalf("batched active scan used Redis SCAN %d times", got)
	}
}

func TestInstrumentedPreservesIndexedCapabilities(t *testing.T) {
	base := NewMemory()
	wrapped := Instrument(base, discardRecorder{})
	t.Cleanup(func() { wrapped.Close() })
	blocks, ok := wrapped.(ActiveBlockScanner)
	if !ok {
		t.Fatal("instrumentation hid ActiveBlockScanner")
	}
	votes, ok := wrapped.(PostureVotes)
	if !ok {
		t.Fatal("instrumentation hid PostureVotes")
	}
	ctx := t.Context()
	if err := wrapped.Set(ctx, "block:192.0.2.20", []byte("x"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if kvs, complete, err := blocks.ScanActiveBlocks(ctx, "block:", 10); err != nil || !complete || len(kvs) != 1 {
		t.Fatalf("instrumented active blocks = %+v complete=%v err=%v", kvs, complete, err)
	}
	if err := votes.SetPostureVote(ctx, "replica", 2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := votes.MaxPostureVote(ctx, ""); err != nil || got != 2 {
		t.Fatalf("instrumented posture max = %d, %v", got, err)
	}
}
