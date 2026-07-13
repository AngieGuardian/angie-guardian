// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

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

// TestRedisSubMillisecondTTL is the regression for MR review 9181: a positive
// sub-millisecond TTL must not truncate to the 0 "no expiry" sentinel and make
// the counter permanent. IncrBy and CompareAndSwap both go through the TTL-aware
// Lua scripts, so both must keep a finite expiry for a tiny positive TTL.
func TestRedisSubMillisecondTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := NewRedisFromClient(rdb)
	ctx := context.Background()

	if _, err := s.IncrBy(ctx, "ctr", 1, 500*time.Microsecond); err != nil {
		t.Fatal(err)
	}
	if pttl := mr.TTL("ctr"); pttl <= 0 {
		t.Fatalf("IncrBy sub-ms TTL: key TTL = %v, want a finite positive expiry (not permanent)", pttl)
	}

	if ok, err := s.CompareAndSwap(ctx, "cas", nil, []byte("v"), 500*time.Microsecond); err != nil || !ok {
		t.Fatalf("CAS create = %v %v, want true nil", ok, err)
	}
	if pttl := mr.TTL("cas"); pttl <= 0 {
		t.Fatalf("CAS sub-ms TTL: key TTL = %v, want a finite positive expiry (not permanent)", pttl)
	}

	// The key must actually expire after its window, proving it is not permanent.
	mr.FastForward(2 * time.Millisecond)
	if _, ok, _ := s.Get(ctx, "ctr"); ok {
		t.Fatal("sub-ms TTL counter did not expire; it became permanent")
	}
}
