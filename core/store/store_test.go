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

func sleepAdvance(d time.Duration) { time.Sleep(d + d/2) }

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

			// TTL expiry.
			if err := s.Set(ctx, "ttl", []byte("x"), 20*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := s.Get(ctx, "ttl"); !ok {
				t.Fatal("fresh TTL key should be present")
			}
			advance(20 * time.Millisecond)
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

			// Incr: starts at 1, counts up, restarts after expiry.
			for want := int64(1); want <= 3; want++ {
				n, err := s.Incr(ctx, "ctr", 20*time.Millisecond)
				if err != nil || n != want {
					t.Fatalf("incr = %d %v, want %d nil", n, err, want)
				}
			}
			advance(20 * time.Millisecond)
			if n, _ := s.Incr(ctx, "ctr", time.Minute); n != 1 {
				t.Fatalf("incr after expiry = %d, want 1", n)
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
