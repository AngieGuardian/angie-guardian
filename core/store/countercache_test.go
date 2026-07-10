// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// inlineCounterCache runs flushes synchronously so the store state is
// deterministic within a test.
func inlineCounterCache(t *testing.T) (*CounterCache, Store) {
	t.Helper()
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)
	c.Go = func(f func()) { f() }
	return c, st
}

// TestCounterCacheCounts: sequential bumps return the running total and the
// store counter tracks it.
func TestCounterCacheCounts(t *testing.T) {
	c, st := inlineCounterCache(t)

	for i := int64(1); i <= 5; i++ {
		if n := c.Incr("k", time.Minute); n != i {
			t.Fatalf("bump %d returned %d", i, n)
		}
	}
	v, ok, err := st.Get(context.Background(), "k")
	if err != nil || !ok {
		t.Fatalf("store counter missing: ok=%v err=%v", ok, err)
	}
	if string(v) != "5" {
		t.Fatalf("store counter = %s, want 5", v)
	}
}

// TestCounterCacheExpiry: a bump after the entry's TTL restarts the count.
func TestCounterCacheExpiry(t *testing.T) {
	c, _ := inlineCounterCache(t)
	base := time.Now()
	c.now = func() time.Time { return base }

	c.Incr("k", time.Minute)
	c.Incr("k", time.Minute)

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after expiry = %d, want 1 (fresh window)", n)
	}
}

// TestCounterCacheAdoptsSharedTotal: the flush result overwrites the local
// count, so an instance converges on a counter other replicas advanced.
func TestCounterCacheAdoptsSharedTotal(t *testing.T) {
	c, st := inlineCounterCache(t)

	// Another replica already counted 5 events against this key.
	for range 5 {
		if _, err := st.Incr(context.Background(), "k", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	// Local bump returns the local view first, but the inline flush lands
	// the shared total (6), so the next bump continues from it.
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("first local bump = %d, want 1", n)
	}
	if n := c.Incr("k", time.Minute); n != 7 {
		t.Fatalf("bump after flush = %d, want 7 (shared total adopted)", n)
	}
}

// TestCounterCacheForget clears the counter locally and in the store.
func TestCounterCacheForget(t *testing.T) {
	c, st := inlineCounterCache(t)

	c.Incr("k", time.Minute)
	c.Incr("k", time.Minute)
	c.Forget("k")

	if _, ok, _ := st.Get(context.Background(), "k"); ok {
		t.Fatal("store counter survived Forget")
	}
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after Forget = %d, want 1", n)
	}
}

// failingStore errors on every op; the cache must keep counting locally.
type failingStore struct{ Store }

var errStoreDown = errors.New("store down")

func (failingStore) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errStoreDown
}
func (failingStore) Delete(context.Context, string) error { return errStoreDown }

// TestCounterCacheStoreDown: a broken store degrades to per-instance
// counting instead of failing open.
func TestCounterCacheStoreDown(t *testing.T) {
	c := NewCounterCache(failingStore{})
	c.Go = func(f func()) { f() }

	for i := int64(1); i <= 3; i++ {
		if n := c.Incr("k", time.Minute); n != i {
			t.Fatalf("bump %d with store down returned %d", i, n)
		}
	}
	c.Forget("k")
	if n := c.Incr("k", time.Minute); n != 1 {
		t.Fatalf("bump after Forget with store down = %d, want 1", n)
	}
}

// TestCounterCacheConcurrent exercises the mutex paths under the race
// detector with real background flushes.
func TestCounterCacheConcurrent(t *testing.T) {
	st := NewMemory()
	t.Cleanup(func() { st.Close() })
	c := NewCounterCache(st)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				c.Incr("k", time.Minute)
			}
			c.Forget("k")
		})
	}
	wg.Wait()
}
