// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package botverify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

type expiryTestStore struct {
	store.Store
	calls  atomic.Int64
	record store.KV
	now    *time.Time
	delay  time.Duration
	fail   bool
}

func (s *expiryTestStore) GetWithExpiry(context.Context, string) (store.KV, bool, error) {
	s.calls.Add(1)
	if s.fail {
		return store.KV{}, false, errors.New("offline")
	}
	if s.now != nil {
		*s.now = s.now.Add(s.delay)
	}
	return s.record, s.record.Value != nil, nil
}
func (s *expiryTestStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if s.fail {
		return errors.New("offline")
	}
	return s.Store.Set(ctx, key, value, ttl)
}

func TestFreshIdentitySurvivesStoreOutageWithoutRenewal(t *testing.T) {
	now := time.Now()
	st := &expiryTestStore{Store: store.NewMemory(), fail: true}
	t.Cleanup(func() { st.Close() })
	v := New(st, slog.Default())
	v.local.now = func() time.Time { return now }
	resolver := &fakeResolver{ptr: map[string][]string{"198.51.100.42": {"crawl.googlebot.com."}}, fwd: map[string][]string{"crawl.googlebot.com": {"198.51.100.42"}}}
	v.SetResolver(resolver)
	if v.Verify(t.Context(), "198.51.100.42", Options{CacheTTL: time.Minute}).Status != StatusConfirmed {
		t.Fatal("store outage lost fresh DNS identity")
	}
	now = now.Add(59 * time.Second)
	if v.Verify(t.Context(), "198.51.100.42", Options{CacheTTL: time.Hour}).Status != StatusConfirmed {
		t.Fatal("fresh local identity lost")
	}
	if st.calls.Load() != 1 || resolver.ptrCall.Load() != 1 {
		t.Fatal("local hit retried failed store or DNS")
	}
	now = now.Add(time.Second)
	if _, ok := v.LookupCached("198.51.100.42"); ok {
		t.Fatal("read renewed DNS identity TTL")
	}
}

func TestLocalCachePreservesStoreExpiry(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{"ok:crawl.googlebot.com", "none", "err"} {
		t.Run(raw, func(t *testing.T) {
			now := time.Now()
			deadline := now.Add(time.Minute)
			st := &expiryTestStore{Store: store.NewMemory(), now: &now, delay: 20 * time.Second, record: store.KV{Value: []byte(raw), ExpiresAt: deadline}}
			t.Cleanup(func() { st.Close() })
			v := New(st, slog.Default())
			v.local.now = func() time.Time { return now }
			v.SetResolver(&fakeResolver{})
			v.Verify(ctx, "198.51.100.42", Options{CacheTTL: 12 * time.Hour})
			for range 3 {
				now = now.Add(10 * time.Second)
				if _, ok := v.LookupCached("198.51.100.42"); !ok {
					t.Fatal("expired before original deadline")
				}
				v.Verify(ctx, "198.51.100.42", Options{})
			}
			if st.calls.Load() != 1 {
				t.Fatal("local hits accessed store")
			}
			now = deadline
			st.fail = true
			if _, ok := v.LookupCached("198.51.100.42"); ok {
				t.Fatal("local copy extended original expiry")
			}
			if st.calls.Load() != 1 {
				t.Fatal("shed miss accessed store")
			}
		})
	}
}
func TestLocalCacheRejectsUnsafePromotion(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		deadline  time.Time
	}{
		{"permanent", "ok:crawl.googlebot.com", time.Time{}},
		{"expired", "ok:crawl.googlebot.com", time.Now().Add(-time.Second)},
		{"empty hostname", "ok:", time.Now().Add(time.Hour)},
		{"oversize", "ok:" + string(make([]byte, 254)), time.Now().Add(time.Hour)},
		{"unknown format", "bad", time.Now().Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &expiryTestStore{Store: store.NewMemory(), record: store.KV{Value: []byte(tc.raw), ExpiresAt: tc.deadline}}
			t.Cleanup(func() { st.Close() })
			v := New(st, slog.Default())
			// A DNS concurrency shed cannot replace the invalid store record.
			for range maxConcurrent {
				v.sem <- struct{}{}
			}
			v.Verify(context.Background(), "198.51.100.42", Options{})
			if _, ok := v.LookupCached("198.51.100.42"); ok {
				t.Fatal("unsafe store entry warmed local cache")
			}
		})
	}
}
func TestLocalCacheFreshDNSAndUnsupportedStore(t *testing.T) {
	r := &fakeResolver{ptr: map[string][]string{"198.51.100.42": {"crawl.googlebot.com."}}, fwd: map[string][]string{"crawl.googlebot.com": {"198.51.100.42"}}}
	// Hiding ExpiryReader models an embedding implementing only Store.
	st := struct{ store.Store }{store.NewMemory()}
	t.Cleanup(func() { st.Close() })
	if err := st.Set(context.Background(), keyPrefix+"198.51.100.42", []byte("ok:crawl.googlebot.com"), time.Minute); err != nil {
		t.Fatal(err)
	}
	v := New(store.Instrument(st, discardCacheStoreRecorder{}), slog.Default())
	v.SetResolver(r)
	if v.Verify(context.Background(), "198.51.100.42", Options{}).Status != StatusConfirmed {
		t.Fatal("unsupported capability lost normal cache")
	}
	if _, ok := v.LookupCached("198.51.100.42"); ok {
		t.Fatal("unknown expiry promoted")
	}
	st.Delete(context.Background(), keyPrefix+"198.51.100.42")
	now := time.Now()
	v.local.now = func() time.Time { return now }
	v.Verify(context.Background(), "198.51.100.42", Options{CacheTTL: time.Minute})
	if _, ok := v.LookupCached("198.51.100.42"); !ok {
		t.Fatal("fresh DNS failed to warm local cache")
	}
	now = now.Add(time.Minute)
	if _, ok := v.LookupCached("198.51.100.42"); ok {
		t.Fatal("fresh DNS cache did not expire")
	}
}

type discardCacheStoreRecorder struct{}

func (discardCacheStoreRecorder) StoreOp(string, float64, error) {}

func TestLocalCacheIsolationNormalizationAndContention(t *testing.T) {
	r := &fakeResolver{ptr: map[string][]string{"2001:db8::42": {"crawl.googlebot.com."}}, fwd: map[string][]string{"crawl.googlebot.com": {"2001:db8::42"}}}
	v := newTestVerifier(t, r)
	result := v.Verify(context.Background(), "2001:db8::42", Options{})
	result.Hostnames[0] = "attacker.test"
	id, ok := v.LookupCached("2001:0DB8:0:0::42")
	if !ok || !id.MatchesDomains([]string{"googlebot.com"}) {
		t.Fatal("mutable result or IP spelling corrupted cache")
	}
	result = v.Verify(context.Background(), "2001:0DB8:0:0::42", Options{})
	result.Hostnames[0] = "attacker.test"
	if r.ptrCall.Load() != 1 {
		t.Fatal("equivalent IP caused DNS")
	}
	sh := v.local.shard(netip.MustParseAddr("2001:db8::42"))
	sh.mu.Lock()
	if _, ok := v.LookupCached("2001:db8::42"); ok {
		t.Fatal("contended lookup succeeded")
	}
	sh.mu.Unlock()
	v.local.put(netip.MustParseAddr("192.0.2.1"), Result{Status: StatusNone}, time.Now().Add(time.Hour))
	if _, ok := v.LookupCached("::ffff:192.0.2.1"); !ok {
		t.Fatal("mapped IPv4 did not share identity")
	}
}
func TestLocalCacheCapacityLRUAndConcurrency(t *testing.T) {
	c := newLocalCache()
	addr := netip.MustParseAddr("198.51.100.42")
	sh := c.shard(addr)
	expires := time.Now().Add(time.Hour)
	c.put(addr, Result{Status: StatusNone}, expires)
	var sameShard []netip.Addr
	for i := 1; len(sameShard) < localPerShard; i++ {
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i))
		if c.shard(a) == sh {
			sameShard = append(sameShard, a)
		}
	}
	for _, a := range sameShard[:localPerShard-1] {
		c.put(a, Result{Status: StatusNone}, expires)
	}
	c.get(addr, false) // Keep the original address hot.
	c.put(sameShard[localPerShard-1], Result{Status: StatusNone}, expires)
	if _, ok := c.get(addr, true); !ok {
		t.Fatal("LRU evicted recently used address")
	}
	if _, ok := c.get(sameShard[0], true); ok {
		t.Fatal("LRU retained oldest entry at capacity")
	}
	if len(sh.entries) != localPerShard {
		t.Fatal("shard exceeded capacity")
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 1000 {
				a := netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::%x", worker, i))
				c.put(a, Result{Status: StatusNone}, expires)
				c.get(a, false)
				c.get(a, true)
			}
		})
	}
	wg.Wait()
	total := 0
	for i := range c.shards {
		if len(c.shards[i].entries) > localPerShard {
			t.Fatal("capacity exceeded")
		}
		total += len(c.shards[i].entries)
	}
	if total > localShards*localPerShard {
		t.Fatal("total capacity exceeded")
	}
}

func BenchmarkLocalBotIdentityShed(b *testing.B) {
	v := New(nil, slog.Default())
	v.local.put(netip.MustParseAddr("198.51.100.42"), Result{Status: StatusConfirmed, Hostnames: []string{"crawl.googlebot.com"}}, time.Now().Add(time.Hour))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		id, ok := v.LookupCached("198.51.100.42")
		if !ok || !id.MatchesDomains([]string{"googlebot.com"}) {
			b.Fatal("miss")
		}
	}
}
