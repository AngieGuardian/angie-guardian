// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A reader queued behind a writer must reconstruct the deadline from the TTL
// sampled after admission to the transaction, not from its pre-lock timestamp.
func TestBuntDBGetWithExpiryAfterTransactionWait(t *testing.T) {
	b, err := NewBuntDB(":memory:", BuntDBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := t.Context()
	const ttl = time.Hour
	before := time.Now()
	if err := b.Set(ctx, "queued", []byte("value"), ttl); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	writer, err := b.db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	type result struct {
		kv    KV
		found bool
		err   error
	}
	started := make(chan struct{})
	read := make(chan result, 1)
	go func() {
		close(started)
		kv, found, err := b.GetWithExpiry(ctx, "queued")
		read <- result{kv, found, err}
	}()
	<-started
	runtime.Gosched() // let the reader enter GetWithExpiry and wait on the lock
	time.Sleep(150 * time.Millisecond)
	select {
	case <-read:
		t.Fatal("reader bypassed the writer transaction lock")
	default:
	}
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-read:
		if got.err != nil || !got.found || string(got.kv.Value) != "value" {
			t.Fatalf("queued read: %+v", got)
		}
		if got.kv.ExpiresAt.Before(before.Add(ttl-25*time.Millisecond)) || got.kv.ExpiresAt.After(after.Add(ttl+time.Millisecond)) {
			t.Fatalf("transaction wait changed deadline: %v; write interval %v to %v", got.kv.ExpiresAt, before, after)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not resume after the writer released its lock")
	}
}

func TestGetWithExpiryAllBackends(t *testing.T) {
	bes := backends(t)
	peb, err := NewPebble(filepath.Join(t.TempDir(), "expiry.pebble"), PebbleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bes["pebble"] = backend{peb, sleepAdvance}
	for name, be := range bes {
		t.Run(name, func(t *testing.T) {
			defer be.store.Close()
			rec := &countingRecorder{}
			reader := Instrument(be.store, rec).(ExpiryReader)
			ctx := context.Background()
			if _, ok, err := reader.GetWithExpiry(ctx, "missing"); ok || err != nil {
				t.Fatalf("missing: %v %v", ok, err)
			}
			for _, key := range []string{"botdns:test", "block:192.0.2.42"} {
				before := time.Now()
				if err := be.store.Set(ctx, key, []byte("value"), time.Second); err != nil {
					t.Fatal(err)
				}
				after := time.Now()
				kv, ok, err := reader.GetWithExpiry(ctx, key)
				if err != nil || !ok || kv.Key != key || string(kv.Value) != "value" || kv.ExpiresAt.IsZero() {
					t.Fatalf("live: %+v %v %v", kv, ok, err)
				}
				if kv.ExpiresAt.Before(before.Add(900*time.Millisecond)) || kv.ExpiresAt.After(after.Add(time.Second+50*time.Millisecond)) {
					t.Fatalf("incorrect deadline: %v", kv.ExpiresAt)
				}
				kv.Value[0] = 'X'
				be.advance(20 * time.Millisecond)
				again, ok, err := reader.GetWithExpiry(ctx, key)
				if err != nil || !ok || string(again.Value) != "value" || again.ExpiresAt.After(kv.ExpiresAt.Add(time.Millisecond)) {
					t.Fatalf("mutation/extended deadline: %+v", again)
				}
				if err := be.store.Set(ctx, key, []byte("permanent"), 0); err != nil {
					t.Fatal(err)
				}
				permanent, ok, err := reader.GetWithExpiry(ctx, key)
				if err != nil || !ok || !permanent.ExpiresAt.IsZero() || string(permanent.Value) != "permanent" {
					t.Fatalf("permanent: %+v", permanent)
				}
				be.store.Set(ctx, key, []byte("expired"), time.Millisecond)
			}
			be.advance(5 * time.Millisecond)
			for _, key := range []string{"botdns:test", "block:192.0.2.42"} {
				if _, ok, err := reader.GetWithExpiry(ctx, key); ok || err != nil {
					t.Fatalf("expired %s: %v %v", key, ok, err)
				}
			}
			// Concurrent replacement must not pair one value with another version's TTL.
			done := make(chan error, 1)
			go func() {
				for i := range 50 {
					raw, ttl := "short", time.Hour
					if i%2 == 0 {
						raw, ttl = "long", 2*time.Hour
					}
					if err := be.store.Set(ctx, "snapshot", []byte(raw), ttl); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			for range 100 {
				kv, found, err := reader.GetWithExpiry(ctx, "snapshot")
				if err != nil {
					t.Fatal(err)
				}
				if !found {
					continue
				}
				remaining := time.Until(kv.ExpiresAt)
				if (string(kv.Value) == "short" && (remaining < 59*time.Minute || remaining > 61*time.Minute)) || (string(kv.Value) == "long" && (remaining < 119*time.Minute || remaining > 121*time.Minute)) {
					t.Fatalf("torn snapshot: %+v", kv)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if rec.ops.Load() != 109 || rec.errs.Load() != 0 {
				t.Fatalf("instrumentation: %d ops %d errors", rec.ops.Load(), rec.errs.Load())
			}
		})
	}
}
