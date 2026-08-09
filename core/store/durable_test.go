// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"testing"
	"time"
)

// TestPebbleConformance runs the full Store contract against the Pebble adapter
// in both durability modes, proving byte-for-byte semantic parity with the
// in-memory store: CAS anti-replay, IncrByDeadline rules 2/3/4, per-key TTL, and
// sorted prefix scan. Pebble emulates TTL with a nanosecond expiry prefix, so the
// fine-grained (sub-second) window is used, same as the in-memory suite.
func TestPebbleConformance(t *testing.T) {
	for _, sync := range []bool{false, true} {
		name := "async"
		if sync {
			name = "sync"
		}
		t.Run(name, func(t *testing.T) {
			st, err := NewPebble(t.TempDir(), PebbleOptions{Sync: sync})
			if err != nil {
				t.Fatalf("open pebble: %v", err)
			}
			defer st.Close()
			assertStoreConformance(t, st, sleepAdvance, 500*time.Millisecond, 200*time.Millisecond)
		})
	}
}

// TestPebbleSweepExpired proves the janitor physically removes expired records
// (not just hides them at read time) while leaving live and permanent keys, and
// that Close is idempotent.
func TestPebbleSweepExpired(t *testing.T) {
	st, err := NewPebble(t.TempDir(), PebbleOptions{})
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	ctx := t.Context()
	if err := st.Set(ctx, "dead", []byte("x"), 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(ctx, "live", []byte("y"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(ctx, "perm", []byte("z"), 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	st.sweepExpired()

	// The expired record must be physically gone from the LSM, not merely
	// filtered by the expiry decode.
	if _, _, err := st.db.Get([]byte("dead")); err == nil {
		t.Error("expired record still physically present after sweep")
	}
	for _, key := range []string{"live", "perm"} {
		if _, ok, err := st.Get(ctx, key); err != nil || !ok {
			t.Errorf("sweep removed live key %q (ok=%v err=%v)", key, ok, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got: %v", err)
	}
}

func TestPebbleDeferredWriteEncoding(t *testing.T) {
	st, err := NewPebble(t.TempDir(), PebbleOptions{})
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	defer st.Close()

	ctx := t.Context()
	ttl := time.Hour
	value := []byte("caller-owned challenge record")
	before := time.Now()
	if err := st.Set(ctx, "challenge:deferred", value, ttl); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	clear(value)

	raw, closer, err := st.db.Get([]byte("challenge:deferred"))
	if err != nil {
		t.Fatal(err)
	}
	exp, payload, ok := splitExpiry(raw)
	if !ok {
		t.Fatal("deferred write has no expiry prefix")
	}
	if !bytes.Equal(payload, []byte("caller-owned challenge record")) {
		t.Fatalf("deferred write retained caller bytes: %q", payload)
	}
	expiresAt := time.Unix(0, exp)
	if expiresAt.Before(before.Add(ttl)) || expiresAt.After(after.Add(ttl)) {
		t.Fatalf("expiry = %v, want between %v and %v", expiresAt, before.Add(ttl), after.Add(ttl))
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := st.Set(ctx, "challenge:permanent", []byte("record"), 0); err != nil {
		t.Fatal(err)
	}
	raw, closer, err = st.db.Get([]byte("challenge:permanent"))
	if err != nil {
		t.Fatal(err)
	}
	exp, payload, ok = splitExpiry(raw)
	if !ok || exp != 0 || !bytes.Equal(payload, []byte("record")) {
		t.Fatalf("permanent deferred write = exp %d payload %q ok %v", exp, payload, ok)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}
