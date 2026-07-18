// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package enforce

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a.Unmap()
}

func TestMirrorHitMissAndTTL(t *testing.T) {
	mr := newMirror(1024)
	now := time.Now().UnixNano()
	a := addr(t, "203.0.113.9")

	if _, ok := mr.get(a, now); ok {
		t.Fatal("empty mirror reported a hit")
	}
	mr.set(a, entry{reason: "threshold:tamper", expiresAt: now + int64(time.Minute), insertedAt: now})
	reason, ok := mr.get(a, now)
	if !ok || reason != "threshold:tamper" {
		t.Fatalf("get = %q, %v; want threshold:tamper, true", reason, ok)
	}
	// Expired entries read as absent even before the sweep removes them.
	if _, ok := mr.get(a, now+int64(2*time.Minute)); ok {
		t.Fatal("expired entry still reported as a hit")
	}
	// No-expiry entries (expiresAt 0) never expire.
	b := addr(t, "2001:db8::1")
	mr.set(b, entry{reason: "manual", insertedAt: now})
	if _, ok := mr.get(b, now+int64(365*24*time.Hour)); !ok {
		t.Fatal("no-expiry entry expired")
	}
}

func TestMirrorRemove(t *testing.T) {
	mr := newMirror(1024)
	now := time.Now().UnixNano()
	a := addr(t, "203.0.113.9")
	mr.set(a, entry{reason: "x", insertedAt: now})
	mr.remove(a)
	if _, ok := mr.get(a, now); ok {
		t.Fatal("removed entry still present")
	}
}

func TestMirrorCapacityOverflow(t *testing.T) {
	// Capacity is per shard; fill far past the bound and verify the count
	// stays bounded, drops are counted, and existing entries still update.
	const maxEntries = shardCount * 4
	mr := newMirror(maxEntries)
	now := time.Now().UnixNano()
	for i := range 100 * shardCount {
		mr.set(addr(t, fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			entry{reason: "x", expiresAt: now + int64(time.Hour), insertedAt: now})
	}
	if got := mr.count(); got > maxEntries {
		t.Fatalf("count %d exceeds bound %d", got, maxEntries)
	}
	if mr.dropped.Load() == 0 {
		t.Fatal("no drops recorded despite overflow")
	}

	// A full shard sheds expired entries to make room for a live one.
	mr2 := newMirror(shardCount) // one entry per shard
	victim := addr(t, "192.0.2.1")
	mr2.set(victim, entry{reason: "old", expiresAt: now - 1, insertedAt: now - 10})
	// Find another address in the same shard so the insert must evict.
	for i := range 10000 {
		a := addr(t, fmt.Sprintf("192.0.%d.%d", i/256, i%256))
		if a != victim && shardOf(a) == shardOf(victim) {
			if !mr2.set(a, entry{reason: "new", expiresAt: now + int64(time.Hour), insertedAt: now}) {
				t.Fatal("insert into full shard did not evict the expired entry")
			}
			if _, ok := mr2.get(victim, now); ok {
				t.Fatal("expired victim survived eviction")
			}
			return
		}
	}
	t.Fatal("no shard collision found")
}

func TestMirrorReconcile(t *testing.T) {
	mr := newMirror(1024)
	base := time.Now().UnixNano()
	stale := addr(t, "203.0.113.1")   // in mirror, absent from scan: removed
	updated := addr(t, "203.0.113.2") // in both: expiry corrected
	fresh := addr(t, "203.0.113.3")   // written through after scan start: kept
	scanned := addr(t, "203.0.113.4") // only in scan: added

	mr.set(stale, entry{reason: "gone", insertedAt: base - 100})
	mr.set(updated, entry{reason: "prov", expiresAt: base + int64(time.Second), insertedAt: base - 100})
	scanStart := base
	mr.set(fresh, entry{reason: "new-block", expiresAt: base + int64(time.Hour), insertedAt: base + 50})

	mr.reconcile(map[netip.Addr]entry{
		updated: {reason: "real", expiresAt: base + int64(time.Hour), insertedAt: scanStart},
		scanned: {reason: "scanned", expiresAt: base + int64(time.Hour), insertedAt: scanStart},
	}, scanStart)

	if _, ok := mr.get(stale, base); ok {
		t.Fatal("stale entry survived reconcile")
	}
	if reason, ok := mr.get(updated, base+int64(time.Minute)); !ok || reason != "real" {
		t.Fatalf("updated entry = %q, %v; want real (corrected expiry), true", reason, ok)
	}
	if _, ok := mr.get(fresh, base); !ok {
		t.Fatal("write-through entry newer than the scan was removed")
	}
	if _, ok := mr.get(scanned, base); !ok {
		t.Fatal("scanned entry was not added")
	}
}
