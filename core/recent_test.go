// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestRecentRing(t *testing.T) {
	var r recentRing

	// Empty ring.
	if got := r.list(0); len(got) != 0 {
		t.Fatalf("empty ring list = %d entries, want 0", len(got))
	}

	// Under capacity: newest first, limit respected.
	for i := 0; i < 5; i++ {
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	got := r.list(0)
	if len(got) != 5 || got[0].URI != "/4" || got[4].URI != "/0" {
		t.Fatalf("list = %+v, want /4../0 newest-first", got)
	}
	if got := r.list(2); len(got) != 2 || got[0].URI != "/4" || got[1].URI != "/3" {
		t.Fatalf("list(2) = %+v, want [/4 /3]", got)
	}

	// Overfill past capacity: oldest entries overwritten, order kept.
	for i := 5; i < defaultRecentSize+10; i++ {
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	got = r.list(0)
	if len(got) != defaultRecentSize {
		t.Fatalf("wrapped ring holds %d, want %d", len(got), defaultRecentSize)
	}
	if got[0].URI != "/"+strconv.Itoa(defaultRecentSize+9) {
		t.Errorf("newest = %s, want /%d", got[0].URI, defaultRecentSize+9)
	}
	if got[defaultRecentSize-1].URI != "/10" {
		t.Errorf("oldest = %s, want /10 (0..9 overwritten)", got[defaultRecentSize-1].URI)
	}
}

func TestRecentRingCustomSizeAndSnapshot(t *testing.T) {
	r := newRecentRing(3)
	if snap := r.snapshot(0); len(snap.Decisions) != 0 || snap.Capacity != 3 || snap.Full || snap.StartedAt.IsZero() {
		t.Fatalf("empty snapshot = %+v, want initialized capacity 3", snap)
	}
	for i := 0; i < 4; i++ {
		if i == 3 {
			snap := r.snapshot(0)
			if snap.Full || len(snap.Decisions) != 3 {
				t.Fatalf("exact-capacity snapshot = %+v, want complete but not overwritten", snap)
			}
		}
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	snap := r.snapshot(0)
	if snap.Capacity != 3 || !snap.Full || len(snap.Decisions) != 3 {
		t.Fatalf("wrapped snapshot = %+v, want capacity 3 full with 3 entries", snap)
	}
	if snap.Decisions[0].URI != "/3" || snap.Decisions[2].URI != "/1" {
		t.Fatalf("wrapped decisions = %+v, want /3../1", snap.Decisions)
	}
}

func TestRecentRingConcurrentSnapshot(t *testing.T) {
	r := newRecentRing(64)
	var wg sync.WaitGroup
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				r.add(RecentDecision{Time: time.Now(), URI: "/" + strconv.Itoa(writer) + "/" + strconv.Itoa(i)})
				_ = r.snapshot(16)
			}
		}(writer)
	}
	wg.Wait()
	if snap := r.snapshot(0); len(snap.Decisions) != 64 || !snap.Full {
		t.Fatalf("final snapshot = %+v, want full 64-entry ring", snap)
	}
}

func BenchmarkRecentRingSnapshot(b *testing.B) {
	for _, size := range []int{512, 4096, 16384, 65536} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			r := newRecentRing(size)
			for i := 0; i < size; i++ {
				r.add(RecentDecision{
					Time: time.Now(), Host: "protected.example", IP: "203.0.113.10",
					Method: "GET", URI: "/wp-login.php?source=distributed-scan",
					UA:     "Mozilla/5.0 (compatible; GuardianBenchmarkBot/1.0)",
					Action: "deny", Reason: "denylist:ip",
				})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = r.snapshot(0)
			}
		})
	}
}
