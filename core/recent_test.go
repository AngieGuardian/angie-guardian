// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"strconv"
	"testing"
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
	for i := 5; i < recentSize+10; i++ {
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	got = r.list(0)
	if len(got) != recentSize {
		t.Fatalf("wrapped ring holds %d, want %d", len(got), recentSize)
	}
	if got[0].URI != "/"+strconv.Itoa(recentSize+9) {
		t.Errorf("newest = %s, want /%d", got[0].URI, recentSize+9)
	}
	if got[recentSize-1].URI != "/10" {
		t.Errorf("oldest = %s, want /10 (0..9 overwritten)", got[recentSize-1].URI)
	}
}
