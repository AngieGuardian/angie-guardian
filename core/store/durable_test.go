// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
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
