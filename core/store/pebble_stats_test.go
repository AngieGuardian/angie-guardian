// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"testing"
	"time"
)

func TestPebbleStatsReportsWALWrites(t *testing.T) {
	p, err := NewPebble(t.TempDir(), PebbleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Set(context.Background(), "key", []byte("value"), time.Minute); err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()
	if stats.WALBytesWritten == 0 {
		t.Errorf("WALBytesWritten = 0 after write, stats = %+v", stats)
	}
}
