// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPebbleUsesTunedOptions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sync     bool
		memtable []string
	}{
		{"async", false, []string{"mem_table_size=67108864", "mem_table_stop_writes_threshold=3"}},
		{"sync", true, []string{"mem_table_size=4194304", "mem_table_stop_writes_threshold=2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := persistedPebbleOptions(t, PebbleOptions{Sync: tc.sync})
			wants := []string{
				"bytes_per_sync=1048576",
				"cache_size=536870912",
				"concurrent_compactions=2",
				"l0_compaction_threshold=2",
				"l0_stop_writes_threshold=24",
				"max_concurrent_compactions=4",
				"block_size=4096",
				"compression=Fastest",
				"filter_policy=rocksdb.BuiltinBloomFilter",
			}
			wants = append(wants, tc.memtable...)
			for _, want := range wants {
				if !strings.Contains(options, want) {
					t.Fatalf("OPTIONS file does not contain %q:\n%s", want, options)
				}
			}
		})
	}
}

func persistedPebbleOptions(t *testing.T, opts PebbleOptions) string {
	t.Helper()
	dir := t.TempDir()
	p, err := NewPebble(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "OPTIONS-") {
			continue
		}
		options, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		return string(options)
	}
	t.Fatal("Pebble did not create an OPTIONS file")
	return ""
}

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
