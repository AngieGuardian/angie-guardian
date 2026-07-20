// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Store-engine benchmark harness. It drives the raw store.Store interface (no
// HTTP, no instrumentation) with the write shapes Guardian's hot path actually
// produces, so we can pick a replacement for bbolt on data:
//
//	SpentFlood      — 100% unique-key create-only CAS: the single-spend marker
//	                  write under a fresh-client DDoS (stateless_challenge.go).
//	                  This is the decisive test that separates the backends.
//	TTLCounter      — IncrByDeadline on a small hot keyspace: the CounterCache
//	                  flush load (per-IP sliding-window counters).
//	MixedReadWrite  — Get vs create-only CAS at 90/10 and 50/50.
//	ExpiryReclaim   — steady-state throughput while entries expire under the read.
//
// Every benchmark runs each candidate as a sub-benchmark so one `go test -bench`
// invocation yields comparable /Memory, /Sharded256, /Bolt lines.

// benchStoreNames is the shipped-backend comparison:
//   - Sharded256 — the in-memory ceiling (production default = NewShardedMemory(0)).
//   - each durable embedded backend in "-async" (fast, bounded replay window on
//     crash) and "-sync" (fsync every write, fully durable) mode.
//
// Pebble and BuntDB are the two durable backends that ship. They won a bake-off
// against Badger/NutsDB/goleveldb and bbolt (see testdata/durable-bakeoff.txt),
// which is why bbolt was retired. The Sharded16/64/256 shard-count sweep that
// justified the 256 default lives in git history.
var benchStoreNames = []string{
	"Sharded256",
	"BuntDB-async",
	"BuntDB-sync",
	"Pebble-async",
	"Pebble-sync",
}

// newCandidate builds a fresh store for one sub-benchmark and registers its
// cleanup (Close stops background goroutines; b.TempDir is per-sub-bench so each
// disk store gets a fresh dir/file, closed before the next candidate runs).
func newCandidate(b *testing.B, name string) Store {
	b.Helper()
	dir := b.TempDir()
	var st Store
	var err error
	switch name {
	case "Sharded256":
		st = NewShardedMemory(256)
	case "BuntDB-async":
		st, err = NewBuntDB(filepath.Join(dir, "bench.db"), BuntDBOptions{Sync: false})
	case "BuntDB-sync":
		st, err = NewBuntDB(filepath.Join(dir, "bench.db"), BuntDBOptions{Sync: true})
	case "Pebble-async":
		st, err = NewPebble(dir, PebbleOptions{Sync: false})
	case "Pebble-sync":
		st, err = NewPebble(dir, PebbleOptions{Sync: true})
	default:
		b.Fatalf("unknown candidate %q", name)
	}
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	return st
}

// benchValue is the tiny spent-marker payload (matches stateless_challenge.go's
// []byte{1}); shared so no benchmark allocates it per iteration.
var benchValue = []byte{1}

// The map key must become a string regardless of backend (Go maps key on
// string), so the single string(buf) allocation per write is inherent to the
// workload and identical across candidates — it does not bias the comparison.

func BenchmarkSpentFlood(b *testing.B) {
	ctx := context.Background()
	ttl := time.Minute
	for _, name := range benchStoreNames {
		b.Run(name, func(b *testing.B) {
			st := newCandidate(b, name)
			var ctr atomic.Uint64
			// Sanity: the first create-only CAS on a fresh key must win exactly once.
			if ok, err := st.CompareAndSwap(ctx, "spent1:sanity", nil, benchValue, ttl); err != nil || !ok {
				b.Fatalf("create-only CAS sanity = %v %v, want true nil", ok, err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				buf := make([]byte, 0, 32)
				for pb.Next() {
					n := ctr.Add(1)
					buf = append(buf[:0], "spent1:"...)
					buf = strconv.AppendUint(buf, n, 16)
					// Unique key per iteration → CAS creates (returns true) once.
					st.CompareAndSwap(ctx, string(buf), nil, benchValue, ttl)
				}
			})
		})
	}
}

func BenchmarkTTLCounter(b *testing.B) {
	ctx := context.Background()
	const hotN = 64 // small keyspace → real per-key contention on the counter
	for _, name := range benchStoreNames {
		b.Run(name, func(b *testing.B) {
			st := newCandidate(b, name)
			deadline := time.Now().Add(time.Minute).UnixNano()
			var ctr atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				buf := make([]byte, 0, 32)
				for pb.Next() {
					n := ctr.Add(1) % hotN
					buf = append(buf[:0], "ctr:"...)
					buf = strconv.AppendUint(buf, n, 10)
					st.IncrByDeadline(ctx, string(buf), 1, deadline)
				}
			})
		})
	}
}

func BenchmarkMixedReadWrite(b *testing.B) {
	ctx := context.Background()
	ttl := time.Minute
	const hotN = 1024
	// writePct out of 10: 1 => 90/10 read/write, 5 => 50/50.
	for _, mix := range []struct {
		label     string
		writeOf10 uint64
	}{
		{"90-10", 1},
		{"50-50", 5},
	} {
		for _, name := range benchStoreNames {
			b.Run(mix.label+"/"+name, func(b *testing.B) {
				st := newCandidate(b, name)
				// Pre-populate the hot keyspace so Get has something to read.
				buf := make([]byte, 0, 32)
				for i := range uint64(hotN) {
					buf = append(buf[:0], "mix:"...)
					buf = strconv.AppendUint(buf, i, 10)
					if err := st.Set(ctx, string(buf), benchValue, ttl); err != nil {
						b.Fatal(err)
					}
				}
				var ctr atomic.Uint64
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					lbuf := make([]byte, 0, 32)
					for pb.Next() {
						n := ctr.Add(1)
						k := n % hotN
						lbuf = append(lbuf[:0], "mix:"...)
						lbuf = strconv.AppendUint(lbuf, k, 10)
						key := string(lbuf)
						if n%10 < mix.writeOf10 {
							// Create-only CAS on an existing key: exercises the write
							// path (returns false, but does the read+compare work).
							st.CompareAndSwap(ctx, key, nil, benchValue, ttl)
						} else {
							st.Get(ctx, key)
						}
					}
				})
			})
		}
	}
}

func BenchmarkExpiryReclaim(b *testing.B) {
	ctx := context.Background()
	const fillN = 5000
	for _, name := range benchStoreNames {
		// Expiry reclaim is an in-memory-store concern (lazy-expire-on-read). Bolt
		// is excluded here: its per-key fsync'd fill of fillN keys dominates the
		// wall clock and would make `make bench-store` unusably slow, without
		// telling us anything the SpentFlood write numbers don't already show.
		if name == "Bolt" {
			continue
		}
		b.Run(name, func(b *testing.B) {
			st := newCandidate(b, name)
			// Fill with a short TTL, then let it lapse so the timed loop constantly
			// trips lazy-expire-on-read.
			buf := make([]byte, 0, 32)
			for i := range fillN {
				buf = append(buf[:0], "exp:"...)
				buf = strconv.AppendInt(buf, int64(i), 10)
				if err := st.Set(ctx, string(buf), benchValue, 10*time.Millisecond); err != nil {
					b.Fatal(err)
				}
			}
			time.Sleep(30 * time.Millisecond) // past the TTL
			var ctr atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				lbuf := make([]byte, 0, 32)
				for pb.Next() {
					n := int64(ctr.Add(1)) % fillN
					lbuf = append(lbuf[:0], "exp:"...)
					lbuf = strconv.AppendInt(lbuf, n, 10)
					// Reads on expired keys reclaim them (Memory/Sharded) or miss (Bolt).
					st.Get(ctx, string(lbuf))
				}
			})
		})
	}
}
