// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"
)

// BenchmarkPebbleChallengeCAS isolates the three CompareAndSwap shapes used by
// stateful challenges. It is a manual diagnostic rather than an allocation
// gate: Pebble's flush and compaction goroutines make whole-process allocation
// accounting scheduler-dependent.
func BenchmarkPebbleChallengeCAS(b *testing.B) {
	for _, size := range []int{96, 1024} {
		b.Run("create-only/bytes="+strconv.Itoa(size), func(b *testing.B) {
			st, err := NewPebble(b.TempDir(), PebbleOptions{Sync: false})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { st.Close() })
			keys := make([]string, b.N)
			for i := range keys {
				keys[i] = "challenge:" + strconv.Itoa(i)
			}
			value := bytes.Repeat([]byte{'i'}, size)
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, err := st.CompareAndSwap(ctx, keys[i], nil, value, time.Minute)
				if err != nil || !ok {
					b.Fatalf("create-only CAS %d = %v, %v; want true, nil", i, ok, err)
				}
			}
		})

		b.Run("collision/bytes="+strconv.Itoa(size), func(b *testing.B) {
			st, err := NewPebble(b.TempDir(), PebbleOptions{Sync: false})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { st.Close() })
			value := bytes.Repeat([]byte{'i'}, size)
			ctx := context.Background()
			if err := st.Set(ctx, "challenge:collision", value, time.Minute); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				ok, err := st.CompareAndSwap(ctx, "challenge:collision", nil, value, time.Minute)
				if err != nil || ok {
					b.Fatalf("collision CAS = %v, %v; want false, nil", ok, err)
				}
			}
		})

		b.Run("issued-to-spent/bytes="+strconv.Itoa(size), func(b *testing.B) {
			st, err := NewPebble(b.TempDir(), PebbleOptions{Sync: false})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { st.Close() })
			issued := bytes.Repeat([]byte{'i'}, size)
			spent := bytes.Repeat([]byte{'s'}, size-1)
			ctx := context.Background()
			if err := st.Set(ctx, "challenge:redeem", issued, time.Minute); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				old, next := issued, spent
				if i&1 != 0 {
					old, next = spent, issued
				}
				ok, err := st.CompareAndSwap(ctx, "challenge:redeem", old, next, time.Minute)
				if err != nil || !ok {
					b.Fatalf("issued-to-spent CAS %d = %v, %v; want true, nil", i, ok, err)
				}
			}
		})
	}
}
