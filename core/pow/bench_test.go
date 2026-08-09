// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

func benchManagerAndToken(b *testing.B) (*Manager, string) {
	b.Helper()
	key, err := LoadOrCreateKey(filepath.Join(b.TempDir(), "ed25519.key"))
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	m := NewManager(key, st)

	ch, err := m.Issue(context.Background(), "bench.test", "198.51.100.7", "/", 0, time.Minute, false)
	if err != nil {
		b.Fatal(err)
	}
	res, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: "0",
		Host: "bench.test", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		b.Fatal(err)
	}
	return m, res.Token
}

func BenchmarkVerifyTokenUncached(b *testing.B) {
	m, token := benchManagerAndToken(b)
	b.ReportAllocs()
	for b.Loop() {
		m.cache = newTokenCache() // force the full Ed25519 path every time
		if err := m.VerifyToken(token, "bench.test", "198.51.100.7", "UA", 0, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenCached(b *testing.B) {
	m, token := benchManagerAndToken(b)
	if err := m.VerifyToken(token, "bench.test", "198.51.100.7", "UA", 0, 0); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := m.VerifyToken(token, "bench.test", "198.51.100.7", "UA", 0, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkIssue mints one stateful challenge: the random id, the HMAC over
// the {host, ip, bucket, id} binding, the JSON issuance record and the
// create-only store CAS. It is the deterministic core of the challenge write
// path, and unlike the transport-level BenchmarkChallengeIssue it touches no
// CounterCache, so it spawns no background flush goroutines and its allocs/op
// is stable enough to gate (see allocs-baseline.txt).
func BenchmarkIssue(b *testing.B) {
	benchmarkIssue(b, "bench.test")
}

// BenchmarkIssueMixedCaseHost pins the one-allocation normalization path.
// BenchmarkIssue deliberately uses the overwhelmingly common lowercase host;
// without this second gate a duplicate ToLower call is invisible there.
func BenchmarkIssueMixedCaseHost(b *testing.B) {
	benchmarkIssue(b, "Bench.TEST")
}

func benchmarkIssue(b *testing.B, host string) {
	b.Helper()
	key, err := LoadOrCreateKey(filepath.Join(b.TempDir(), "ed25519.key"))
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	m := NewManager(key, st)
	ctx := context.Background()

	// A distinct client per iteration, like a flood of new visitors: the id is
	// random per call, so no two iterations collide on the challenge key.
	var ipBuf [16]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		ip := append(ipBuf[:0], "10."...)
		ip = strconv.AppendInt(ip, int64((i>>16)&0x3f|0x40), 10)
		ip = append(ip, '.')
		ip = strconv.AppendInt(ip, int64((i>>8)&0xff), 10)
		ip = append(ip, '.')
		ip = strconv.AppendInt(ip, int64(i&0xff), 10)
		if _, err := m.Issue(ctx, host, string(ip), "/page?x=1", 8, time.Minute, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRecordBufferAfterLargeRecord measures the review-sensitive reuse
// pattern: one retained near-ceiling record followed by ordinary short ones.
// put clears retained capacity for request-data privacy, so the ceiling bounds
// the per-request clearing work this benchmark observes.
func BenchmarkRecordBufferAfterLargeRecord(b *testing.B) {
	var cache recordBufferCache
	large := cache.get()
	large.Grow(maxPooledRecordBuffer)
	large.Write(bytes.Repeat([]byte{'x'}, maxPooledRecordBuffer-1))
	cache.put(large)
	rec := &record{State: "issued", Host: "bench.test", IP: "203.0.113.7", Challenge: strings.Repeat("a", 64), URI: "/"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		buf := cache.get()
		if _, err := encodeIssuedRecord(buf, rec); err != nil {
			b.Fatal(err)
		}
		cache.put(buf)
	}
}

// BenchmarkIssueParallel exercises both issuance pools and store writes under
// concurrent normal-mode traffic. It is not allocation-gated because worker
// scheduling makes harness allocations nondeterministic; BenchmarkIssue owns
// the exact allocation regression gate.
func BenchmarkIssueParallel(b *testing.B) {
	key, err := LoadOrCreateKey(filepath.Join(b.TempDir(), "ed25519.key"))
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	m := NewManager(key, st)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := m.Issue(ctx, "bench.test", "203.0.113.7", "/page?x=1", 8, time.Minute, false); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkIssueStateless covers the attack-mode issuance core: an
// authenticated self-contained challenge ID and solve string, with no store
// write. A flood is exactly when this path takes over, so its allocation count
// must be watched independently from ordinary stateful issuance.
func BenchmarkIssueStateless(b *testing.B) {
	key, err := LoadOrCreateKey(filepath.Join(b.TempDir(), "ed25519.key"))
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	m := NewManager(key, st)

	var ipBuf [16]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		ip := append(ipBuf[:0], "10."...)
		ip = strconv.AppendInt(ip, int64((i>>16)&0x3f|0x40), 10)
		ip = append(ip, '.')
		ip = strconv.AppendInt(ip, int64((i>>8)&0xff), 10)
		ip = append(ip, '.')
		ip = strconv.AppendInt(ip, int64(i&0xff), 10)
		if _, err := m.IssueStateless("bench.test", string(ip), "/page?x=1", 8, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIssueStatelessParallel exercises the sync.Pool behavior under the
// concurrent flood shape this path is designed for. It is intentionally not
// allocation-gated because the benchmark harness's worker goroutines make the
// exact count scheduler-dependent; BenchmarkIssueStateless owns that gate.
func BenchmarkIssueStatelessParallel(b *testing.B) {
	key, err := LoadOrCreateKey(filepath.Join(b.TempDir(), "ed25519.key"))
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	m := NewManager(key, st)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := m.IssueStateless("bench.test", "203.0.113.7", "/page?x=1", 8, false); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
