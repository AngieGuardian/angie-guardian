// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"path/filepath"
	"strconv"
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
		if _, err := m.Issue(ctx, "bench.test", string(ip), "/page?x=1", 8, time.Minute, false); err != nil {
			b.Fatal(err)
		}
	}
}
