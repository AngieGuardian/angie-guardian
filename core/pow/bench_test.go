// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"path/filepath"
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
