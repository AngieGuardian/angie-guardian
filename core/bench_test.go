// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const benchYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
  allowlist:
    ips: [ "10.0.0.0/8" ]
    paths: [ "/robots.txt", "/.well-known/" ]
  denylist:
    ips: [ "203.0.113.0/24" ]
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
`

func benchEngine(b *testing.B, st store.Store) (*Engine, *pow.Manager) {
	b.Helper()
	path := filepath.Join(b.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(benchYAML), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		b.Fatal(err)
	}
	key, err := pow.LoadOrCreateKey(filepath.Join(b.TempDir(), "ed25519.key"))
	if err != nil {
		b.Fatal(err)
	}
	mgr := pow.NewManager(key, st)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewEngine(cfg, st, mgr, log), mgr
}

// benchToken mints a real token by issuing at difficulty 0 (any nonce passes).
func benchToken(b *testing.B, mgr *pow.Manager, host, ip, ua string) string {
	b.Helper()
	ctx := context.Background()
	ch, err := mgr.Issue(ctx, host, ip, "/", 0, time.Minute, false)
	if err != nil {
		b.Fatal(err)
	}
	res, err := mgr.Redeem(ctx, &pow.RedeemRequest{
		ChallengeID: ch.ID, Nonce: "0",
		Host: host, IP: ip, UserAgent: ua,
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		b.Fatal(err)
	}
	return res.Token
}

func benchmarkEvaluate(b *testing.B, st store.Store, req *RequestContext, wantReason string) {
	b.Helper()
	e, mgr := benchEngine(b, st)
	if req.Cookie == "cookie" { // sentinel: mint a real token for this client
		req.Cookie = pow.CookieName + "=" + benchToken(b, mgr, req.Host, req.RemoteAddr, req.UserAgent)
	}
	ctx := context.Background()
	if d := e.Evaluate(ctx, req); d.Reason != wantReason {
		b.Fatalf("sanity: reason = %q, want %q", d.Reason, wantReason)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Evaluate(ctx, req)
		}
	})
}

func BenchmarkEvaluateAllowDefault(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page?x=1", RemoteAddr: "198.51.100.7", UserAgent: "curl/8.0"},
		"default")
}

func BenchmarkEvaluateAllowlistIP(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page", RemoteAddr: "10.1.2.3", UserAgent: "curl/8.0"},
		"allowlist:ip")
}

func BenchmarkEvaluateDeny(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page", RemoteAddr: "203.0.113.9", UserAgent: "curl/8.0"},
		"denylist:ip")
}

// BenchmarkEvaluatePoWTokenCached is the production common path: a vouched
// browser re-requesting with a valid cookie (token verify served from cache).
func BenchmarkEvaluatePoWTokenCached(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "html.test", Method: "GET", URI: "/page", RemoteAddr: "198.51.100.7",
			UserAgent: "Mozilla/5.0", Cookie: "cookie"},
		"pow:token")
}

func BenchmarkEvaluateChallengeDecision(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "html.test", Method: "GET", URI: "/page", RemoteAddr: "198.51.100.7", UserAgent: "Mozilla/5.0"},
		"pow:no_token")
}

// BenchmarkEvaluateWithBolt measures the full pipeline with the persistent
// store in the loop (behaviour-block lookup per request).
func BenchmarkEvaluateWithBolt(b *testing.B) {
	st, err := store.NewBolt(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page?x=1", RemoteAddr: "198.51.100.7", UserAgent: "curl/8.0"},
		"default")
}
