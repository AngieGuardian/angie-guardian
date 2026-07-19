// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const benchYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
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
	e, err := NewEngine(cfg, st, mgr, log)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(e.Close)
	return e, mgr
}

// benchToken mints a real token at the minimum production difficulty.
func benchToken(b *testing.B, mgr *pow.Manager, host, ip, ua string) string {
	b.Helper()
	ctx := context.Background()
	const difficulty = 4
	ch, err := mgr.Issue(ctx, host, ip, "/", difficulty, time.Minute, false)
	if err != nil {
		b.Fatal(err)
	}
	var nonce string
	for n := 0; ; n++ {
		nonce = strconv.Itoa(n)
		sum := sha256.Sum256([]byte(ch.Challenge + nonce))
		leading := 0
		for _, v := range sum {
			if v != 0 {
				leading += bits.LeadingZeros8(v)
				break
			}
			leading += 8
		}
		if leading >= difficulty {
			break
		}
	}
	res, err := mgr.Redeem(ctx, &pow.RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
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

// benchmarkEvaluateMirror wires the enforcement offload the way guardiand does
// (authoritative seeded mirror), so the block stage is served from memory. A
// "behaviour_block:" wantReason places a block for the request's IP first.
func benchmarkEvaluateMirror(b *testing.B, st store.Store, req *RequestContext, wantReason string) {
	b.Helper()
	e, _ := benchEngine(b, st)
	ctx := context.Background()
	if reason, ok := strings.CutPrefix(wantReason, "behaviour_block:"); ok {
		if err := e.BlockIP(ctx, req.RemoteAddr, reason, time.Hour); err != nil {
			b.Fatal(err)
		}
	}
	enf := enforce.New(e.Config().EnforceConfig(), st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { enf.Close() })
	e.SetEnforcer(enf)
	ectx, cancel := context.WithCancel(ctx)
	b.Cleanup(cancel)
	enf.Start(ectx)
	for !enf.Status().Mirror.Seeded { // wait for the seed scan
		time.Sleep(time.Millisecond)
	}
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

// BenchmarkEvaluateBoltMirror is the production authoritative-mirror path on a
// bbolt store: the block check is served from the seeded in-process mirror, so
// the per-request store read is gone. Compare against BenchmarkEvaluateWithBolt
// (same store, no enforcer) to see the offload's hot-path win.
func BenchmarkEvaluateBoltMirror(b *testing.B) {
	st, err := store.NewBolt(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	benchmarkEvaluateMirror(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page?x=1", RemoteAddr: "198.51.100.7", UserAgent: "curl/8.0"},
		"default")
}

// BenchmarkEvaluateBoltMirrorBlocked measures a blocked client under the
// mirror: the denial is a memory lookup with zero store I/O, the exact flood
// case the offload exists for.
func BenchmarkEvaluateBoltMirrorBlocked(b *testing.B) {
	st, err := store.NewBolt(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	req := &RequestContext{Host: "plain.test", Method: "GET", URI: "/p", RemoteAddr: "198.51.100.9", UserAgent: "curl/8.0"}
	benchmarkEvaluateMirror(b, st, req, "behaviour_block:flood")
}
