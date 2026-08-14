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
	"golang.org/x/crypto/argon2"
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

// Every benchmark evaluates a FRESH RequestContext per iteration, because that
// is what the transport does: it builds one per subrequest. Reusing a single
// value across iterations would let per-request derivations (the normalized
// path, the lowercased User-Agent) be computed once for the whole run and
// silently understate the cost of the thing being measured. It is also the
// documented contract — a RequestContext belongs to one request on one
// goroutine — so a shared one would be a data race waiting for a future edit
// to expose it.
func benchmarkEvaluate(b *testing.B, st store.Store, tmpl *RequestContext, wantReason string) {
	b.Helper()
	e, mgr := benchEngine(b, st)
	if tmpl.Cookie == "cookie" { // sentinel: mint a real token for this client
		tmpl.Cookie = pow.CookieName + "=" + benchToken(b, mgr, tmpl.Host, tmpl.RemoteAddr, tmpl.UserAgent)
	}
	ctx := context.Background()
	if d := e.Evaluate(ctx, cloneRequest(tmpl)); d.Reason != wantReason {
		b.Fatalf("sanity: reason = %q, want %q", d.Reason, wantReason)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Evaluate(ctx, cloneRequest(tmpl))
		}
	})
}

// cloneRequest returns a fresh RequestContext carrying the same request fields,
// with no derivation memoized yet.
func cloneRequest(tmpl *RequestContext) *RequestContext {
	return &RequestContext{
		Host: tmpl.Host, Method: tmpl.Method, URI: tmpl.URI,
		RemoteAddr: tmpl.RemoteAddr, UserAgent: tmpl.UserAgent,
		Cookie: tmpl.Cookie, Header: tmpl.Header,
	}
}

// benchmarkEvaluateMirror wires the enforcement offload the way guardiand does
// (authoritative seeded mirror), so the block stage is served from memory. A
// "behaviour_block:" wantReason places a block for the request's IP first.
func benchmarkEvaluateMirror(b *testing.B, st store.Store, tmpl *RequestContext, wantReason string) {
	b.Helper()
	e, _ := benchEngine(b, st)
	ctx := context.Background()
	if reason, ok := strings.CutPrefix(wantReason, "behaviour_block:"); ok {
		if err := e.BlockIP(ctx, tmpl.RemoteAddr, reason, time.Hour); err != nil {
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
	if d := e.Evaluate(ctx, cloneRequest(tmpl)); d.Reason != wantReason {
		b.Fatalf("sanity: reason = %q, want %q", d.Reason, wantReason)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Evaluate(ctx, cloneRequest(tmpl))
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

// BenchmarkEvaluatePoWTokenCachedWithOneArgon2IDVerifier is the mixed-load
// isolation check: the production cached-token path runs while one bounded
// 32 MiB verifier continuously does real Argon2id work. Compare it with
// BenchmarkEvaluatePoWTokenCached on the deployment machine; the acceptance
// budget is at most 5% throughput loss for the ~150k req/s target. It is a
// manual benchmark because CI CPU topology and noise cannot produce a stable
// timing gate.
func BenchmarkEvaluatePoWTokenCachedWithOneArgon2IDVerifier(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	e, mgr := benchEngine(b, st)
	tmpl := &RequestContext{Host: "html.test", Method: "GET", URI: "/page", RemoteAddr: "198.51.100.7", UserAgent: "Mozilla/5.0"}
	tmpl.Cookie = pow.CookieName + "=" + benchToken(b, mgr, tmpl.Host, tmpl.RemoteAddr, tmpl.UserAgent)
	ctx := context.Background()
	if d := e.Evaluate(ctx, cloneRequest(tmpl)); d.Reason != "pow:token" {
		b.Fatalf("sanity: reason = %q, want pow:token", d.Reason)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				proof := argon2.IDKey([]byte("guardian mixed-load verifier"), []byte("0123456789abcdef"), 1, 32*1024, 1, 32)
				clear(proof)
			}
		}
	}()
	b.Cleanup(func() { close(stop); <-done })

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Evaluate(ctx, cloneRequest(tmpl))
		}
	})
}

func BenchmarkEvaluateChallengeDecision(b *testing.B) {
	st := store.NewMemory()
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "html.test", Method: "GET", URI: "/page", RemoteAddr: "198.51.100.7", UserAgent: "Mozilla/5.0"},
		"pow:no_token")
}

// BenchmarkEvaluateWithPebble measures the full pipeline with the persistent
// store in the loop (behaviour-block lookup per request).
func BenchmarkEvaluateWithPebble(b *testing.B) {
	st, err := store.NewPebble(b.TempDir(), store.PebbleOptions{Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	benchmarkEvaluate(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page?x=1", RemoteAddr: "198.51.100.7", UserAgent: "curl/8.0"},
		"default")
}

// BenchmarkEvaluatePebbleMirror is the production authoritative-mirror path on a
// pebble store: the block check is served from the seeded in-process mirror, so
// the per-request store read is gone. Compare against BenchmarkEvaluateWithPebble
// (same store, no enforcer) to see the offload's hot-path win.
func BenchmarkEvaluatePebbleMirror(b *testing.B) {
	st, err := store.NewPebble(b.TempDir(), store.PebbleOptions{Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	benchmarkEvaluateMirror(b, st,
		&RequestContext{Host: "plain.test", Method: "GET", URI: "/page?x=1", RemoteAddr: "198.51.100.7", UserAgent: "curl/8.0"},
		"default")
}

// BenchmarkEvaluatePebbleMirrorBlocked measures a blocked client under the
// mirror: the denial is a memory lookup with zero store I/O, the exact flood
// case the offload exists for.
func BenchmarkEvaluatePebbleMirrorBlocked(b *testing.B) {
	st, err := store.NewPebble(b.TempDir(), store.PebbleOptions{Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	req := &RequestContext{Host: "plain.test", Method: "GET", URI: "/p", RemoteAddr: "198.51.100.9", UserAgent: "curl/8.0"}
	benchmarkEvaluateMirror(b, st, req, "behaviour_block:flood")
}

// benchRulesYAML is a realistic starter rule match set: every request that
// reaches the WAF stage scans it, so its cost is paid on the common path, not
// only when something matches.
const benchRulesYAML = `
rules:
  - id: dotfile
    targets: [path]
    keywords: [ "/.env", "/.git/", "/.aws/", "/.ssh/" ]
  - id: admin-probe
    targets: [path]
    keywords: [ "/wp-admin", "/phpmyadmin", "/administrator/" ]
  - id: traversal
    targets: [path, query]
    regexes: [ "\\.\\./", "%2e%2e" ]
  - id: sqli
    targets: [query]
    regexes: [ "union\\s+select", "or\\s+1=1", "sleep\\(" ]
  - id: scanner-ua
    targets: [ua]
    keywords: [ "sqlmap", "nikto", "masscan", "nuclei" ]
  - id: shellshock
    targets: [ "header:user-agent", "header:referer" ]
    keywords: [ "() {" ]
  - id: trace
    methods: [ TRACE, TRACK ]
`

// BenchmarkEvaluateWAFClean is the case the WAF actually spends its life in:
// a legitimate request scanned against the whole rule set and matching none of
// it. A benchmark that only measures a matching request measures the rare path.
func BenchmarkEvaluateWAFClean(b *testing.B) {
	dir := b.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte(benchRulesYAML), 0o600); err != nil {
		b.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "guardian.yaml")
	cfgYAML := "store: { backend: memory }\ndefaults:\n  waf:\n    rules: { enabled: true, files: [ " +
		strconv.Quote(rules) + " ] }\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(e.Close)

	tmpl := &RequestContext{
		Host: "shop.test", Method: "GET",
		URI:        "/products/1234/reviews?page=2&sort=recent",
		RemoteAddr: "198.51.100.7",
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
		Header:     func(string) []string { return nil },
	}
	ctx := context.Background()
	if d := e.Evaluate(ctx, cloneRequest(tmpl)); d.Reason != "default" {
		b.Fatalf("sanity: reason = %q, want default", d.Reason)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Evaluate(ctx, cloneRequest(tmpl))
		}
	})
}

// BenchmarkShedDecision measures the load-shedding gate, which replaces the
// full pipeline once attack_mode.effects.max_inflight is reached. It has to be
// dramatically cheaper than Evaluate or it cannot relieve the saturation it
// exists for.
func BenchmarkShedDecision(b *testing.B) {
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	e, mgr := benchEngine(b, st)
	enf := enforce.New(e.Config().EnforceConfig(), st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { enf.Close() })
	e.SetEnforcer(enf)
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	enf.Start(ctx)
	for !enf.Status().Mirror.Seeded {
		time.Sleep(time.Millisecond)
	}
	tmpl := &RequestContext{
		Host: "html.test", Method: "GET", URI: "/dashboard",
		RemoteAddr: "198.51.100.7", UserAgent: "Mozilla/5.0 Firefox/140.0",
		Cookie: pow.CookieName + "=" + benchToken(b, mgr, "html.test", "198.51.100.7", "Mozilla/5.0 Firefox/140.0"),
	}
	if v := e.ShedDecision(cloneRequest(tmpl)); v != ShedPass {
		b.Fatalf("sanity: verdict = %v, want ShedPass", v)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.ShedDecision(cloneRequest(tmpl))
		}
	})
}

// BenchmarkRecordEvent is the behaviour-scoring write path: one bad event
// counted for one IP, below the threshold so no block is placed. It is not the
// auth hot path (only a non-allow decision produces events), but a rule match
// flood drives it once per request. It performs two exact-key store operations:
// a generation read and one atomic guarded increment. Measured here so that
// coordination's cost remains a number.
func BenchmarkRecordEvent(b *testing.B) {
	ctx := context.Background()
	st := store.NewMemory()
	defer st.Close()
	board := NewScoreboard(st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		// A fresh IP every 1000 events, so the counter neither trips the
		// threshold nor turns into a single-key hot spot.
		ip := "198.51." + strconv.Itoa(i/1000%256) + "." + strconv.Itoa(i%256)
		if _, err := board.RecordEvent(ctx, ip, "rule_match", 1<<30, time.Minute, time.Minute, time.Hour); err != nil {
			b.Fatal(err)
		}
	}
}
