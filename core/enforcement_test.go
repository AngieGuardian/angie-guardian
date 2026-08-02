// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// countingStore counts Get calls and can simulate a store outage.
type countingStore struct {
	store.Store
	gets    atomic.Int64
	failing atomic.Bool
}

var errStoreDown = errors.New("store down")

func (s *countingStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	s.gets.Add(1)
	if s.failing.Load() {
		return nil, false, errStoreDown
	}
	return s.Store.Get(ctx, key)
}

func (s *countingStore) Scan(ctx context.Context, prefix string) ([]store.KV, error) {
	if s.failing.Load() {
		return nil, errStoreDown
	}
	return s.Store.Scan(ctx, prefix)
}

// enforcedEngine builds an engine with the offload manager wired and seeded,
// the way guardiand runs in production.
func enforcedEngine(t *testing.T, yaml string) (*Engine, *countingStore) {
	t.Helper()
	cfg := loadTestConfig(t, yaml)
	cs := &countingStore{Store: store.NewMemory()}
	t.Cleanup(func() { cs.Store.Close() })
	e, err := NewEngine(cfg, cs, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	enf := enforce.New(cfg.EnforceConfig(), cs, nil, slog.Default())
	t.Cleanup(func() { enf.Close() })
	e.SetEnforcer(enf)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	enf.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !enf.Status().Mirror.Seeded {
		if time.Now().After(deadline) {
			t.Fatal("mirror seed scan never completed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return e, cs
}

func TestMirrorFastPathBlockedIPWithoutStoreReads(t *testing.T) {
	ctx := context.Background()
	e, cs := enforcedEngine(t, pipelineYAML)
	ip := "198.51.100.42"

	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("unblocked IP: got %s", d.Action)
	}
	if err := e.BlockIP(ctx, ip, "test_abuse", time.Minute); err != nil {
		t.Fatal(err)
	}
	// The write-through mirror enforces immediately, no reconcile needed.
	cs.gets.Store(0)
	d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:test_abuse" {
		t.Fatalf("blocked IP: got %s/%s", d.Action, d.Reason)
	}
	if n := cs.gets.Load(); n != 0 {
		t.Fatalf("blocked-IP evaluation performed %d store Gets; want 0 (mirror hit)", n)
	}
	// Authoritative mode: the common unblocked path also skips the store read.
	cs.gets.Store(0)
	if d := e.Evaluate(ctx, req("x.test", "198.51.100.43", "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("clean IP: got %s", d.Action)
	}
	if n := cs.gets.Load(); n != 0 {
		t.Fatalf("clean-IP evaluation performed %d store Gets; want 0 (authoritative miss)", n)
	}
	// Unblock propagates through the mirror immediately too.
	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("unblocked IP still denied: %s/%s", d.Action, d.Reason)
	}
}

func TestMirrorNeverOverridesAllowlist(t *testing.T) {
	// Pipeline order: 10.0.0.66 is allowlisted in pipelineYAML. Even with a
	// mirror entry for it, the allowlist stage terminates first.
	ctx := context.Background()
	e, _ := enforcedEngine(t, pipelineYAML)
	if err := e.BlockIP(ctx, "10.0.0.66", "framed", time.Minute); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req("x.test", "10.0.0.66", "/", "Mozilla")); d.Action != ActionAllow || d.Reason != "allowlist:ip" {
		t.Fatalf("allowlisted IP with mirror entry: got %s/%s, want allow/allowlist:ip", d.Action, d.Reason)
	}
}

func TestMirrorEnforcesThroughStoreOutage(t *testing.T) {
	ctx := context.Background()
	e, cs := enforcedEngine(t, pipelineYAML)
	ip := "198.51.100.44"
	if err := e.BlockIP(ctx, ip, "abuse", time.Minute); err != nil {
		t.Fatal(err)
	}
	cs.failing.Store(true)
	// Without the mirror this request would fail open (stage error). With it
	// the block keeps enforcing while the store is down.
	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionDeny {
		t.Fatalf("blocked IP during store outage: got %s, want deny", d.Action)
	}
}

func TestAuthoritativeMirrorOverflowFallsBackToStore(t *testing.T) {
	e, _ := enforcedEngine(t, `
store: { backend: memory }
enforcement:
  mirror: { mode: authoritative, max_entries: 32, reconcile_interval: 1h }
`)
	ctx := t.Context()
	var dropped string
	for i := range 2048 {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}).String()
		if err := e.BlockIP(ctx, ip, "capacity-test", time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, ok := e.Enforcer().Lookup(ip); !ok {
			dropped = ip
			break
		}
	}
	if dropped == "" {
		t.Fatal("test did not overflow a mirror shard")
	}
	if !e.Enforcer().ReadThrough() {
		t.Fatal("capacity-incomplete authoritative mirror did not enable store fallback")
	}
	if d := e.Evaluate(ctx, req("x.test", dropped, "/", "Mozilla")); d.Action != ActionDeny {
		t.Fatalf("persisted block dropped by mirror failed open: %s/%s", d.Action, d.Reason)
	}
}

func TestScoreboardBlocksReachTheMirror(t *testing.T) {
	// A threshold crossing (not just admin BlockIP) must write through.
	ctx := context.Background()
	e, cs := enforcedEngine(t, pipelineYAML)
	ip := "198.51.100.45"
	blocked, err := e.board.RecordEvent(ctx, ip, "tamper", 1, time.Minute, time.Minute, time.Hour)
	if err != nil || !blocked {
		t.Fatalf("RecordEvent = %v, %v; want block placed", blocked, err)
	}
	cs.gets.Store(0)
	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionDeny {
		t.Fatalf("scoreboard-blocked IP: got %s", d.Action)
	}
	if n := cs.gets.Load(); n != 0 {
		t.Fatalf("scoreboard block needed %d store Gets; want 0", n)
	}
}

// loadConfigErr loads a config expected to fail validation.
func loadConfigErr(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

const enforcementYAML = `
store: { backend: memory }
enforcement:
  mirror: { reconcile_interval: 5s, max_entries: 4096, mode: read_through }
  nftables:
    mode: sets_only
    table: guardian_test
    ports: [8080]
    never_block: [ "192.0.2.0/24", "2001:db8::1" ]
defaults:
  allowlist: { ips: [ "10.0.0.0/8" ] }
domains:
  a.test:
    allowlist: { ips: [ "172.16.0.0/12" ] }
    paths:
      /api/: { allowlist: { ips: [ "198.51.100.7" ] } }
`

func TestEnforcementConfig(t *testing.T) {
	cfg := loadTestConfig(t, enforcementYAML)
	ec := cfg.EnforceConfig()
	if ec.Mode != enforce.ModeReadThrough {
		t.Fatalf("mode = %q, want read_through", ec.Mode)
	}
	if ec.ReconcileInterval != 5*time.Second || ec.MaxEntries != 4096 {
		t.Fatalf("mirror config not mapped: %+v", ec)
	}
	if ec.KeyPrefix != "block:" {
		t.Fatalf("key prefix = %q", ec.KeyPrefix)
	}
	if ec.NFTables.Table != "guardian_test" || ec.NFTables.Mode != "sets_only" ||
		len(ec.NFTables.Ports) != 1 || ec.NFTables.Ports[0] != 8080 {
		t.Fatalf("nftables config not mapped: %+v", ec.NFTables)
	}
	// never_block plus the allowlist union across defaults, domain, path.
	want := []string{"192.0.2.0/24", "2001:db8::1/128", "10.0.0.0/8", "172.16.0.0/12", "198.51.100.7/32"}
	if len(ec.NFTables.NeverBlock) != len(want) {
		t.Fatalf("NeverBlock = %v, want %d prefixes %v", ec.NFTables.NeverBlock, len(want), want)
	}
	have := make(map[string]bool)
	for _, p := range ec.NFTables.NeverBlock {
		have[p.String()] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Fatalf("NeverBlock missing %s: %v", w, ec.NFTables.NeverBlock)
		}
	}
}

func TestEnforcementConfigDefaults(t *testing.T) {
	cfg := loadTestConfig(t, "store: { backend: memory }\n")
	en := cfg.Enforcement
	if en.Mirror.Mode != "auto" || en.Mirror.ReconcileInterval.Std() != 10*time.Second || en.Mirror.MaxEntries != 1<<20 {
		t.Fatalf("mirror defaults: %+v", en.Mirror)
	}
	nf := en.NFTables
	if nf.Enabled || nf.Mode != "managed" || nf.Hook != "input" || nf.Table != "guardian" ||
		nf.MaxEntries != 65536 || len(nf.Ports) != 2 || nf.Ports[0] != 80 || nf.Ports[1] != 443 {
		t.Fatalf("nftables defaults: %+v", nf)
	}
	if got := cfg.EnforceConfig().Mode; got != enforce.ModeAuthoritative {
		t.Fatalf("memory backend auto mode = %q, want authoritative", got)
	}
}

func TestEnforcementConfigAutoModeRedis(t *testing.T) {
	cfg := loadTestConfig(t, "trusted_proxy: true\nstore: { backend: redis, addr: \"127.0.0.1:6379\" }\n")
	if got := cfg.EnforceConfig().Mode; got != enforce.ModeReadThrough {
		t.Fatalf("redis backend auto mode = %q, want read_through", got)
	}
}

func TestEnforcementConfigValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"bad mirror mode", "enforcement: { mirror: { mode: sideways } }", "mirror.mode"},
		{"interval too small", "enforcement: { mirror: { reconcile_interval: 500ms } }", "reconcile_interval"},
		{"negative entries", "enforcement: { mirror: { max_entries: -1 } }", "max_entries"},
		{"bad nft mode", "enforcement: { nftables: { mode: chaos } }", "nftables.mode"},
		{"bad hook", "enforcement: { nftables: { hook: output } }", "hook"},
		{"bad port", "enforcement: { nftables: { ports: [0] } }", "invalid port"},
		{"bad never_block", "enforcement: { nftables: { never_block: [ nope ] } }", "never_block"},
		{"negative min_ttl", "enforcement: { nftables: { min_ttl: -1s } }", "min_ttl"},
		{"managed empty ports", "enforcement: { nftables: { enabled: true, ports: [] } }", "must not be empty in managed mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfigErr(t, "store: { backend: memory }\n"+tc.yaml+"\n")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestAllowlistUnionDedup(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
defaults:
  allowlist: { ips: [ "10.0.0.0/8" ] }
domains:
  a.test: { allowlist: { ips: [ "10.0.0.0/8" ] } }
`)
	union := cfg.AllowlistUnion()
	if len(union) != 1 || union[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("union = %v, want exactly one 10.0.0.0/8", union)
	}
}

const shedParityYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: true, base_difficulty: 1, max_difficulty: 2 }
  waf:
    ip_behaviour: { enabled: true }
    honeypot: { enabled: true, paths: [ "/trap" ] }
  allowlist:
    ips: [ "192.0.2.10" ]
  denylist:
    ips: [ "203.0.113.66" ]
    uas: [ "BadCrawler" ]
    paths: [ "/forbidden", "/private/" ]
`

// TestShedDecisionMatchesPipelineTerminals is the anti-drift check for the
// load-shedding fast path.
//
// ShedDecision reimplements the pipeline's cheap terminal stages so a saturated
// daemon can answer without a full evaluation. Reimplementing is the hazard: a
// stage that grows a new dimension leaves the copy behind, and the gap opens
// only under load, which is when it is least likely to be noticed and most
// likely to matter. That is not hypothetical. The static denylist grew uas and
// paths, CheckDenylist gained them, and the shed copy kept matching IPs alone,
// so a client holding one honestly solved token was fast-passed to a denylisted
// path for as long as the daemon stayed saturated.
//
// Every row here is a request the FULL pipeline terminates on. The shed is
// allowed to be less specific (ShedReject where the pipeline denies is a safe
// answer: the client gets a 503, not the resource) but never more permissive:
// ShedPass on anything the pipeline denies is a bypass. Each row carries a
// valid token, because a token is what makes the difference between the two
// verdicts reachable at all.
func TestShedDecisionMatchesPipelineTerminals(t *testing.T) {
	ctx := context.Background()
	cfg := loadTestConfig(t, shedParityYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := pow.NewManager(key, st)
	e, err := NewEngine(cfg, st, mgr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	const (
		cleanIP = "198.51.100.5"
		cleanUA = "Mozilla/5.0 (X11; Linux x86_64)"
	)
	// Two tokens, so each row can vary exactly one dimension: a token binds
	// host + IP + User-Agent, never a path.
	cleanToken := mintTestToken(t, mgr, "x.test", cleanIP, cleanUA, 4)
	crawlerToken := mintTestToken(t, mgr, "x.test", cleanIP, "BadCrawler/1.0", 4)

	cases := []struct {
		name               string
		ip, uri, ua, token string
	}{
		{"denylist ip", "203.0.113.66", "/", cleanUA, mintTestToken(t, mgr, "x.test", "203.0.113.66", cleanUA, 4)},
		{"denylist ua", cleanIP, "/", "BadCrawler/1.0", crawlerToken},
		{"denylist path, exact", cleanIP, "/forbidden", cleanUA, cleanToken},
		{"denylist path, prefix", cleanIP, "/private/secret", cleanUA, cleanToken},
		{"denylist path, prefix bare", cleanIP, "/private", cleanUA, cleanToken},
		{"denylist path, dot segments resolve onto it", cleanIP, "/a/../forbidden", cleanUA, cleanToken},
		{"denylist path, percent-encoded", cleanIP, "/%66orbidden", cleanUA, cleanToken},
		{"honeypot", cleanIP, "/trap", cleanUA, cleanToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mk := func() *RequestContext {
				r := req("x.test", tc.ip, tc.uri, tc.ua)
				r.Cookie = pow.CookieName + "=" + tc.token
				return r
			}
			full := e.Evaluate(ctx, mk())
			if full.Action != ActionDeny {
				t.Fatalf("the pipeline itself did not deny this: got %s/%s. "+
					"The row no longer tests what it claims to.", full.Action, full.Reason)
			}
			if shed := e.ShedDecision(mk()); shed == ShedPass {
				t.Errorf("pipeline denies (%s) but the shed fast-passes it: "+
					"a saturated daemon serves what a healthy one refuses", full.Reason)
			}
		})
	}

	// The control: the shed must still fast-pass an ordinary token holder, or
	// the check above could be satisfied by refusing everything.
	ok := req("x.test", cleanIP, "/normal", cleanUA)
	ok.Cookie = pow.CookieName + "=" + cleanToken
	if shed := e.ShedDecision(ok); shed != ShedPass {
		t.Errorf("clean token holder: shed = %v, want ShedPass", shed)
	}
	// And an allowlisted client, which the shed answers before any denylist.
	if shed := e.ShedDecision(req("x.test", "192.0.2.10", "/", cleanUA)); shed != ShedPass {
		t.Errorf("allowlisted client: shed = %v, want ShedPass", shed)
	}
}
