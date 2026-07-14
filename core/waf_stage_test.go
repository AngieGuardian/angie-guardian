// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const stageRules = `
rules:
  - id: dotfile
    action: deny
    keywords: [ "/.env" ]
  - id: sqli
    action: challenge
    regexes: [ 'union.+select' ]
  - id: scanner
    action: block
    targets: [ ua ]
    keywords: [ "sqlmap" ]
`

const wafYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m
      thresholds: { signature: 3/min, pow_fail: 3/min, tamper: 3/min }
    keywords: { enabled: true, rules_file: %q }
    honeypot: { enabled: true, paths: [ "/wp-login.php", "/admin-old/" ] }
  allowlist:
    ips: [ "10.0.0.0/8" ]
domains:
  pow.test:
    pow: { enabled: true, base_difficulty: 2, max_difficulty: 6 }
`

func wafEngine(t *testing.T) (*Engine, *pow.Manager) {
	t.Helper()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(stageRules), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, fmt.Sprintf(wafYAML, rules))
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
	return e, mgr
}

func TestWAFSignatureStage(t *testing.T) {
	ctx := context.Background()
	e, _ := wafEngine(t)

	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"keyword deny",
			req("plain.test", "198.51.100.1", "/backup/.env", "curl"), ActionDeny, "waf:dotfile"},
		{"url-encoded keyword still caught",
			req("plain.test", "198.51.100.2", "/%2e%65nv", "curl"), ActionDeny, "waf:dotfile"},
		{"regex in query",
			req("plain.test", "198.51.100.3", "/s?q=1+UNION+ALL+SELECT+pw", "curl"), ActionDeny, "waf:sqli"},
		{"challenge action degrades to deny without PoW",
			req("plain.test", "198.51.100.3", "/union all select", "curl"), ActionDeny, "waf:sqli"},
		{"challenge action challenges on PoW domain",
			req("pow.test", "198.51.100.4", "/union all select", "curl"), ActionChallenge, "waf:sqli"},
		{"clean request",
			req("plain.test", "198.51.100.5", "/blog/env-vars-explained", "Mozilla/5.0"), ActionAllow, "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
			if tc.action == ActionChallenge && d.Difficulty != 12 {
				t.Errorf("escalated difficulty = %d bits, want base 8 + 4 = 12", d.Difficulty)
			}
		})
	}
}

func TestBlockActionBlocksIP(t *testing.T) {
	ctx := context.Background()
	e, _ := wafEngine(t)
	ip := "198.51.100.20"

	d := e.Evaluate(ctx, req("plain.test", ip, "/", "sqlmap/1.7"))
	if d.Action != ActionDeny || d.Reason != "waf:scanner" {
		t.Fatalf("scanner UA: got %s/%s", d.Action, d.Reason)
	}
	// The next, otherwise clean, request from that IP hits the block.
	d = e.Evaluate(ctx, req("plain.test", ip, "/clean", "curl"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:waf:scanner" {
		t.Fatalf("after block action: got %s/%s, want behaviour_block", d.Action, d.Reason)
	}
}

func TestHoneypotTrap(t *testing.T) {
	ctx := context.Background()
	e, _ := wafEngine(t)
	ip := "198.51.100.21"

	d := e.Evaluate(ctx, req("plain.test", ip, "/wp-login.php", "Mozilla/5.0"))
	if d.Action != ActionDeny || d.Reason != "honeypot:path" {
		t.Fatalf("trap hit: got %s/%s", d.Action, d.Reason)
	}
	d = e.Evaluate(ctx, req("plain.test", ip, "/", "Mozilla/5.0"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:honeypot:path" {
		t.Fatalf("after trap: got %s/%s, want instant block", d.Action, d.Reason)
	}
}

func TestEncodedHoneypotTrapBlocksIP(t *testing.T) {
	ctx := context.Background()
	e, _ := wafEngine(t)
	ip := "198.51.100.24"

	d := e.Evaluate(ctx, req("plain.test", ip, "/%61dmin-old/secret", "Mozilla/5.0"))
	if d.Action != ActionDeny || d.Reason != "honeypot:path" {
		t.Fatalf("encoded trap hit: got %s/%s", d.Action, d.Reason)
	}
	d = e.Evaluate(ctx, req("plain.test", ip, "/clean", "Mozilla/5.0"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:honeypot:path" {
		t.Fatalf("after encoded trap: got %s/%s, want instant block", d.Action, d.Reason)
	}
}

func TestSignatureThresholdBlocks(t *testing.T) {
	ctx := context.Background()
	e, _ := wafEngine(t)
	ip := "198.51.100.22"

	// Threshold is 3/min: two deny-hits leave the IP unblocked, the third blocks.
	for i := 0; i < 3; i++ {
		if d := e.Evaluate(ctx, req("plain.test", ip, "/.env", "curl")); d.Reason != "waf:dotfile" {
			t.Fatalf("hit %d: %s/%s", i, d.Action, d.Reason)
		}
	}
	d := e.Evaluate(ctx, req("plain.test", ip, "/clean", "curl"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:threshold:signature" {
		t.Fatalf("after threshold: got %s/%s", d.Action, d.Reason)
	}
}

func TestVouchedClientStillPassesWAF(t *testing.T) {
	ctx := context.Background()
	e, mgr := wafEngine(t)
	ip, ua := "198.51.100.23", "Mozilla/5.0"
	token := mintTestToken(t, mgr, "pow.test", ip, ua)

	// The token vouches for clean requests...
	r := req("pow.test", ip, "/clean", ua)
	r.Cookie = pow.CookieName + "=" + token
	if d := e.Evaluate(ctx, r); d.Reason != "pow:token" {
		t.Fatalf("clean vouched request: %s/%s", d.Action, d.Reason)
	}
	// ...but does not exempt the client from signature checks (WAF-lite).
	r = req("pow.test", ip, "/backup/.env", ua)
	r.Cookie = pow.CookieName + "=" + token
	if d := e.Evaluate(ctx, r); d.Action != ActionDeny || d.Reason != "waf:dotfile" {
		t.Fatalf("vouched attack request: got %s/%s, want waf:dotfile deny", d.Action, d.Reason)
	}
}

func TestReportEvent(t *testing.T) {
	ctx := context.Background()
	e, _ := wafEngine(t)

	// pow_fail threshold is 3/min: the third report blocks.
	ip := "198.51.100.24"
	for i := 0; i < 3; i++ {
		e.ReportEvent(ctx, "pow.test", ip, EventPoWFail, "bad nonce")
	}
	d := e.Evaluate(ctx, req("pow.test", ip, "/", "curl"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:threshold:pow_fail" {
		t.Fatalf("after pow_fail reports: got %s/%s", d.Action, d.Reason)
	}

	// Tamper events (forged/replayed challenge IDs) are scored out of the box,
	// with no separate feature toggle: the tamper threshold is 3/min, so the
	// third report blocks. This is the behaviour that finding 6 fixed; the old
	// uuid_tamper gate dropped these by default.
	tamperIP := "198.51.100.77"
	for i := 0; i < 3; i++ {
		e.ReportEvent(ctx, "pow.test", tamperIP, EventTamper, "unknown challenge id")
	}
	d = e.Evaluate(ctx, req("pow.test", tamperIP, "/", "curl"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:threshold:tamper" {
		t.Fatalf("after tamper reports: got %s/%s, want deny on tamper threshold", d.Action, d.Reason)
	}

	// Allowlisted IPs are never scored.
	for i := 0; i < 5; i++ {
		e.ReportEvent(ctx, "pow.test", "10.1.2.3", EventPoWFail, "bad nonce")
	}
	if d := e.Evaluate(ctx, req("pow.test", "10.1.2.3", "/", "curl")); d.Action != ActionAllow {
		t.Fatalf("allowlisted IP got scored/blocked: %s/%s", d.Action, d.Reason)
	}
}
