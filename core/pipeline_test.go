// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

const pipelineYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
  allowlist:
    ips: [ "10.0.0.0/8" ]
    uas: [ "HealthBot" ]
    paths: [ "/robots.txt" ]
  denylist:
    ips: [ "203.0.113.0/24", "10.0.0.66" ]
domains:
  nowaf.test:
    waf: { ip_behaviour: { enabled: false } }
`

func testEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := loadTestConfig(t, pipelineYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func req(host, ip, uri, ua string) *RequestContext {
	return &RequestContext{Host: host, Method: "GET", URI: uri, RemoteAddr: ip, UserAgent: ua}
}

func TestPipeline(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t)

	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"default allow", req("x.test", "198.51.100.7", "/page", "Mozilla"), ActionAllow, "default"},
		{"allowlist ip", req("x.test", "10.9.8.7", "/page", "Mozilla"), ActionAllow, "allowlist:ip"},
		{"allowlist ua", req("x.test", "198.51.100.7", "/page", "monitoring healthbot v2"), ActionAllow, "allowlist:ua"},
		{"allowlist path", req("x.test", "203.0.113.5", "/robots.txt?x=1", "curl"), ActionAllow, "allowlist:path"},
		{"denylist", req("x.test", "203.0.113.5", "/page", "curl"), ActionDeny, "denylist:ip"},
		// Allowlist runs before denylist: 10.0.0.66 is in both, allow wins.
		{"allowlist precedence", req("x.test", "10.0.0.66", "/page", "curl"), ActionAllow, "allowlist:ip"},
		// Unparseable IP: denylist stage errors, pipeline fails open.
		{"garbage ip fails open", req("x.test", "not-an-ip", "/page", "curl"), ActionAllow, "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
		})
	}
}

func TestBehaviourBlock(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t)
	ip := "198.51.100.99"

	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("unblocked IP should be allowed, got %s", d.Action)
	}

	if err := e.BlockIP(ctx, ip, "test_abuse", time.Minute); err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla"))
	if d.Action != ActionDeny || d.Reason != "behaviour_block:test_abuse" {
		t.Fatalf("blocked IP: got %s/%s", d.Action, d.Reason)
	}

	// Existing blocks are enforced even where ip_behaviour is disabled: that
	// toggle only controls whether NEW blocks are placed automatically, not
	// whether an already-placed block (admin or otherwise) is honoured.
	if d := e.Evaluate(ctx, req("nowaf.test", ip, "/", "Mozilla")); d.Action != ActionDeny {
		t.Fatalf("nowaf.test should still enforce an existing block, got %s", d.Action)
	}

	if err := e.UnblockIP(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("unblocked IP should be allowed again, got %s", d.Action)
	}
}
