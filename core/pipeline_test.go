// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"net"
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
    ips: [ "10.0.0.0/8", "2001:db8:a110::/48" ]
    uas: [ "HealthBot" ]
    paths: [ "/robots.txt" ]
  denylist:
    ips: [ "203.0.113.0/24", "10.0.0.66", "2001:db8:bad::/48" ]
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
		// IPv6 ranges, including non-canonical textual forms of the client IP.
		{"allowlist ip v6", req("x.test", "2001:db8:a110::7", "/page", "Mozilla"), ActionAllow, "allowlist:ip"},
		{"allowlist ip v6 mixed case", req("x.test", "2001:0DB8:A110::7", "/page", "Mozilla"), ActionAllow, "allowlist:ip"},
		{"denylist v6", req("x.test", "2001:db8:bad::5", "/page", "curl"), ActionDeny, "denylist:ip"},
		{"denylist v6 expanded form", req("x.test", "2001:0db8:0bad:0000:0000:0000:0000:0005", "/page", "curl"), ActionDeny, "denylist:ip"},
		{"v6 outside every range", req("x.test", "2001:db8:cafe::1", "/page", "Mozilla"), ActionAllow, "default"},
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

// stubResolver serves canned PTR/forward answers for the verified-bot tests.
type stubResolver struct {
	ptr map[string][]string // ip -> PTR hostnames
	fwd map[string][]string // hostname -> IPs
	err map[string]error    // ip -> PTR lookup error
}

func (s *stubResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err, ok := s.err[addr]; ok {
		return nil, err
	}
	hosts, ok := s.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return hosts, nil
}

func (s *stubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := s.fwd[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, len(ips))
	for i, v := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(v)}
	}
	return out, nil
}

const verifiedBotYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m, thresholds: { bot_spoof: 2/min } }
  verified_bots:
    bots: [ { name: googlebot } ]
domains:
  lenient.test:
    verified_bots: { spoof_action: continue }
`

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func verifiedBotEngine(t *testing.T, r *stubResolver) *Engine {
	t.Helper()
	cfg := loadTestConfig(t, verifiedBotYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	e.BotVerifier().SetResolver(r)
	return e
}

func TestVerifiedBotStage(t *testing.T) {
	ctx := context.Background()
	e := verifiedBotEngine(t, &stubResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"192.0.2.66":  {"scraper.evil.example."}, // valid rDNS, wrong owner
			// Genuine Google infrastructure, but the user-triggered fetcher
			// category (google.com), not a common crawler (googlebot.com):
			// third parties can aim these hosts at any site, so a Googlebot
			// claim from one is an impersonation.
			"66.249.93.77": {"google-proxy-66-249-93-77.google.com."},
			// A crawler arriving over IPv6: PTR on the v6 source, AAAA-style
			// forward confirmation.
			"2001:db8:60::1": {"crawl-v6.googlebot.com."},
			// Valid v6 rDNS pointing at googlebot, but the forward record
			// resolves to a different v6 address: an impostor.
			"2001:db8:bad::66": {"fake-v6.googlebot.com."},
		},
		fwd: map[string][]string{
			"crawl-66-249-66-1.googlebot.com":      {"66.249.66.1"},
			"scraper.evil.example":                 {"192.0.2.66"},
			"google-proxy-66-249-93-77.google.com": {"66.249.93.77"},
			"crawl-v6.googlebot.com":               {"2001:db8:60::1"},
			"fake-v6.googlebot.com":                {"2001:db8:60::1"},
		},
		err: map[string]error{"198.51.100.3": &net.DNSError{Err: "i/o timeout", IsTimeout: true}},
	})

	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"verified crawler allowed", req("x.test", "66.249.66.1", "/page", googlebotUA), ActionAllow, "verified_bot:googlebot"},
		{"verified v6 crawler allowed", req("x.test", "2001:db8:60::1", "/page", googlebotUA), ActionAllow, "verified_bot:googlebot"},
		{"v6 forward mismatch is an impostor", req("x.test", "2001:db8:bad::66", "/page", googlebotUA), ActionDeny, "bot_spoof:googlebot"},
		{"no rDNS is an impostor", req("x.test", "203.0.113.50", "/page", googlebotUA), ActionDeny, "bot_spoof:googlebot"},
		{"foreign rDNS is an impostor", req("x.test", "192.0.2.66", "/page", googlebotUA), ActionDeny, "bot_spoof:googlebot"},
		{"google.com proxy rDNS is not googlebot", req("x.test", "66.249.93.77", "/page", googlebotUA), ActionDeny, "bot_spoof:googlebot"},
		{"dns error falls through unverified", req("x.test", "198.51.100.3", "/page", googlebotUA), ActionAllow, "default"},
		// Garbage IP = transport misconfig: fail open like the denylist
		// stage, never spoof-deny.
		{"garbage ip falls through unverified", req("x.test", "not-an-ip", "/page", googlebotUA), ActionAllow, "default"},
		{"non-bot ua ignores the stage", req("x.test", "203.0.113.60", "/page", "Mozilla/5.0 Firefox"), ActionAllow, "default"},
		{"spoof_action continue only drops the skip", req("lenient.test", "203.0.113.70", "/page", googlebotUA), ActionAllow, "default"},
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

// TestVerifiedBotSpoofScoring: repeated spoofed-crawler requests trip the
// bot_spoof threshold (2/min in the test config) and block the IP for every
// User-Agent, not just the spoofed one.
func TestVerifiedBotSpoofScoring(t *testing.T) {
	ctx := context.Background()
	// The stub resolves nothing, so every crawler claim is a spoof.
	e := verifiedBotEngine(t, &stubResolver{})

	ip := "203.0.113.99"
	for range 2 {
		if d := e.Evaluate(ctx, req("x.test", ip, "/page", googlebotUA)); d.Action != ActionDeny {
			t.Fatalf("spoofed request should be denied, got %s/%s", d.Action, d.Reason)
		}
	}
	if _, blocked, err := e.BlockStatus(ctx, ip); err != nil || !blocked {
		t.Fatalf("IP should be behaviour-blocked after 2 spoofs (blocked=%v err=%v)", blocked, err)
	}
	if d := e.Evaluate(ctx, req("x.test", ip, "/page", "curl/8.0")); d.Action != ActionDeny {
		t.Errorf("blocked IP with plain UA should be denied, got %s/%s", d.Action, d.Reason)
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

	if _, err := e.UnblockIP(ctx, ip, true); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req("x.test", ip, "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("unblocked IP should be allowed again, got %s", d.Action)
	}
}

// TestBehaviourBlockIPv6 proves a behavioural block placed under one textual
// form of an IPv6 address is enforced and liftable under every other form:
// block key canonicalization (case, zero expansion, IPv4-mapped) is what the
// enforcement path relies on when Angie and the admin API spell the same
// client differently.
func TestBehaviourBlockIPv6(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t)

	// Placed in a non-canonical form, enforced against every spelling.
	if err := e.BlockIP(ctx, "2001:0DB8::66", "test_abuse", time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{
		"2001:db8::66",
		"2001:0DB8::66",
		"2001:0db8:0000:0000:0000:0000:0000:0066",
	} {
		if d := e.Evaluate(ctx, req("x.test", form, "/", "Mozilla")); d.Action != ActionDeny || d.Reason != "behaviour_block:test_abuse" {
			t.Errorf("%s: got %s/%s, want deny/behaviour_block:test_abuse", form, d.Action, d.Reason)
		}
	}
	// Unblock via yet another form lifts it for all of them.
	if _, err := e.UnblockIP(ctx, "2001:0db8:0:0:0:0:0:66", true); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req("x.test", "2001:db8::66", "/", "Mozilla")); d.Action != ActionAllow {
		t.Fatalf("unblocked v6 IP should be allowed again, got %s/%s", d.Action, d.Reason)
	}

	// A dual-stack listener reports a v4 client as ::ffff:a.b.c.d; the block
	// must land on (and be enforced against) the plain v4 identity.
	if err := e.BlockIP(ctx, "::ffff:198.51.100.80", "test_abuse", time.Minute); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req("x.test", "198.51.100.80", "/", "Mozilla")); d.Action != ActionDeny {
		t.Fatalf("mapped-form block must deny the plain v4 client, got %s/%s", d.Action, d.Reason)
	}
	if d := e.Evaluate(ctx, req("x.test", "::ffff:198.51.100.80", "/", "Mozilla")); d.Action != ActionDeny {
		t.Fatalf("mapped-form client must hit the same block, got %s/%s", d.Action, d.Reason)
	}
}
