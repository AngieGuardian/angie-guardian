// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

type crawlerHTTPResolver struct{ calls atomic.Int64 }

func (r *crawlerHTTPResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.calls.Add(1)
	return []string{"crawl.googlebot.com."}, nil
}
func (r *crawlerHTTPResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.calls.Add(1)
	return []net.IPAddr{{IP: net.ParseIP("198.51.100.42")}}, nil
}

type crawlerHTTPOps struct{ calls atomic.Int64 }

func (o *crawlerHTTPOps) StoreOp(string, float64, error) { o.calls.Add(1) }

func TestHTTPOverloadUsesCachedCrawlerIdentity(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(`rules:
 - {id: challenge-first, action: challenge, keywords: [secret]}
 - {id: deny-secret, action: deny, keywords: [secret]}
`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := &crawlerHTTPOps{}
	ts, h := testServerAndHandlerWithStore(t, fmt.Sprintf(`
store: {backend: memory}
signing_key_file: test.key
attack_mode: {effects: {max_inflight: 1}}
defaults:
 verified_bots: {bots: [{name: googlebot}], spoof_action: continue}
 pow: {enabled: true, base_difficulty: 1, max_difficulty: 6}
 waf: {rules: {enabled: true, files: [%q]}, ip_behaviour: {enabled: false}}
`, rules), store.Instrument(store.NewMemory(), ops), nil)
	resolver := &crawlerHTTPResolver{}
	h.engine.BotVerifier().SetResolver(resolver)
	const host = "example.test"
	const ip = "198.51.100.42"
	const ua = "Googlebot/2.1"
	// Mint a token independently of crawler exemption, as in the reproduced bug.
	mgr := h.engine.PoWManager()
	ch, err := mgr.Issue(t.Context(), host, ip, "/items", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mgr.Redeem(t.Context(), &pow.RedeemRequest{ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 4), Host: host, IP: ip, UserAgent: ua, TokenTTL: time.Hour, ChallengeTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if d := h.engine.Evaluate(t.Context(), &core.RequestContext{Host: host, RemoteAddr: ip, URI: "/items", UserAgent: ua}); d.PoWExemption != "verified_bot:googlebot" {
		t.Fatalf("warm: %+v", d)
	}
	// Redemption clears escalation counters asynchronously. Drain that setup
	// work before measuring store access from the saturated HTTP requests.
	flushCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := mgr.FlushCounters(flushCtx); err != nil {
		t.Fatalf("flush setup counters: %v", err)
	}
	h.inflight.Add(1)
	defer h.inflight.Add(-1)
	before, dns := ops.calls.Load(), resolver.calls.Load()
	for _, tc := range []struct {
		ip, path, token, action string
		status                  int
	}{
		{ip, "/secret", result.Token, "deny", http.StatusForbidden},
		{ip, "/items", result.Token, "allow", http.StatusOK},
		{ip, "/items", "", "shed", http.StatusForbidden},
		{"198.51.100.43", "/items", result.Token, "shed", http.StatusForbidden},
	} {
		headers := guardianHeaders(host, tc.ip, tc.path, ua)
		headers["X-Guardian-Cookie"] = pow.CookieName + "=" + tc.token
		resp := do(t, "GET", ts.URL+"/auth", headers, nil)
		if resp.StatusCode != tc.status || resp.Header.Get("X-Guardian-Action") != tc.action {
			t.Fatalf("%+v: %d %v", tc, resp.StatusCode, resp.Header)
		}
	}
	if after, dnsAfter := ops.calls.Load(), resolver.calls.Load(); after != before || dnsAfter != dns {
		t.Fatalf("saturated HTTP path accessed store or DNS: store %d -> %d, DNS %d -> %d", before, after, dns, dnsAfter)
	}
}
