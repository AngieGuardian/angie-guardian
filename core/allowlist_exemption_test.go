// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/stateless"
	"github.com/melroy89/angie-guardian/core/store"
)

func allowlistExemptionEngine(t *testing.T, enabled, scoring bool) *Engine {
	t.Helper()
	return allowlistExemptionEngineWithStore(t, enabled, scoring, store.NewMemory())
}

func allowlistExemptionEngineWithStore(t *testing.T, enabled, scoring bool, st store.Store) *Engine {
	t.Helper()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	err := os.WriteFile(rules, []byte(`rules:
  - { id: challenge-first, action: challenge, keywords: [ "challenge" ] }
  - { id: explicit-allow, action: allow, keywords: [ "explicit-allow" ] }
  - { id: deny-secret, action: deny, keywords: [ "secret" ] }
  - { id: block-scanner, action: block, keywords: [ "scanner" ] }
  - { id: late-allow, action: allow, keywords: [ "late-allow" ] }
`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, fmt.Sprintf(`
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  allowlist:
    ips: [ "192.0.2.0/24", "2001:db8:a::/48" ]
    uas: [ MachineClient ]
    paths: [ "/exempt/" ]
  denylist:
    ips: [ "192.0.2.66", "198.51.100.66" ]
    uas: [ DeniedClient ]
    paths: [ "/deny-path", "/exempt/deny-path" ]
  verified_bots: { bots: [ { name: googlebot } ] }
  pow:
    enabled: %t
    base_difficulty: 1
    max_difficulty: 6
    header_exemptions: [ { header: X-Machine-Proof, require_value: true } ]
  waf:
    rules: { enabled: true, files: [ %q ] }
    honeypot: { enabled: true, paths: [ "/trap", "/exempt/trap" ] }
    ip_behaviour: { enabled: %t, block_ttl: 15m, thresholds: { rule_match: off } }
domains:
  isolated.test:
    allowlist: { ips: [], uas: [], paths: [] }
    verified_bots: { bots: [] }
    pow: { header_exemptions: [] }
  disabled.test:
    waf: { rules: { disabled_ids: [ deny-secret ] } }
  overlay.test:
    paths:
      "/scoped/":
        allowlist: { paths: [ "/scoped/" ] }
        waf: { rules: { disabled_ids: [ deny-secret ] } }
  lenient.test:
    verified_bots: { spoof_action: continue }
`, enabled, rules, scoring))
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	e.BotVerifier().SetResolver(&stubResolver{
		ptr: map[string][]string{"198.51.100.42": {"crawl.googlebot.com."}},
		fwd: map[string][]string{"crawl.googlebot.com": {"198.51.100.42"}},
	})
	return e
}

func sourceRequest(source, suffix string) *RequestContext {
	r := req("site.test", "198.51.100.42", "/"+suffix, "curl")
	switch source {
	case "ip":
		r.RemoteAddr = "192.0.2.42"
	case "ipv6":
		r.RemoteAddr = "2001:0DB8:A::42"
	case "ua":
		r.UserAgent = "machineclient/1.0"
	case "path":
		r.URI = "/exempt/" + suffix
	case "bot":
		r.UserAgent = googlebotUA
	case "header":
		r.Header = func(name string) []string {
			if equalFoldASCII(name, "X-Machine-Proof") {
				return []string{"opaque"}
			}
			return nil
		}
	}
	return r
}

func sourceReason(source string) string {
	switch source {
	case "ipv6":
		return "allowlist:ip"
	case "bot":
		return "verified_bot:googlebot"
	case "header":
		return "header_exemption"
	default:
		return "allowlist:" + source
	}
}

func TestPoWExemptionEnforcementMatrix(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		sources := []string{"ip", "ipv6", "ua", "path", "bot"}
		if enabled {
			sources = append(sources, "header")
		}
		for _, source := range sources {
			for _, tc := range []struct {
				name, suffix, reason string
				deny                 bool
			}{
				{"safe", "items", "default", false},
				{"challenge suppressed", "challenge", "default", false},
				{"deny", "secret", "waf:deny-secret", true},
				{"challenge then deny", "challenge-secret", "waf:deny-secret", true},
				{"deny before explicit allow", "secret-late-allow", "waf:deny-secret", true},
				{"challenge then block", "challenge-scanner", "waf:block-scanner", true},
				{"honeypot", "trap", "honeypot:path", true},
				{"deny path", "deny-path", "denylist:path", true},
				{"explicit allow remains terminal", "explicit-allow-secret", "waf:explicit-allow", false},
			} {
				t.Run(fmt.Sprintf("pow=%t/%s/%s", enabled, source, tc.name), func(t *testing.T) {
					e := allowlistExemptionEngine(t, enabled, true)
					r := sourceRequest(source, tc.suffix)
					r.Method = "POST"
					r.Unchallengeable = true
					d := e.Evaluate(t.Context(), r)
					exemption := sourceReason(source)
					if source == "bot" && tc.reason == "denylist:path" {
						exemption = ""
					}
					action := ActionAllow
					if tc.deny {
						action = ActionDeny
					}
					if d.Action != action || d.Reason != tc.reason || d.PoWExemption != exemption {
						t.Fatalf("decision = %+v, want %s/%s exempt=%s", d, action, tc.reason, exemption)
					}
					if !tc.deny && len(d.Events) != 0 {
						t.Fatalf("suppressed challenge/allow emitted events: %+v", d.Events)
					}
					if tc.deny {
						recent := e.RecentDecisions(1)
						if len(recent) != 1 || recent[0].Reason != tc.reason || recent[0].PoWExemption != exemption {
							t.Fatalf("recent diagnostics = %+v", recent)
						}
					}
					if tc.reason == "waf:block-scanner" || tc.reason == "honeypot:path" {
						if _, blocked, err := e.BlockStatus(t.Context(), r.RemoteAddr); err != nil || !blocked {
							t.Fatalf("block missing: %t %v", blocked, err)
						}
						next := sourceRequest(source, "items")
						if d := e.Evaluate(t.Context(), next); d.Action != ActionDeny {
							t.Fatalf("recorded block bypassed: %+v", d)
						}
					}

				})
			}
		}
	}
}

func TestPoWExemptionDenyDimensionsAndRecordedBlocks(t *testing.T) {
	for _, source := range []string{"ip", "ua", "path", "header"} {
		for _, dimension := range []string{"ip", "ua", "path", "admin"} {
			t.Run(source+"/"+dimension, func(t *testing.T) {
				e := allowlistExemptionEngine(t, true, false)
				r := sourceRequest(source, "items")
				want := "denylist:" + dimension
				switch dimension {
				case "ip":
					r.RemoteAddr = "198.51.100.66"
					if source == "ip" {
						r.RemoteAddr = "192.0.2.66"
					}
				case "ua":
					r.UserAgent += " DeniedClient"
				case "path":
					r = sourceRequest(source, "deny-path")
				case "admin":
					if err := e.BlockIP(t.Context(), r.RemoteAddr, "admin", time.Minute); err != nil {
						t.Fatal(err)
					}
					want = "behaviour_block:admin"
				}
				d := e.Evaluate(t.Context(), r)
				if d.Action != ActionDeny || d.Reason != want || d.PoWExemption != sourceReason(source) {
					t.Fatalf("decision = %+v, want deny/%s exempt=%s", d, want, sourceReason(source))
				}
			})
		}
	}
	// A confirmed crawler must also encounter bans with scoring disabled.
	e := allowlistExemptionEngine(t, true, false)
	r := sourceRequest("bot", "items")
	if err := e.BlockIP(t.Context(), r.RemoteAddr, "admin", time.Minute); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(t.Context(), r); d.Action != ActionDeny || d.Reason != "behaviour_block:admin" || d.PoWExemption != sourceReason("bot") {
		t.Fatalf("crawler block = %+v", d)
	}
}

func TestPoWExemptionIsolationAndPolicy(t *testing.T) {
	e := allowlistExemptionEngine(t, true, true)
	for _, source := range []string{"ip", "ua", "path", "bot", "header"} {
		r := sourceRequest(source, "items")
		for range 2 {
			if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.PoWExemption != sourceReason(source) {
				t.Fatalf("repeated evaluation = %+v", d)
			}
		}
		r.Host = "isolated.test"
		if d := e.Evaluate(t.Context(), r); d.Action != ActionChallenge || d.PoWExemption != "" {
			t.Fatalf("host exemption leaked: %+v", d)
		}
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			source := "ua"
			if i%2 == 0 {
				source = "none"
			}
			d := e.Evaluate(t.Context(), sourceRequest(source, "items"))
			if (source == "none" && (d.Action != ActionChallenge || d.PoWExemption != "")) || (source == "ua" && (d.Action != ActionAllow || d.PoWExemption != "allowlist:ua")) {
				t.Errorf("concurrent classification = %+v", d)
			}
		})
	}
	wg.Wait()
	r := sourceRequest("ua", "challenge-secret")
	r.Host = "disabled.test"
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow {
		t.Fatalf("disabled rule was reenabled: %+v", d)
	}
	r = sourceRequest("ip", "items")
	r.UserAgent = googlebotUA
	if d := e.Evaluate(t.Context(), r); d.Action != ActionDeny || d.Reason != "bot_spoof:googlebot" || d.PoWExemption != "allowlist:ip" {
		t.Fatalf("allowlist concealed spoof: %+v", d)
	}
	r.Host = "lenient.test"
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow {
		t.Fatalf("continue policy = %+v", d)
	}
	e.BotVerifier().SetResolver(&stubResolver{err: map[string]error{"192.0.2.99": fmt.Errorf("temporary DNS failure")}})
	r.RemoteAddr = "192.0.2.99"
	r.Host = "site.test"
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.PoWExemption != "allowlist:ip" {
		t.Fatalf("DNS error revoked independent exemption: %+v", d)
	}
}

func TestPoWExemptionNativeStatelessParity(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		e := allowlistExemptionEngine(t, enabled, false)
		cfg := e.Config()
		dc := cfg.DomainFor("site.test")
		rs := e.snap.Load().rules.Get(dc.WAF.Rules.ruleKey)
		dr := stateless.DomainRules{Allowlist: dc.Allowlist, Denylist: dc.Denylist, Honeypot: dc.WAF.Honeypot, RulesEnabled: true, Rules: rs}
		for _, source := range []string{"ip", "ipv6", "ua", "path"} {
			for _, suffix := range []string{"items", "challenge", "challenge-secret", "challenge-scanner", "trap", "deny-path", "explicit-allow-secret"} {
				native := e.Evaluate(t.Context(), sourceRequest(source, suffix))
				shared := stateless.Evaluate(sourceRequest(source, suffix), &dr)
				if native.Action != shared.Action || native.Reason != shared.Reason || native.PoWExemption != shared.PoWExemption {
					t.Fatalf("%s/%s parity: native=%+v shared=%+v", source, suffix, native, shared)
				}
			}
		}
	}
}

func TestPoWExemptionIntelAndAnomaly(t *testing.T) {
	for _, source := range []string{"ip", "ua", "path", "bot"} {
		t.Run(source, func(t *testing.T) {
			var intelPolicy, anomalyPolicy string
			switch source {
			case "ip":
				intelPolicy = "  allowlist: { ips: [ 192.0.2.0/24, 203.0.113.0/24, 100.64.0.0/16 ] }\n"
				anomalyPolicy = "    allowlist: { ips: [ 198.51.100.0/24 ] }\n"
			case "ua":
				intelPolicy = "  allowlist: { uas: [ curl ] }\n"
				anomalyPolicy = "    allowlist: { uas: [ Firefox/, zgrab/ ] }\n"
			case "path":
				intelPolicy = "  allowlist: { paths: [ /items ] }\n"
				anomalyPolicy = "    allowlist: { paths: [ /cgi-bin/ ] }\n"
			case "bot":
				intelPolicy = "  verified_bots: { bots: [ { name: fixture, uas: [ curl ], domains: [ crawler.example.net ] } ] }\n"
				anomalyPolicy = "    verified_bots: { bots: [ { name: fixture, uas: [ Firefox/, zgrab/ ], domains: [ crawler.example.net ] } ] }\n"
			}
			intelE, _ := intelEngineWithPolicy(t, intelPolicy)
			ips := []string{"192.0.2.5", "203.0.113.5", "100.64.8.5", "100.64.7.5"}
			ptr := map[string][]string{}
			for _, ip := range ips {
				ptr[ip] = []string{"crawler.example.net."}
			}
			intelE.BotVerifier().SetResolver(&stubResolver{ptr: ptr, fwd: map[string][]string{"crawler.example.net": ips}})
			for _, tc := range []struct {
				ip, reason string
				action     Action
			}{
				{ips[0], "default", ActionAllow}, {ips[1], "geo:country:RU", ActionDeny},
				{ips[2], "default", ActionAllow}, {ips[3], "reputation:bad-actors", ActionDeny},
			} {
				d := intelE.Evaluate(t.Context(), req("x.test", tc.ip, "/items", "curl"))
				if d.Action != tc.action || d.Reason != tc.reason || d.PoWExemption == "" {
					t.Fatalf("intel = %+v, want %s/%s with exemption", d, tc.action, tc.reason)
				}
			}
			anomalyE := anomalyEngineWithPolicy(t, anomalyPolicy)
			anomalyE.BotVerifier().SetResolver(&stubResolver{ptr: map[string][]string{"198.51.100.46": {"crawler.example.net."}}, fwd: map[string][]string{"crawler.example.net": {"198.51.100.46"}}})
			for _, tc := range []struct {
				ua, reason string
				action     Action
			}{{commonUA, "default", ActionAllow}, {"zgrab/0.x", "anomaly:deny", ActionDeny}} {
				d := anomalyE.Evaluate(t.Context(), req("anom.test", "198.51.100.46", scannerPath, tc.ua))
				if d.Action != tc.action || d.Reason != tc.reason || d.PoWExemption == "" {
					t.Fatalf("anomaly = %+v, want %s/%s with exemption", d, tc.action, tc.reason)
				}
			}
		})
	}
}

func TestPoWExemptionAttackTokensAndShed(t *testing.T) {
	e := allowlistExemptionEngine(t, true, true)
	detector := attackmode.New(e.Config().AttackModeSettings(), e.store, slog.Default())
	e.SetAttackDetector(detector)
	detector.Pin(attackmode.Attack, 0)
	if detector.State().Level != attackmode.Attack || !detector.State().ForceAlways {
		t.Fatal("attack fixture did not force always")
	}
	for _, source := range []string{"ip", "ipv6", "ua", "path", "bot", "header"} {
		r := sourceRequest(source, "challenge")
		r.Cookie = pow.CookieName + "=invalid"
		r.Unchallengeable = true
		if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.PoWExemption != sourceReason(source) {
			t.Fatalf("attack/invalid cookie %s: %+v", source, d)
		}
		r = sourceRequest(source, "items")
		if got := e.ShedDecision(r); got != ShedReject {
			t.Fatalf("exemption %s granted shed admission: %v", source, got)
		}
		if source != "bot" {
			r = sourceRequest(source, "challenge-secret")
			if got := e.ShedDecision(r); got != ShedDeny {
				t.Fatalf("shed concealed later deny for %s: %v", source, got)
			}
		}
	}
	// A token still cannot conceal a WAF deny for an exempt request.
	r := sourceRequest("ua", "challenge-secret")
	ch, err := e.pow.Issue(t.Context(), r.Host, r.RemoteAddr, "/items", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.pow.Redeem(t.Context(), &pow.RedeemRequest{ChallengeID: ch.ID, Nonce: solvePoW(t, ch.Challenge, 4), Host: r.Host, IP: r.RemoteAddr, UserAgent: r.UserAgent, TokenTTL: time.Hour, ChallengeTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r.Cookie = pow.CookieName + "=" + result.Token
	if d := e.Evaluate(t.Context(), r); d.Action != ActionDeny || d.Reason != "waf:deny-secret" {
		t.Fatalf("token concealed security deny: %+v", d)
	}
	cookie := r.Cookie
	r = sourceRequest("ua", "items")
	r.Cookie = cookie
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.Reason != "default" {
		t.Fatalf("valid token exempt flow: %+v", d)
	}
	if got := e.ShedDecision(r); got != ShedPass {
		t.Fatalf("valid token did not retain shed admission: %v", got)
	}
}

func TestPoWExemptionOverlayReloadAndPrecedence(t *testing.T) {
	e := allowlistExemptionEngine(t, true, false)
	r := sourceRequest("none", "items")
	r.Host = "overlay.test"
	if d := e.Evaluate(t.Context(), r); d.Action != ActionChallenge || d.PoWExemption != "" {
		t.Fatalf("outside overlay = %+v", d)
	}
	for _, uri := range []string{"/scoped/items", "/%73coped//items", "/scoped/challenge-secret"} {
		r = req("overlay.test", "198.51.100.42", uri, "curl")
		if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.PoWExemption != "allowlist:path" {
			t.Fatalf("overlay/exclusions = %+v", d)
		}
	}
	for _, source := range []string{"path", "ip", "ua", "bot"} {
		r = sourceRequest(source, "items")
		r.Header = sourceRequest("header", "items").Header
		if d := e.Evaluate(t.Context(), r); d.PoWExemption != sourceReason(source) {
			t.Fatalf("source precedence = %+v", d)
		}
	}
	// Reload into a configuration without the same UA exemption; reuse the
	// request without changing matcher inputs to prove classification is local.
	r = sourceRequest("ua", "items")
	if d := e.Evaluate(t.Context(), r); d.PoWExemption != "allowlist:ua" {
		t.Fatalf("before reload = %+v", d)
	}
	if err := e.Reload(loadTestConfig(t, pipelineYAML)); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.PoWExemption != "" {
		t.Fatalf("reload leaked classification = %+v", d)
	}
	// Static shared deny decisions must never acquire another request's reason.
	denied := req("site.test", "203.0.113.5", "/robots.txt", "curl")
	if d := e.Evaluate(t.Context(), denied); d.PoWExemption != "allowlist:path" {
		t.Fatalf("classified deny = %+v", d)
	}
	denied = req("site.test", "203.0.113.5", "/items", "curl")
	if d := e.Evaluate(t.Context(), denied); d.PoWExemption != "" {
		t.Fatalf("shared deny mutated = %+v", d)
	}
}

func TestNonExemptWAFChallengeFallback(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		e := allowlistExemptionEngine(t, enabled, false)
		d := e.Evaluate(t.Context(), sourceRequest("none", "challenge"))
		action := ActionDeny
		if enabled {
			action = ActionChallenge
		}
		if d.Action != action || d.Reason != "waf:challenge-first" || d.PoWExemption != "" {
			t.Fatalf("pow=%t nonexempt fallback = %+v", enabled, d)
		}
	}
}
