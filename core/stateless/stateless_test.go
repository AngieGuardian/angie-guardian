// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package stateless

import "testing"

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
    honeypot:
      enabled: true
      paths: [ "/wp-login.php" ]
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
		{"signature keyword (block->deny)", req("site.test", "192.0.2.9", "/app/.env", "curl"), ActionDeny, "waf:dotfile"},
		{"signature url-encoded", req("site.test", "192.0.2.9", "/%2e%65nv", "curl"), ActionDeny, "waf:dotfile"},
		{"signature challenge degrades to deny", req("site.test", "192.0.2.9", "/x?q=union+all+select+1", "curl"), ActionDeny, "waf:sqli"},
		{"signature ua", req("site.test", "192.0.2.9", "/", "sqlmap/1.7"), ActionDeny, "waf:scanner"},
		{"defaults denylist", req("other.test", "203.0.113.5", "/", "curl"), ActionDeny, "denylist:ip"},
		{"defaults allow", req("other.test", "192.0.2.1", "/", "curl"), ActionAllow, "default"},
		{"host case + port normalized", req("SITE.test:443", "198.51.100.66", "/page", "curl"), ActionDeny, "denylist:ip"},
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
	} {
		if _, err := ParseGuestConfig([]byte(yaml)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
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
