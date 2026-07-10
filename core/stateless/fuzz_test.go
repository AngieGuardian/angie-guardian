// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package stateless

import (
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core/waf"
)

// A panic on the decision hot path is worse than a normal crash: with
// fail-open, the site keeps serving while protection silently drops. These
// targets drive the URI/percent-decode helpers and the full WAF match input
// builder with arbitrary bytes; any input that panics is a bug.

func FuzzDecodePath(f *testing.F) {
	seeds := []string{
		"", "/", "/a/b/c", "/%2e%2e/%2e%2e/etc/passwd", "/%",
		"/%zz", "/%c0%ae", "/%u002e", "/\x00/x", "/%00", "/a%2",
		"/" + strings.Repeat("%2e", 5000), "%%%%", "/%25%32%65",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		_ = DecodePath(p)
		// RequestPath/RequestQuery split the same raw URI the decoders see.
		_ = DecodePath(RequestPath(p))
		_ = DecodeQuery(RequestQuery(p))
	})
}

func FuzzDecodeQuery(f *testing.F) {
	seeds := []string{
		"", "a=1", "a=1&b=2", "q=%27+or+1=1--", "a=%", "a=%zz",
		"a=+++", "%2e%2e", "a=%c0%ae", strings.Repeat("a=%2e&", 5000),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		_ = DecodeQuery(q)
	})
}

// FuzzBuildMatchInput drives the full normalize+decode path an untrusted
// request takes into the WAF matcher, then runs the compiled rules against it,
// so a crash anywhere from URI splitting through regex matching surfaces here.
func FuzzBuildMatchInput(f *testing.F) {
	rs, err := waf.CompileRules([]byte(`
rules:
  - id: sqli
    targets: [path, query, ua]
    keywords: ["union select", "' or "]
  - id: traversal
    targets: [path]
    regexes: ['\.\./', '/etc/passwd']
  - id: scanner-ua
    targets: [ua]
    keywords: ["sqlmap", "nikto"]
  - id: referer-jndi
    targets: ["header:referer"]
    keywords: ["jndi:"]
  - id: track
    methods: [TRACK, TRACE]
`), "fuzz")
	if err != nil {
		f.Fatalf("seed rules failed to compile: %v", err)
	}

	f.Add("/x", "a=1", "curl/8", "GET", "http://ok/")
	f.Add("/%2e%2e/etc/passwd", "q=%27%20or%201=1", "sqlmap/1.0", "TRACK", "${jndi:ldap://x}")
	f.Add("/\x00", "%", "%zz", "\x00", "")

	f.Fuzz(func(t *testing.T, uri, rawQuery, ua, method, referer string) {
		// The transport hands the matcher a full request; build one whose
		// fields are the fuzzed bytes, including the header getter a
		// header-targeting rule reads.
		req := &RequestContext{
			Host:       "fuzz.test",
			Method:     method,
			URI:        uri + "?" + rawQuery,
			RemoteAddr: "203.0.113.7",
			UserAgent:  ua,
			Header: func(name string) string {
				if strings.EqualFold(name, "referer") {
					return referer
				}
				return ""
			},
		}
		in := BuildMatchInput(req, rs)
		_ = rs.Match(&in)
	})
}
