// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import "testing"

// FuzzCompileRules feeds arbitrary bytes to the rules-file parser. A rules
// file is operator input, but it is hot-reloaded from disk without a restart
// and the WASM guest receives rules inline from an untrusted-adjacent config
// path, so the parser must reject any input with an error, never a panic.
func FuzzCompileRules(f *testing.F) {
	seeds := []string{
		"",
		"rules: []",
		"rules:\n  - id: x\n    targets: [path]\n    keywords: [\"a\"]\n",
		"rules:\n  - id: r\n    targets: [path]\n    regex: ['(a+)+$']\n", // catastrophic-looking regex
		"rules:\n  - id: r\n    targets: [path]\n    regex: ['[']\n",      // invalid regex
		"rules:\n  - id: r\n    methods: [GET]\n",
		"rules:\n  - targets: [bogus]\n",
		"not: a rules file",
		"rules:\n  - id: r\n    targets: [header]\n    headers: []\n",
		":\n:\n:",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rs, err := CompileRules(raw, "fuzz")
		// A successful compile must yield a usable, non-nil rule set that can
		// be matched against without panicking.
		if err == nil {
			if rs == nil {
				t.Fatal("CompileRules returned nil ruleset with nil error")
			}
			in := &MatchInput{Path: "/x", Query: "a=1", UA: "curl", Method: "GET"}
			_ = rs.Match(in)
		}
	})
}
