// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const rulesYAML = `
rules:
  - id: dotfile-probe
    action: block
    targets: [ path ]
    keywords: [ "/.env", "/.git/" ]
  - id: sqli-union
    action: challenge
    targets: [ path, query ]
    regexes: [ '(?i)\bunion\b[\s/*+]+select\b' ]
  - id: scanner-ua
    action: deny
    targets: [ ua ]
    keywords: [ "sqlmap", "nikto" ]
  - id: default-targets
    keywords: [ "boot.ini" ]
  - id: log4shell-header
    action: block
    targets: [ "header:Referer", "header:x-forwarded-for" ]
    keywords: [ "${jndi:" ]
  - id: trace-method
    action: deny
    methods: [ trace, TRACK ]
  - id: put-script
    action: deny
    methods: [ PUT ]
    targets: [ query ]
    keywords: [ "<script" ]
`

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRuleMatching(t *testing.T) {
	rs, err := compileRules([]byte(rulesYAML), "test")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		in     MatchInput
		rule   string
		action Action
	}{
		{"keyword in path", MatchInput{Path: "/backup/.env"}, "dotfile-probe", ActionBlock},
		{"keyword is case-insensitive via lowered input", MatchInput{Path: "/.git/config"}, "dotfile-probe", ActionBlock},
		{"regex in query", MatchInput{Path: "/search", Query: "q=1 union select password"}, "sqli-union", ActionChallenge},
		{"regex in path", MatchInput{Path: "/union select"}, "sqli-union", ActionChallenge},
		{"ua keyword", MatchInput{Path: "/", UA: "sqlmap/1.7"}, "scanner-ua", ActionDeny},
		{"default targets are path+query", MatchInput{Query: "f=boot.ini"}, "default-targets", ActionDeny},
		{"default action is deny", MatchInput{Path: "/boot.ini"}, "default-targets", ActionDeny},
		{"clean request", MatchInput{Path: "/blog/post", Query: "page=2", UA: "mozilla/5.0"}, "", ""},
		{"ua rule must not match path", MatchInput{Path: "/nikto"}, "", ""},
		{"header keyword, name lowered at compile", MatchInput{Headers: map[string]string{"referer": "http://evil/${jndi:ldap://x}"}}, "log4shell-header", ActionBlock},
		{"second header target", MatchInput{Headers: map[string]string{"x-forwarded-for": "${jndi:dns://x}"}}, "log4shell-header", ActionBlock},
		{"header rule must not match path", MatchInput{Path: "/${jndi:x"}, "", ""},
		{"methods-only rule, method uppercased at compile", MatchInput{Method: "TRACE", Path: "/"}, "trace-method", ActionDeny},
		{"methods-only rule ignores clean fields", MatchInput{Method: "TRACK", Path: "/blog", UA: "mozilla/5.0"}, "trace-method", ActionDeny},
		{"method gate passes", MatchInput{Method: "PUT", Query: "x=<script>alert(1)"}, "put-script", ActionDeny},
		{"method gate blocks other methods", MatchInput{Method: "GET", Query: "x=<script>alert(1)"}, "", ""},
		{"empty method never matches a method rule", MatchInput{Path: "/"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := rs.Match(&tc.in)
			switch {
			case r == nil && tc.rule != "":
				t.Errorf("no match, want rule %s", tc.rule)
			case r != nil && tc.rule == "":
				t.Errorf("matched %s, want no match", r.ID)
			case r != nil && (r.ID != tc.rule || r.Action != tc.action):
				t.Errorf("matched %s/%s, want %s/%s", r.ID, r.Action, tc.rule, tc.action)
			}
		})
	}
}

func TestRuleSetPrecomputation(t *testing.T) {
	rs, err := compileRules([]byte(rulesYAML), "test")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"referer", "x-forwarded-for"}; !slices.Equal(rs.HeaderTargets(), want) {
		t.Errorf("HeaderTargets() = %v, want %v", rs.HeaderTargets(), want)
	}
	if !rs.NeedsMethod() {
		t.Error("NeedsMethod() = false, want true")
	}

	plain, err := compileRules([]byte("rules: [ { id: a, keywords: [x] } ]"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.HeaderTargets()) != 0 || plain.NeedsMethod() {
		t.Errorf("plain rule set: HeaderTargets() = %v, NeedsMethod() = %v, want none/false",
			plain.HeaderTargets(), plain.NeedsMethod())
	}
}

func TestRuleValidation(t *testing.T) {
	for name, body := range map[string]string{
		"missing id":               "rules: [ { keywords: [x] } ]",
		"duplicate id":             "rules: [ { id: a, keywords: [x] }, { id: a, keywords: [y] } ]",
		"empty rule":               "rules: [ { id: a } ]",
		"bad action":               "rules: [ { id: a, action: nuke, keywords: [x] } ]",
		"bad target":               "rules: [ { id: a, targets: [ body ], keywords: [x] } ]",
		"bad regex":                "rules: [ { id: a, regexes: [ '([' ] } ]",
		"unknown field":            "rules: [ { id: a, keywords: [x], severity: high } ]",
		"empty header name":        "rules: [ { id: a, targets: [ 'header:' ], keywords: [x] } ]",
		"empty method":             "rules: [ { id: a, methods: [ '' ] } ]",
		"targets without patterns": "rules: [ { id: a, methods: [ GET ], targets: [ path ] } ]",
	} {
		if _, err := compileRules([]byte(body), "test"); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestHotReload(t *testing.T) {
	path := writeRules(t, "rules: [ { id: old, keywords: [ oldkw ] } ]")
	cache, err := NewRuleCache([]string{path}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	cache.Start(10 * time.Millisecond)

	if rs := cache.Get(path); rs.Match(&MatchInput{Path: "/oldkw"}) == nil {
		t.Fatal("initial rules not loaded")
	}

	// Valid update is picked up.
	if err := os.WriteFile(path, []byte("rules: [ { id: new, keywords: [ newkw ] } ]"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if rs := cache.Get(path); rs.Match(&MatchInput{Path: "/newkw"}) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("updated rules never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Broken update keeps the last good rule set. Give the poller several
	// intervals to have attempted (and rejected) the reload; the "newkw"
	// rule must survive throughout.
	if err := os.WriteFile(path, []byte("rules: [ { id: broken, regexes: [ '([' ] } ]"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if rs := cache.Get(path); rs.Match(&MatchInput{Path: "/newkw"}) == nil {
			t.Fatal("broken reload must keep the previous good rules")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Unknown path returns nil.
	if cache.Get("/nonexistent") != nil {
		t.Fatal("unknown path should return nil rule set")
	}
}

func TestNewRuleCacheFailsFast(t *testing.T) {
	if _, err := NewRuleCache([]string{"/does/not/exist.yaml"}, slog.Default()); err == nil {
		t.Fatal("missing rules file must fail startup")
	}
	bad := writeRules(t, "rules: [ { id: a, regexes: [ '([' ] } ]")
	if _, err := NewRuleCache([]string{bad}, slog.Default()); err == nil {
		t.Fatal("invalid rules file must fail startup")
	}
}
