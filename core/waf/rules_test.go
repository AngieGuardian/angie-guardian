// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import (
	"log/slog"
	"os"
	"path/filepath"
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

func TestRuleValidation(t *testing.T) {
	for name, body := range map[string]string{
		"missing id":    "rules: [ { keywords: [x] } ]",
		"duplicate id":  "rules: [ { id: a, keywords: [x] }, { id: a, keywords: [y] } ]",
		"empty rule":    "rules: [ { id: a } ]",
		"bad action":    "rules: [ { id: a, action: nuke, keywords: [x] } ]",
		"bad target":    "rules: [ { id: a, targets: [ body ], keywords: [x] } ]",
		"bad regex":     "rules: [ { id: a, regexes: [ '([' ] } ]",
		"unknown field": "rules: [ { id: a, keywords: [x], severity: high } ]",
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

	// Broken update keeps the last good rule set.
	if err := os.WriteFile(path, []byte("rules: [ { id: broken, regexes: [ '([' ] } ]"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if rs := cache.Get(path); rs.Match(&MatchInput{Path: "/newkw"}) == nil {
		t.Fatal("broken reload must keep the previous good rules")
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
