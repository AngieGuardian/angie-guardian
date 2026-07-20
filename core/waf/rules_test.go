// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		{"header keyword, name lowered at compile", MatchInput{Headers: map[string][]string{"referer": {"http://evil/${jndi:ldap://x}"}}}, "log4shell-header", ActionBlock},
		{"second header target", MatchInput{Headers: map[string][]string{"x-forwarded-for": {"${jndi:dns://x}"}}}, "log4shell-header", ActionBlock},
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
		"empty keyword":            "rules: [ { id: a, keywords: [ '' ] } ]",
		"empty regex":              "rules: [ { id: a, regexes: [ '' ] } ]",
	} {
		if _, err := compileRules([]byte(body), "test"); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestRulesRejectTrailingYAMLDocument(t *testing.T) {
	body := "rules: [ { id: first, keywords: [x] } ]\n---\nrules: [ { id: hidden, keywords: [y] } ]\n"
	if _, err := compileRules([]byte(body), "test"); err == nil {
		t.Fatal("second YAML document must be rejected")
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

func TestVariantKey(t *testing.T) {
	if got := VariantKey("/r.yaml", nil); got != "/r.yaml" {
		t.Errorf("no exclusions must key on the bare path, got %q", got)
	}
	if VariantKey("/r.yaml", []string{"b", "a"}) != VariantKey("/r.yaml", []string{"a", "b"}) {
		t.Error("exclusion order must not change the key")
	}
	if VariantKey("/r.yaml", []string{"a"}) == VariantKey("/r.yaml", nil) {
		t.Error("exclusions must produce a distinct key")
	}
	if VariantKey("/r.yaml", []string{"a"}) == VariantKey("/other.yaml", []string{"a"}) {
		t.Error("different files must produce distinct keys")
	}
	// The encoding is length-prefixed, so an ID containing a separator-ish
	// byte can never collide with a differently split set: two such scopes
	// must get distinct variants, not silently share one.
	if VariantKey("/r.yaml", []string{"a\x00b"}) == VariantKey("/r.yaml", []string{"a", "b"}) {
		t.Error(`["a\x00b"] and ["a", "b"] must produce distinct keys`)
	}
	// The key is the path plus a fixed-size digest: the request-time map
	// lookup hashes the key bytes, so key length must not scale with the
	// number or size of the excluded IDs.
	small := VariantKey("/r.yaml", []string{"a"})
	big := VariantKey("/r.yaml", []string{strings.Repeat("x", 4096), "b", "c", "d", "e", "f"})
	if len(small) != len(big) {
		t.Errorf("key length must be independent of the exclusion list: %d vs %d", len(small), len(big))
	}
}

// TestDisabledRuleVariants: one watched file, two effective sets. The filtered
// variant drops exactly the excluded rules, preserves file order (the next
// matching rule decides), and recomputes the precomputed header/method hints;
// the full variant is untouched.
func TestDisabledRuleVariants(t *testing.T) {
	path := writeRules(t, rulesYAML)
	disabled := []string{"dotfile-probe", "log4shell-header", "trace-method", "put-script"}
	cache, err := NewRuleCacheVariants([]VariantSpec{
		{Path: path, Scopes: []string{"defaults"}},
		{Path: path, Disabled: disabled, Scopes: []string{"domain a.test"}},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	full := cache.Get(path)
	filtered := cache.Get(VariantKey(path, disabled))
	if full == nil || filtered == nil {
		t.Fatal("both variants must be loaded")
	}
	if len(full.Rules) != 7 || len(filtered.Rules) != 3 {
		t.Fatalf("rule counts = %d/%d, want 7 full, 3 filtered", len(full.Rules), len(filtered.Rules))
	}

	// A request matching both the excluded first rule and a later rule falls
	// through to the later rule in the filtered set only.
	in := MatchInput{Path: "/backup/.env", Query: "1 union select pw"}
	if r := full.Match(&in); r == nil || r.ID != "dotfile-probe" {
		t.Errorf("full set: got %v, want dotfile-probe", r)
	}
	if r := filtered.Match(&in); r == nil || r.ID != "sqli-union" {
		t.Errorf("filtered set: got %v, want fall-through to sqli-union", r)
	}
	// A request matching only excluded rules matches nothing.
	if r := filtered.Match(&MatchInput{Method: "TRACE", Path: "/.env"}); r != nil {
		t.Errorf("filtered set matched %s, want no match", r.ID)
	}

	// Precomputed hints are rebuilt for the filtered set and kept on the full.
	if len(filtered.HeaderTargets()) != 0 || filtered.NeedsMethod() {
		t.Errorf("filtered hints = %v/%v, want none/false after excluding header+method rules",
			filtered.HeaderTargets(), filtered.NeedsMethod())
	}
	if len(full.HeaderTargets()) != 2 || !full.NeedsMethod() {
		t.Errorf("full hints = %v/%v, want 2 headers and true", full.HeaderTargets(), full.NeedsMethod())
	}
}

// TestUnknownDisabledRuleIDFailsFast: an exclusion that names no rule in the
// file (including a case mismatch) must fail cache construction, naming the
// file, the scope and the unknown ID.
func TestUnknownDisabledRuleIDFailsFast(t *testing.T) {
	path := writeRules(t, rulesYAML)
	for name, ids := range map[string][]string{
		"unknown id":    {"wp-probe"},
		"case mismatch": {"Dotfile-Probe"},
	} {
		_, err := NewRuleCacheVariants([]VariantSpec{
			{Path: path, Disabled: ids, Scopes: []string{"domain a.test"}},
		}, slog.Default())
		if err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
		for _, want := range []string{path, "domain a.test", ids[0]} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q must mention %q", name, err, want)
			}
		}
	}
}

// TestHotReloadRejectsRemovedExcludedID: a watched update that renames a rule
// some scope still disables is rejected wholesale, keeping the last good sets
// for every variant of the file, so the formerly-disabled rule can never
// become active silently. A later fix that restores the ID is picked up.
func TestHotReloadRejectsRemovedExcludedID(t *testing.T) {
	path := writeRules(t, "rules: [ { id: keep, keywords: [ keepkw ] }, { id: banned, keywords: [ badkw ] } ]")
	cache, err := NewRuleCacheVariants([]VariantSpec{
		{Path: path, Scopes: []string{"defaults"}},
		{Path: path, Disabled: []string{"banned"}, Scopes: []string{"domain a.test"}},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	cache.Start(10 * time.Millisecond)
	fkey := VariantKey(path, []string{"banned"})

	if cache.Get(fkey).Match(&MatchInput{Path: "/badkw"}) != nil {
		t.Fatal("excluded rule must not match in the filtered variant")
	}

	// The update renames banned -> renamed while a scope still excludes it:
	// both variants must keep serving the previous rule set.
	update := "rules: [ { id: keep, keywords: [ keepkw2 ] }, { id: renamed, keywords: [ badkw ] } ]"
	if err := os.WriteFile(path, []byte(update), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cache.Get(path).Match(&MatchInput{Path: "/keepkw"}) == nil {
			t.Fatal("rejected reload must keep the last good full set")
		}
		if cache.Get(fkey).Match(&MatchInput{Path: "/badkw"}) != nil {
			t.Fatal("rejected reload must not reactivate the excluded rule")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Restoring the excluded ID makes the update loadable for every variant.
	fixed := "rules: [ { id: keep, keywords: [ keepkw2 ] }, { id: banned, keywords: [ badkw ] } ]"
	if err := os.WriteFile(path, []byte(fixed), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		if cache.Get(path).Match(&MatchInput{Path: "/keepkw2"}) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixed rules never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cache.Get(fkey).Match(&MatchInput{Path: "/badkw"}) != nil {
		t.Fatal("filtered variant must keep excluding banned after the fixed reload")
	}
	if cache.Get(fkey).Match(&MatchInput{Path: "/keepkw2"}) == nil {
		t.Fatal("filtered variant must serve the updated rules")
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
