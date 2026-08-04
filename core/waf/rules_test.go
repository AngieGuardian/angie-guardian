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
  - id: api-json
    action: allow
    targets: [ "header:Accept" ]
    regexes: [ 'application/(json|problem\+json)' ]
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
		{"allow regex in Accept header", MatchInput{Headers: map[string][]string{"accept": {"text/html, application/problem+json; charset=utf-8"}}}, "api-json", ActionAllow},
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

func TestAllowRuleRespectsFileOrder(t *testing.T) {
	in := MatchInput{
		Path:    "/private/data",
		Headers: map[string][]string{"accept": {"application/json"}},
	}
	for name, body := range map[string]string{
		"allow first": `rules:
  - { id: json-client, action: allow, targets: [ "header:accept" ], keywords: [ "application/json" ] }
  - { id: private-path, action: deny, targets: [ path ], keywords: [ "/private/" ] }
`,
		"deny first": `rules:
  - { id: private-path, action: deny, targets: [ path ], keywords: [ "/private/" ] }
  - { id: json-client, action: allow, targets: [ "header:accept" ], keywords: [ "application/json" ] }
`,
	} {
		t.Run(name, func(t *testing.T) {
			rs, err := compileRules([]byte(body), "test")
			if err != nil {
				t.Fatal(err)
			}
			got := rs.Match(&in)
			if name == "allow first" && (got == nil || got.Action != ActionAllow) {
				t.Fatalf("first match = %+v, want allow", got)
			}
			if name == "deny first" && (got == nil || got.Action != ActionDeny) {
				t.Fatalf("first match = %+v, want deny", got)
			}
		})
	}
}

func TestRuleSetPrecomputation(t *testing.T) {
	rs, err := compileRules([]byte(rulesYAML), "test")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"accept", "referer", "x-forwarded-for"}; !slices.Equal(rs.HeaderTargets(), want) {
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

func TestDeadUppercaseRegexWarns(t *testing.T) {
	// The matcher lowercases input, so a case-sensitive uppercase literal can
	// never fire: warn, but do not reject.
	dead := map[string]string{
		"bare uppercase":    "rules: [ { id: a, regexes: [ 'SELECT' ] } ]",
		"uppercase in word": "rules: [ { id: b, regexes: [ 'union\\s+SELECT' ] } ]",
		"dead alternation":  "rules: [ { id: c, regexes: [ 'SELECT|UNION' ] } ]",
		"plus group":        "rules: [ { id: d, regexes: [ '(FOO)+bar' ] } ]",
	}
	for name, body := range dead {
		rs, err := compileRules([]byte(body), "test")
		if err != nil {
			t.Fatalf("%s: unexpected compile error: %v", name, err)
		}
		if len(rs.Warnings) == 0 {
			t.Errorf("%s: expected a dead-regex warning, got none", name)
		}
	}

	// Lowercase literals, case-insensitive flags, uppercase metacharacters
	// (\S, \b, a character class) and avoidable uppercase (an optional or
	// starred group, a live lowercase alternation branch) all still match
	// lowercased input, so no warning.
	live := map[string]string{
		"lowercase":          "rules: [ { id: a, regexes: [ 'union\\s+select' ] } ]",
		"case-insensitive":   "rules: [ { id: b, regexes: [ '(?i)SELECT' ] } ]",
		"metachar \\S":       "rules: [ { id: c, regexes: [ 'a\\S+b' ] } ]",
		"metachar \\b":       "rules: [ { id: d, regexes: [ '\\bwp-login\\b' ] } ]",
		"optional uppercase": "rules: [ { id: e, regexes: [ 'S?elect' ] } ]",
		"live alternation":   "rules: [ { id: f, regexes: [ 'SELECT|select' ] } ]",
		"starred group":      "rules: [ { id: g, regexes: [ '(FOO)*bar' ] } ]",
		"optional group":     "rules: [ { id: h, regexes: [ '(?:UNION )?select' ] } ]",
	}
	for name, body := range live {
		rs, err := compileRules([]byte(body), "test")
		if err != nil {
			t.Fatalf("%s: unexpected compile error: %v", name, err)
		}
		if len(rs.Warnings) != 0 {
			t.Errorf("%s: unexpected warning(s): %v", name, rs.Warnings)
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
	if got := VariantKey([]string{"/r.yaml"}, nil); got != "/r.yaml" {
		t.Errorf("no exclusions must key on the bare path, got %q", got)
	}
	if VariantKey([]string{"/r.yaml"}, []string{"b", "a"}) != VariantKey([]string{"/r.yaml"}, []string{"a", "b"}) {
		t.Error("exclusion order must not change the key")
	}
	if VariantKey([]string{"/r.yaml"}, []string{"a"}) == VariantKey([]string{"/r.yaml"}, nil) {
		t.Error("exclusions must produce a distinct key")
	}
	if VariantKey([]string{"/r.yaml"}, []string{"a"}) == VariantKey([]string{"/other.yaml"}, []string{"a"}) {
		t.Error("different files must produce distinct keys")
	}
	if VariantKey([]string{"/a.yaml", "/b.yaml"}, nil) == VariantKey([]string{"/b.yaml", "/a.yaml"}, nil) {
		t.Error("file order must change the key")
	}
	// The encoding is length-prefixed, so an ID containing a separator-ish
	// byte can never collide with a differently split set: two such scopes
	// must get distinct variants, not silently share one.
	if VariantKey([]string{"/r.yaml"}, []string{"a\x00b"}) == VariantKey([]string{"/r.yaml"}, []string{"a", "b"}) {
		t.Error(`["a\x00b"] and ["a", "b"] must produce distinct keys`)
	}
	// The key is the path plus a fixed-size digest: the request-time map
	// lookup hashes the key bytes, so key length must not scale with the
	// number or size of the excluded IDs.
	small := VariantKey([]string{"/r.yaml"}, []string{"a"})
	big := VariantKey([]string{"/r.yaml"}, []string{strings.Repeat("x", 4096), "b", "c", "d", "e", "f"})
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
	disabled := []string{"api-json", "dotfile-probe", "log4shell-header", "trace-method", "put-script"}
	cache, err := NewRuleCacheVariants([]VariantSpec{
		{Paths: []string{path}, Scopes: []string{"defaults"}},
		{Paths: []string{path}, DisabledIDs: disabled, Scopes: []string{"domain a.test"}},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	full := cache.Get(path)
	filtered := cache.Get(VariantKey([]string{path}, disabled))
	if full == nil || filtered == nil {
		t.Fatal("both variants must be loaded")
	}
	if len(full.Rules) != 8 || len(filtered.Rules) != 3 {
		t.Fatalf("rule counts = %d/%d, want 8 full, 3 filtered", len(full.Rules), len(filtered.Rules))
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
	if len(full.HeaderTargets()) != 3 || !full.NeedsMethod() {
		t.Errorf("full hints = %v/%v, want 3 headers and true", full.HeaderTargets(), full.NeedsMethod())
	}
}

func TestCombinedRuleFilesPreserveBaseOrderAndScopeExclusions(t *testing.T) {
	common := writeRules(t, `
rules:
  - id: secret-path
    action: deny
    targets: [ path ]
    keywords: [ "/.env" ]
`)
	api := writeRules(t, `
rules:
  - id: json-client
    action: allow
    targets: [ "header:accept" ]
    keywords: [ "application/json" ]
  - id: api-fallback
    action: deny
    targets: [ path ]
    regexes: [ "^/" ]
`)
	paths := []string{common, api}
	cache, err := NewRuleCacheVariants([]VariantSpec{
		{Paths: paths, Scopes: []string{"domain api.test"}},
		{Paths: paths, DisabledIDs: []string{"secret-path"}, Scopes: []string{"domain exception.test"}},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	full := cache.Get(VariantKey(paths, nil))
	if rule := full.Match(&MatchInput{Path: "/.env", Headers: map[string][]string{"accept": {"application/json"}}}); rule == nil || rule.ID != "secret-path" {
		t.Fatalf("common rules must run before domain additions, got %v", rule)
	}
	if rule := full.Match(&MatchInput{Path: "/v1/items", Headers: map[string][]string{"accept": {"application/json"}}}); rule == nil || rule.ID != "json-client" || rule.Action != ActionAllow {
		t.Fatalf("clean JSON request must reach the domain allow, got %v", rule)
	}
	filtered := cache.Get(VariantKey(paths, []string{"secret-path"}))
	if rule := filtered.Match(&MatchInput{Path: "/.env", Headers: map[string][]string{"accept": {"application/json"}}}); rule == nil || rule.ID != "json-client" {
		t.Fatalf("disabled common rule must fall through to the domain file, got %v", rule)
	}
}

func TestCombinedRuleFilesRejectDuplicateIDs(t *testing.T) {
	a := writeRules(t, `rules: [ { id: shared, keywords: [ one ] } ]`)
	b := writeRules(t, `rules: [ { id: shared, keywords: [ two ] } ]`)
	_, err := NewRuleCacheVariants([]VariantSpec{{Paths: []string{a, b}, Scopes: []string{"domain api.test"}}}, slog.Default())
	if err == nil {
		t.Fatal("duplicate ids across effective files must fail startup")
	}
	for _, want := range []string{"shared", a, b, "domain api.test"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must mention %q", err, want)
		}
	}
}

func TestCombinedRuleFilesHotReloadRebuildsEffectiveSet(t *testing.T) {
	common := writeRules(t, `rules: [ { id: common, keywords: [ common-old ] } ]`)
	api := writeRules(t, `rules: [ { id: api, action: allow, keywords: [ api-old ] } ]`)
	paths := []string{common, api}
	cache, err := NewRuleCacheVariants([]VariantSpec{{Paths: paths, Scopes: []string{"domain api.test"}}}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	cache.Start(10 * time.Millisecond)
	key := VariantKey(paths, nil)

	if err := os.WriteFile(api, []byte(`rules: [ { id: api, action: allow, keywords: [ api-new ] } ]`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rs := cache.Get(key)
		if rs.Match(&MatchInput{Path: "/api-new"}) != nil {
			if rs.Match(&MatchInput{Path: "/common-old"}) == nil {
				t.Fatal("reloading one source dropped the unchanged common source")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("combined API source never reloaded")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A cross-file duplicate is rejected and leaves the last-good combined set.
	if err := os.WriteFile(common, []byte(`rules: [ { id: api, keywords: [ collision ] } ]`), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	rs := cache.Get(key)
	if rs.Match(&MatchInput{Path: "/common-old"}) == nil || rs.Match(&MatchInput{Path: "/api-new"}) == nil {
		t.Fatal("rejected cross-file duplicate replaced the last-good combined set")
	}
	if err := os.WriteFile(common, []byte(`rules: [ { id: common, keywords: [ common-new ] } ]`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for cache.Get(key).Match(&MatchInput{Path: "/common-new"}) == nil {
		if time.Now().After(deadline) {
			t.Fatal("valid common source after rejected duplicate never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUnknownDisabledRuleIDFailsFast: an exclusion that names no rule in the
// file (including a case mismatch) must fail cache construction, naming the
// file, the scope and the unknown ID.
func TestUnknownDisabledRuleIDFailsFast(t *testing.T) {
	path := writeRules(t, rulesYAML)
	for name, ids := range map[string][]string{
		"unknown id":    {"wp-cms-probe"},
		"case mismatch": {"Dotfile-Probe"},
	} {
		_, err := NewRuleCacheVariants([]VariantSpec{
			{Paths: []string{path}, DisabledIDs: ids, Scopes: []string{"domain a.test"}},
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
		{Paths: []string{path}, Scopes: []string{"defaults"}},
		{Paths: []string{path}, DisabledIDs: []string{"banned"}, Scopes: []string{"domain a.test"}},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	cache.Start(10 * time.Millisecond)
	fkey := VariantKey([]string{path}, []string{"banned"})

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
