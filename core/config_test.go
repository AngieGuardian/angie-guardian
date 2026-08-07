// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testYAML = `
listen: 127.0.0.1:9999
signing_key_file: test-signing.key
store:
  backend: memory
defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m
      thresholds:
        notfound_rate: 20/min
  pow:
    enabled: true
    base_difficulty: 4
    max_difficulty: 6
    token_ttl: 4h
  allowlist:
    ips: [ "10.0.0.0/8", "192.0.2.1" ]
    uas: [ "GoogleBot" ]
    paths: [ "/robots.txt", "/.well-known/" ]
domains:
  example.com:
    pow: { enabled: true, base_difficulty: 5, token_ttl: 2h }
  api.example.com:
    pow: { enabled: false }
  bare.example.com:
`

func loadTestConfig(t *testing.T, yaml string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDomainMerge(t *testing.T) {
	cfg := loadTestConfig(t, testYAML)

	ex := cfg.DomainFor("example.com")
	if ex.PoW.BaseDifficulty != 5 {
		t.Errorf("example.com base_difficulty = %v, want override 5", ex.PoW.BaseDifficulty)
	}
	if ex.PoW.BaseBits() != 20 || ex.PoW.MaxBits() != 24 {
		t.Errorf("example.com bits = %d/%d, want 20/24", ex.PoW.BaseBits(), ex.PoW.MaxBits())
	}
	if ex.PoW.TokenTTL.Std() != 2*time.Hour {
		t.Errorf("example.com token_ttl = %v, want override 2h", ex.PoW.TokenTTL.Std())
	}
	if ex.PoW.MaxDifficulty != 6 {
		t.Errorf("example.com max_difficulty = %v, want inherited 6", ex.PoW.MaxDifficulty)
	}
	if !ex.WAF.IPBehaviour.Enabled {
		t.Error("example.com ip_behaviour should be inherited enabled")
	}
	if got := ex.WAF.IPBehaviour.Thresholds["notfound_rate"]; got.Count != 20 || got.Per != time.Minute {
		t.Errorf("inherited threshold = %+v, want 20/min", got)
	}
	if !ex.Allowlist.MatchIP(netip.MustParseAddr("10.1.2.3")) {
		t.Error("example.com should inherit the default allowlist")
	}

	api := cfg.DomainFor("api.example.com")
	if api.PoW.Enabled {
		t.Error("api.example.com pow should be disabled")
	}
	if api.PoW.BaseDifficulty != 4 {
		t.Errorf("api.example.com base_difficulty = %v, want inherited 4", api.PoW.BaseDifficulty)
	}

	bare := cfg.DomainFor("bare.example.com")
	if !bare.PoW.Enabled || bare.PoW.BaseDifficulty != 4 {
		t.Error("domain with empty body should equal defaults")
	}

	// Unknown host and host normalization fall back to defaults / resolve.
	if cfg.DomainFor("unknown.test").PoW.BaseDifficulty != 4 {
		t.Error("unknown host should get defaults")
	}
	if cfg.DomainFor("EXAMPLE.com:443").PoW.BaseDifficulty != 5 {
		t.Error("host lookup should be case-insensitive and strip the port")
	}
}

// TestBuiltinDifficultyDefaults pins the shipped defaults: a config that
// never mentions difficulty must resolve to base 5 (20 bits) / max 6 (24
// bits), including for unknown hosts falling back to defaults.
func TestBuiltinDifficultyDefaults(t *testing.T) {
	cfg := loadTestConfig(t, "store: { backend: memory }\ndomains: { bare.test: }\n")
	if cfg.Admin.RecentSize != defaultRecentSize {
		t.Fatalf("admin.recent_size = %d, want default %d", cfg.Admin.RecentSize, defaultRecentSize)
	}
	for _, dc := range []*DomainConfig{
		&cfg.Defaults,
		cfg.DomainFor("bare.test"),
		cfg.DomainFor("never-configured.test"),
	} {
		if dc.PoW.BaseDifficulty != 5 || dc.PoW.MaxDifficulty != 6 {
			t.Errorf("default difficulty = %v/%v, want 5/6", dc.PoW.BaseDifficulty, dc.PoW.MaxDifficulty)
		}
		if dc.PoW.BaseBits() != 20 || dc.PoW.MaxBits() != 24 {
			t.Errorf("default bits = %d/%d, want 20/24", dc.PoW.BaseBits(), dc.PoW.MaxBits())
		}
	}
}

// TestFractionalDifficulty covers the fine-grained quarter steps: each 0.25
// on the config scale is exactly one leading-zero bit (2x the work).
func TestFractionalDifficulty(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: true, base_difficulty: 4.25, max_difficulty: 5.75 }
`)
	p := &cfg.Defaults.PoW
	if p.BaseBits() != 17 {
		t.Errorf("base 4.25 = %d bits, want 17", p.BaseBits())
	}
	if p.MaxBits() != 23 {
		t.Errorf("max 5.75 = %d bits, want 23", p.MaxBits())
	}
}

func TestListMatching(t *testing.T) {
	cfg := loadTestConfig(t, testYAML)
	l := &cfg.Defaults.Allowlist

	if !l.MatchIP(netip.MustParseAddr("10.255.0.1")) {
		t.Error("CIDR match failed")
	}
	if !l.MatchIP(netip.MustParseAddr("192.0.2.1")) {
		t.Error("bare IP match failed")
	}
	if l.MatchIP(netip.MustParseAddr("192.0.2.2")) {
		t.Error("bare IP should not match neighbours")
	}
	if !l.MatchUA("Mozilla/5.0 (compatible; googlebot/2.1)") {
		t.Error("UA match should be case-insensitive substring")
	}
	if l.MatchUA("") {
		t.Error("empty UA should never match")
	}
	if !l.MatchPath("/robots.txt") {
		t.Error("exact path match failed")
	}
	if l.MatchPath("/robots.txt.evil") {
		t.Error("exact path entry must not prefix-match")
	}
	if !l.MatchPath("/.well-known/acme-challenge/token") {
		t.Error("trailing-slash entry should prefix-match")
	}
}

func TestVerifiedBotsConfig(t *testing.T) {
	cfg := loadTestConfig(t, `
defaults:
  verified_bots:
    bots:
      - name: googlebot
      - name: google-special
      - name: mybot
        uas: [ "MyBot/1.0" ]
        domains: [ "Crawler.Example.NET." ]
`)
	vb := &cfg.Defaults.VerifiedBots

	if vb.DNSTimeout.Std() != time.Second || vb.CacheTTL.Std() != 12*time.Hour || vb.NegativeTTL.Std() != time.Hour {
		t.Errorf("defaults not applied: %v / %v / %v", vb.DNSTimeout.Std(), vb.CacheTTL.Std(), vb.NegativeTTL.Std())
	}
	if vb.SpoofAction != "deny" {
		t.Errorf("spoof_action = %q, want default deny", vb.SpoofAction)
	}

	g := vb.match("mozilla/5.0 (compatible; googlebot/2.1; +http://www.google.com/bot.html)")
	if g == nil || g.Name != "googlebot" {
		t.Fatalf("preset UA needle should match, got %v", g)
	}
	// googlebot.com ONLY: google.com belongs to the special-case crawler and
	// user-triggered fetcher categories, which must not vouch for Googlebot.
	if len(g.domainsLower) != 1 || g.domainsLower[0] != "googlebot.com" {
		t.Errorf("preset domains = %v, want [googlebot.com]", g.domainsLower)
	}

	s := vb.match("adsbot-google-mobile (+http://www.google.com/mobile/adsbot.html)")
	if s == nil || s.Name != "google-special" {
		t.Fatalf("AdsBot UA should match the google-special preset, got %v", s)
	}
	if len(s.domainsLower) != 1 || s.domainsLower[0] != "google.com" {
		t.Errorf("google-special domains = %v, want [google.com]", s.domainsLower)
	}

	m := vb.match("mybot/1.0 (+https://example.net)")
	if m == nil || m.Name != "mybot" {
		t.Fatalf("custom UA needle should match case-insensitively, got %v", m)
	}
	if len(m.domainsLower) != 1 || m.domainsLower[0] != "crawler.example.net" {
		t.Errorf("custom domains should be lowercased and dot-trimmed: %v", m.domainsLower)
	}

	if vb.match("mozilla/5.0 firefox/140.0") != nil {
		t.Error("plain browser UA must not match any bot")
	}

	if _, ok := cfg.Defaults.WAF.IPBehaviour.Thresholds["bot_spoof"]; !ok {
		t.Error("default thresholds should include bot_spoof")
	}
}

// A custom thresholds entry at the defaults level must merge with the
// built-ins, not replace them: tamper/pow_fail scoring is documented as on by
// default and must survive an operator adding one unrelated rate.
func TestThresholdsMergeWithBuiltins(t *testing.T) {
	cfg := loadTestConfig(t, `
defaults:
  waf:
    ip_behaviour:
      enabled: true
      thresholds:
        notfound_rate: 20/min
        tamper: 3/min
`)
	th := cfg.Defaults.WAF.IPBehaviour.Thresholds
	if got := th["notfound_rate"]; got.Count != 20 {
		t.Errorf("custom threshold lost: %+v", got)
	}
	if got := th["tamper"]; got.Count != 3 {
		t.Errorf("operator override of a built-in must win: %+v", got)
	}
	for _, event := range []string{"rule_match", "pow_fail", "bot_spoof"} {
		if _, ok := th[event]; !ok {
			t.Errorf("built-in threshold %q wiped by a custom entry", event)
		}
	}
	if got := th["challenge_farm"]; got.Count != 80 || got.Per != time.Hour {
		t.Errorf("challenge_farm built-in default = %+v, want 80/h", got)
	}
}

// A threshold value of "off" disables that one event type: it parses to a
// zero rate, occupies the key so the built-in default is not merged back in,
// and 0/min stays a load error (off is the only disable spelling).
func TestThresholdOff(t *testing.T) {
	cfg := loadTestConfig(t, `
defaults:
  waf:
    ip_behaviour:
      enabled: true
      thresholds: { pow_fail: OFF }
`)
	th := cfg.Defaults.WAF.IPBehaviour.Thresholds
	if got := th["pow_fail"]; got.Count != 0 {
		t.Errorf("pow_fail: off parsed to %+v, want zero rate", got)
	}
	if got := th["tamper"]; got.Count != 10 {
		t.Errorf("unrelated built-in disturbed by an off entry: %+v", got)
	}
	// "0/min" staying invalid and "off" being rejected outside the thresholds
	// map are covered in TestConfigValidation.
}

// challenge_farm is configurable at the defaults level and per domain: set
// fleet-wide it is inherited, a domain override (tighter or off) wins, and
// without any operator value the built-in 80/h default applies.
func TestChallengeFarmThresholdScoping(t *testing.T) {
	cfg := loadTestConfig(t, `
defaults:
  waf:
    ip_behaviour:
      enabled: true
      thresholds: { challenge_farm: 30/h }
domains:
  inherit.test:
  tighter.test:
    waf: { ip_behaviour: { thresholds: { challenge_farm: 5/min } } }
  optout.test:
    waf: { ip_behaviour: { thresholds: { challenge_farm: off } } }
`)
	if got := cfg.DomainFor("inherit.test").WAF.IPBehaviour.Thresholds["challenge_farm"]; got.Count != 30 || got.Per != time.Hour {
		t.Errorf("inherit.test challenge_farm = %+v, want inherited 30/h", got)
	}
	if got := cfg.DomainFor("tighter.test").WAF.IPBehaviour.Thresholds["challenge_farm"]; got.Count != 5 || got.Per != time.Minute {
		t.Errorf("tighter.test challenge_farm = %+v, want override 5/min", got)
	}
	if got := cfg.DomainFor("optout.test").WAF.IPBehaviour.Thresholds["challenge_farm"]; got.Count != 0 {
		t.Errorf("optout.test challenge_farm = %+v, want off (zero rate)", got)
	}

	// Without an operator value, the built-in 80/h default applies; one
	// domain tightening it does not leak to a sibling.
	cfg = loadTestConfig(t, `
domains:
  solo.test:
    waf: { ip_behaviour: { enabled: true, thresholds: { challenge_farm: 10/min } } }
  other.test:
`)
	if got := cfg.DomainFor("solo.test").WAF.IPBehaviour.Thresholds["challenge_farm"]; got.Count != 10 {
		t.Errorf("solo.test challenge_farm = %+v, want 10/min", got)
	}
	if got := cfg.DomainFor("other.test").WAF.IPBehaviour.Thresholds["challenge_farm"]; got.Count != 80 || got.Per != time.Hour {
		t.Errorf("other.test challenge_farm = %+v, want built-in 80/h", got)
	}
}

func TestConfigValidation(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "")
	for name, yaml := range map[string]string{
		"bad backend":                            "store: { backend: etcd }",
		"pebble sans path":                       "store: { backend: pebble }",
		"buntdb sync (footgun)":                  "store: { backend: buntdb, path: /tmp/x, sync: true }",
		"bad difficulty":                         "defaults: { pow: { base_difficulty: 9 } }",
		"max below base":                         "defaults: { pow: { base_difficulty: 5, max_difficulty: 4 } }",
		"difficulty below one":                   "defaults: { pow: { base_difficulty: 0.5 } }",
		"negative challenge_ttl":                 "domains: { a.test: { pow: { enabled: true, challenge_ttl: -1s } } }",
		"zero token_ttl when enabled":            "domains: { a.test: { pow: { enabled: true, token_ttl: 0s } } }",
		"negative default token_ttl":             "defaults: { pow: { token_ttl: -5m } }",
		"pow ttl above cap":                      "domains: { a.test: { pow: { enabled: true, challenge_ttl: 192h } } }",
		"difficulty off the quarter grid":        "defaults: { pow: { base_difficulty: 4.3 } }",
		"max off the quarter grid":               "defaults: { pow: { base_difficulty: 4, max_difficulty: 6.1 } }",
		"bad cidr":                               "defaults: { allowlist: { ips: [ \"10.0.0.0/99\" ] } }",
		"bad rate":                               "defaults: { waf: { ip_behaviour: { thresholds: { x: 20/fortnight } } } }",
		"zero threshold rate":                    "defaults: { waf: { ip_behaviour: { thresholds: { pow_fail: 0/min } } } }",
		"off outside thresholds":                 "defaults: { pow: { issuance_rate_limit: off } }",
		"unknown field":                          "listne: 1.2.3.4:80",
		"unknown field in domain overlay":        "domains: { a.test: { waf: { keywrods: { enabled: true } } } }",
		"unknown nested field in domain overlay": "domains: { a.test: { pow: { enabeld: true } } }",
		"duplicate host":                         "domains: { a.test: , \"A.test:443\": }",
		"non-loopback listen sans trusted_proxy": "listen: 0.0.0.0:8071",
		"malformed trusted proxy listen":         "listen: malformed\ntrusted_proxy: true",
		"nonnumeric trusted proxy port":          "listen: 0.0.0.0:http\ntrusted_proxy: true",
		"malformed admin listen":                 "admin: { listen: malformed, token: secret }",
		"nonloopback admin without token":        "admin: { listen: 0.0.0.0:8072 }",
		"negative recent size":                   "admin: { recent_size: -1 }",
		"oversized recent size":                  "admin: { recent_size: 16385 }",
		"max_block_ttl below block_ttl":          "defaults: { waf: { ip_behaviour: { block_ttl: 1h, max_block_ttl: 15m } } }",
		"negative max_block_ttl":                 "defaults: { waf: { ip_behaviour: { max_block_ttl: -5m } } }",
		"oversized max_block_ttl":                "defaults: { waf: { ip_behaviour: { max_block_ttl: 8761h } } }",
		"bot without name":                       "defaults: { verified_bots: { bots: [ { uas: [X], domains: [x.test] } ] } }",
		"unknown bot preset":                     "defaults: { verified_bots: { bots: [ { name: mybot } ] } }",
		"bot empty domain":                       "defaults: { verified_bots: { bots: [ { name: mybot, uas: [MyBot], domains: [\"\"] } ] } }",
		"bad spoof_action":                       "defaults: { verified_bots: { spoof_action: block } }",
		"negative dns_timeout":                   "defaults: { verified_bots: { dns_timeout: -1s } }",
		"oversized bot cache ttl":                "defaults: { verified_bots: { cache_ttl: 8761h } }",
		"bot also in ua allowlist":               "defaults: { allowlist: { uas: [ Googlebot ] }, verified_bots: { bots: [ { name: googlebot } ] } }",
		"bot overlaps ua allowlist per-domain":   "domains: { a.test: { allowlist: { uas: [ googlebot ] }, verified_bots: { bots: [ { name: googlebot } ] } } }",
		"bad country code":                       "geoip: { location_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { countries: [ Netherlands ] } } }",
		"country in two selectors":               "geoip: { location_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { countries: [ NL ] }, challenge: { countries: [ nl ] } } }",
		"asn in two selectors":                   "geoip: { asn_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { asns: [ 64500 ] }, allow: { asns: [ 64500 ] } } }",
		"geo enabled but inert":                  "geoip: { location_db: /x.mmdb }\ndefaults: { geo: { enabled: true } }",
		"geo without databases":                  "defaults: { geo: { enabled: true, deny: { countries: [ NL ] } } }",
		"country rules sans location_db":         "geoip: { asn_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { countries: [ NL ] } } }",
		"asn rules sans asn_db":                  "geoip: { location_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { asns: [ 64500 ] } } }",
		"bad geo default_action":                 "geoip: { location_db: /x.mmdb }\ndefaults: { geo: { enabled: true, default_action: block, deny: { countries: [ NL ] } } }",
		"geo on domain without databases":        "domains: { a.test: { geo: { enabled: true, deny: { countries: [ NL ] } } } }",
		"feed sans source":                       "reputation: { feeds: [ { name: x } ] }",
		"feed with two sources":                  "reputation: { feeds: [ { name: x, url: \"https://a/b\", file: /a/b } ] }",
		"feed bad name":                          "reputation: { feeds: [ { name: \"sp aces\", file: /a/b } ] }",
		"feed dup name":                          "reputation: { feeds: [ { name: x, file: /a }, { name: x, file: /b } ] }",
		"feed bad action":                        "reputation: { feeds: [ { name: x, file: /a/b, action: block } ] }",
		"feed bad url scheme":                    "reputation: { feeds: [ { name: x, url: \"ftp://a/b\" } ] }",
		"feed refresh too low":                   "reputation: { feeds: [ { name: x, url: \"https://a/b\", refresh: 10s } ] }",
		"bot empty ua":                           "defaults: { verified_bots: { bots: [ { name: mybot, uas: [\"  \"], domains: [x.test] } ] } }",
		"empty allowlist ua":                     "defaults: { allowlist: { uas: [\"  \"] } }",
		"pow without signing key":                "defaults: { pow: { enabled: true } }",
		"anomaly without model":                  "defaults: { anomaly: { enabled: true, challenge_threshold: 0.8, deny_threshold: 0.9 } }",
		"rules without file":                     "defaults: { waf: { rules: { enabled: true } } }",
		"reputation without feeds":               "defaults: { reputation: { enabled: true } }",
		"nan difficulty":                         "defaults: { pow: { base_difficulty: .nan } }",
		"infinite max difficulty":                "defaults: { pow: { max_difficulty: .inf } }",
		"subsecond pow token ttl":                "signing_key_file: /tmp/key\ndefaults: { pow: { enabled: true, token_ttl: 999ms } }",
		"nan anomaly threshold":                  "defaults: { anomaly: { model: model.json, challenge_threshold: .nan } }",
		"nested paths":                           "domains: { a.test: { paths: { \"/api/\": { paths: { \"/v1/\": } } } } }",
		"nested paths under defaults":            "defaults: { paths: { \"/api/\": { paths: { \"/v1/\": } } } }",
		"bad path key under defaults":            "defaults: { paths: { \"api/\": { pow: { enabled: false } } } }",
		"typo inside defaults path overlay":      "defaults: { paths: { \"/api/\": { pow: { enabeld: true } } } }",
		"defaults path pow without signing key":  "defaults: { paths: { \"/app/\": { pow: { enabled: true } } } }",
		"path key without slash":                 "domains: { a.test: { paths: { \"api/\": { pow: { enabled: false } } } } }",
		"empty path key":                         "domains: { a.test: { paths: { \"\": { pow: { enabled: false } } } } }",
		"percent-encoded path key":               "domains: { a.test: { paths: { \"/api%2Fv1/\": { pow: { enabled: false } } } } }",
		"path key with query":                    "domains: { a.test: { paths: { \"/api?x=1\": { pow: { enabled: false } } } } }",
		"typo inside path overlay":               "domains: { a.test: { paths: { \"/api/\": { pow: { enabeld: true } } } } }",
		"bad difficulty inside path overlay":     "domains: { a.test: { paths: { \"/api/\": { pow: { base_difficulty: 9 } } } } }",
		"path pow without signing key":           "domains: { a.test: { paths: { \"/app/\": { pow: { enabled: true, token_ttl: 1h, challenge_ttl: 5m } } } } }",
		"path rules without file":                "domains: { a.test: { paths: { \"/api/\": { waf: { rules: { enabled: true } } } } } }",
		"empty disabled rule id":                 "defaults: { waf: { rules: { enabled: true, files: [ r.yaml ], disabled_ids: [ \"\" ] } } }",
		"whitespace disabled rule id":            "defaults: { waf: { rules: { enabled: true, files: [ r.yaml ], disabled_ids: [ \"  \" ] } } }",
		"duplicate disabled rule id":             "defaults: { waf: { rules: { enabled: true, files: [ r.yaml ], disabled_ids: [ a, a ] } } }",
		"duplicate cumulative rules file":        "defaults: { waf: { rules: { files: [ common.yaml ] } } }\ndomains: { a.test: { waf: { rules: { files: [ common.yaml ] } } } }",
		"exclusions without file":                "defaults: { waf: { rules: { disabled_ids: [ a ] } } }",
		"parked exclusions without file":         "domains: { a.test: { waf: { rules: { enabled: false, disabled_ids: [ a ] } } } }",
		"path exclusions without file":           "domains: { a.test: { paths: { \"/api/\": { waf: { rules: { disabled_ids: [ a ] } } } } } }",
		"path reputation without feeds":          "domains: { a.test: { paths: { \"/api/\": { reputation: { enabled: true } } } } }",
		"path geo without databases":             "domains: { a.test: { paths: { \"/api/\": { geo: { enabled: true, deny: { countries: [ NL ] } } } } } }",
	} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestMinimumPoWTokenTTLIsAccepted(t *testing.T) {
	cfg := loadTestConfig(t, "signing_key_file: /tmp/key\ndefaults: { pow: { enabled: true, token_ttl: 1s } }")
	if got := cfg.Defaults.PoW.TokenTTL.Std(); got != time.Second {
		t.Fatalf("token_ttl = %v, want 1s", got)
	}
}

func TestGuardianExampleConfigLoads(t *testing.T) {
	if _, err := LoadConfig("../guardian.example.yaml"); err != nil {
		t.Fatalf("guardian.example.yaml must remain a valid starting config: %v", err)
	}
}

func TestConfigRejectsTrailingYAMLDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte("listen: 127.0.0.1:8071\n---\nlisten: 127.0.0.1:9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("second YAML document must be rejected")
	}
}

func TestValidateConfigArtifactsLoadsRules(t *testing.T) {
	cfg := loadTestConfig(t, `
signing_key_file: test-signing.key
defaults:
  waf:
    rules:
      enabled: true
      files: [ /definitely/missing/rules.yaml ]
`)
	if err := ValidateConfigArtifacts(cfg, slog.Default()); err == nil {
		t.Fatal("missing rules artifact must fail preflight validation")
	}
}

// TestTrustedProxyAllowsNonLoopback confirms the opt-in lets a non-loopback
// auth listener bind (the operator has isolated it to Angie), while it stays
// refused without the flag (covered above).
func TestTrustedProxyAllowsNonLoopback(t *testing.T) {
	cfg := loadTestConfig(t, "listen: 0.0.0.0:8071\ntrusted_proxy: true\n")
	if cfg.Listen != "0.0.0.0:8071" || !cfg.TrustedProxy {
		t.Fatalf("trusted_proxy non-loopback bind should load, got listen=%q trusted=%v", cfg.Listen, cfg.TrustedProxy)
	}
}

// TestDomainLabel confirms metric labels are bounded: configured hosts map to
// their normalized key, everything else (including client-spoofed Host values)
// collapses to "default" so the label set can't be exploded into an OOM.
func TestDomainLabel(t *testing.T) {
	cfg := loadTestConfig(t, testYAML)
	cases := map[string]string{
		"example.com":          "example.com",
		"EXAMPLE.com:443":      "example.com", // case + port normalized
		"api.example.com":      "api.example.com",
		"unconfigured.test":    "default",
		"evil-\x00-flood.test": "default",
		"":                     "default",
	}
	for host, want := range cases {
		if got := cfg.DomainLabel(host); got != want {
			t.Errorf("DomainLabel(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestDomainLabelStamping pins where the metric label actually comes from. It
// rides on the resolved config itself rather than being carried alongside it,
// so every config a request can land on has to be stamped at load: the domain,
// each of its path overlays, and Defaults. Miss one and that config reports an
// empty label, which no other test would catch, because DomainLabel resolves
// the host without ever consulting an overlay.
//
// An overlay must carry its HOST's label, never its path: paths are
// client-controlled and unbounded, so one reaching a metric is the same
// series-explosion the whole labelling scheme exists to prevent.
func TestDomainLabelStamping(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: false }
domains:
  SHOP.test:
    pow: { enabled: true, base_difficulty: 1 }
    paths:
      "/admin/":
        pow: { base_difficulty: 2 }
      "/api":
        pow: { enabled: false }
`)
	cases := []struct{ host, uri, want string }{
		{"shop.test", "/", "shop.test"},
		{"SHOP.test:8443", "/admin/panel", "shop.test"}, // overlay keeps the host key
		{"shop.test", "/api", "shop.test"},
		{"unconfigured.test", "/admin/panel", "default"},
	}
	for _, tc := range cases {
		if got := cfg.ConfigFor(tc.host, tc.uri).label; got != tc.want {
			t.Errorf("ConfigFor(%q, %q).label = %q, want %q", tc.host, tc.uri, got, tc.want)
		}
	}
	// Reached directly by every unconfigured host, so it must never be blank.
	if cfg.Defaults.label != "default" {
		t.Errorf("Defaults.label = %q, want %q", cfg.Defaults.label, "default")
	}
	// Belt and braces: nothing a request can resolve to may be unlabelled.
	for key, dc := range cfg.resolved {
		if dc.label != key {
			t.Errorf("resolved[%q].label = %q, want %q", key, dc.label, key)
		}
		for _, ov := range dc.pathOverrides {
			if ov.cfg.label != key {
				t.Errorf("resolved[%q] overlay %q label = %q, want %q", key, ov.key, ov.cfg.label, key)
			}
		}
	}
}

const geoYAML = `
geoip:
  location_db: /var/lib/test/country.mmdb
  asn_db: /var/lib/test/asn.mmdb
reputation:
  cache_dir: /var/lib/test/feeds
  feeds:
    - name: bad-actors
      url: https://feeds.test/level1.netset
    - name: local
      file: /etc/guardian/local.list
      action: challenge
defaults:
  geo:
    enabled: true
    deny: { countries: [ ru ], asns: [ 64500 ] }
    challenge: { countries: [ CN ] }
  reputation:
    enabled: true
domains:
  home.test:
    geo:
      enabled: true
      allow: { countries: [ NL ] }
      deny: { countries: [] }
      challenge: { countries: [] }
      default_action: deny
  open.test:
    geo: { enabled: false }
`

func TestGeoConfig(t *testing.T) {
	cfg := loadTestConfig(t, geoYAML)

	g := &cfg.Defaults.Geo
	for _, tc := range []struct {
		country        string
		asn            uint32
		action, reason string
	}{
		{"RU", 0, "deny", "geo:country:RU"}, // lowercase config entry normalized
		{"US", 64500, "deny", "geo:asn:64500"},
		{"CN", 0, "challenge", "geo:country:CN"},
		{"US", 64501, "", ""},
		{"", 0, "", ""}, // unknown origin passes under default_action allow
	} {
		action, reason := g.Action(tc.country, tc.asn)
		if action != tc.action || reason != tc.reason {
			t.Errorf("Action(%q, %d) = (%q, %q), want (%q, %q)",
				tc.country, tc.asn, action, reason, tc.action, tc.reason)
		}
	}

	// Allow-only scoping: home country passes, everything else (including
	// unknown origins) gets default_action.
	home := &cfg.DomainFor("home.test").Geo
	if action, _ := home.Action("NL", 0); action != "" {
		t.Errorf("home country should pass, got %q", action)
	}
	if action, reason := home.Action("DE", 0); action != "deny" || reason != "geo:default" {
		t.Errorf("unlisted country = (%q, %q), want (deny, geo:default)", action, reason)
	}
	if action, _ := home.Action("", 0); action != "deny" {
		t.Error("unknown origin should get default_action deny")
	}

	if action, _ := cfg.DomainFor("open.test").Geo.Action("RU", 0); action != "" {
		t.Error("disabled geo must never act")
	}

	// Feed defaults and the intel bridge.
	ic := cfg.IntelConfig()
	if ic.LocationDB == "" || ic.ASNDB == "" || ic.CacheDir == "" {
		t.Fatalf("intel config incomplete: %+v", ic)
	}
	if len(ic.Feeds) != 2 {
		t.Fatalf("want 2 feeds, got %d", len(ic.Feeds))
	}
	if f := ic.Feeds[0]; f.Action != "deny" || f.Refresh != 12*time.Hour {
		t.Errorf("feed defaults not applied: %+v", f)
	}
	if f := ic.Feeds[1]; f.Action != "challenge" || f.File == "" {
		t.Errorf("unexpected second feed: %+v", f)
	}
	if !cfg.Defaults.Reputation.Enabled || cfg.DomainFor("home.test").Reputation.Enabled != true {
		t.Error("reputation enablement should inherit from defaults")
	}
}

const pathOverlayYAML = `
listen: 127.0.0.1:9999
signing_key_file: test-signing.key
store:
  backend: memory
defaults:
  pow:
    base_difficulty: 4
    max_difficulty: 6
    token_ttl: 4h
domains:
  example.com:
    pow: { enabled: true, base_difficulty: 5 }
    paths:
      "/api/":
        pow: { enabled: false }
      "/api/v1/":
        pow: { enabled: false, max_difficulty: 7 }
      "/api/v1/solve":
        pow: { enabled: true, base_difficulty: 6, max_difficulty: 7 }
      "/admin/":
        pow: { base_difficulty: 6, max_difficulty: 7 }
  plain.example.com:
    pow: { enabled: true }
`

// TestPathOverlayMerge pins the three-level inheritance chain: defaults,
// then the domain overlay, then the path overlay, each only overriding the
// fields it mentions.
func TestPathOverlayMerge(t *testing.T) {
	cfg := loadTestConfig(t, pathOverlayYAML)
	dom := cfg.DomainFor("example.com")

	api := dom.ForPath("/api/x")
	if api.PoW.Enabled {
		t.Error("/api/ overlay should disable pow")
	}
	if api.PoW.BaseDifficulty != 5 {
		t.Errorf("/api/ base_difficulty = %v, want domain's 5", api.PoW.BaseDifficulty)
	}
	if api.PoW.TokenTTL.Std() != 4*time.Hour {
		t.Errorf("/api/ token_ttl = %v, want defaults' 4h", api.PoW.TokenTTL.Std())
	}

	admin := dom.ForPath("/admin/panel")
	if !admin.PoW.Enabled || admin.PoW.BaseDifficulty != 6 {
		t.Errorf("/admin/ should inherit enabled and override base to 6, got %+v", admin.PoW)
	}

	// The domain config itself is untouched by its overlays.
	if !dom.PoW.Enabled || dom.PoW.BaseDifficulty != 5 {
		t.Errorf("domain config mutated by path overlays: %+v", dom.PoW)
	}
	// A sibling domain has no overlays at all.
	if got := cfg.DomainFor("plain.example.com").ForPath("/api/x"); !got.PoW.Enabled {
		t.Error("plain.example.com has no overlays; /api/ must use the domain config")
	}
}

// TestPathOverlayLongestMatch pins the specificity order: longest bare key
// first, an exact key beats a prefix key, and a prefix key matches its own
// bare path.
func TestPathOverlayLongestMatch(t *testing.T) {
	cfg := loadTestConfig(t, pathOverlayYAML)
	dom := cfg.DomainFor("example.com")

	for path, wantBase := range map[string]float64{
		"/api/x":        5, // "/api/" wins, pow off, base inherited from domain
		"/api":          5, // prefix key matches its own bare path
		"/api/v1/x":     5, // "/api/v1/" wins over "/api/"
		"/api/v1/solve": 6, // exact key wins over "/api/v1/"
		"/admin/x":      6,
	} {
		got := dom.ForPath(path)
		if got.PoW.BaseDifficulty != wantBase {
			t.Errorf("ForPath(%q).base = %v, want %v", path, got.PoW.BaseDifficulty, wantBase)
		}
	}
	for path, wantEnabled := range map[string]bool{
		"/api/x":        false,
		"/api/v1/x":     false,
		"/api/v1/solve": true,
		"/admin/x":      true,
		"/":             true,
	} {
		if got := dom.ForPath(path).PoW.Enabled; got != wantEnabled {
			t.Errorf("ForPath(%q).enabled = %v, want %v", path, got, wantEnabled)
		}
	}
	// No match returns the domain config itself, not a copy.
	if dom.ForPath("/other") != dom {
		t.Error("unmatched path must return the domain config pointer")
	}
}

// TestPathOverlayDecodedMatch: overlay selection happens on the decoded path
// (the honeypot/WAF convention), so percent-encoding cannot dodge an
// override.
func TestPathOverlayDecodedMatch(t *testing.T) {
	cfg := loadTestConfig(t, pathOverlayYAML)
	if cfg.ConfigFor("example.com", "/api%2Fv1%2Fthing?x=1").PoW.Enabled {
		t.Error("encoded /api%2Fv1/ URI must still hit the /api/v1/ overlay")
	}
	if !cfg.ConfigFor("example.com", "/apix").PoW.Enabled {
		t.Error("/apix must not match the /api/ prefix")
	}
	if cfg.ConfigFor("EXAMPLE.com:443", "/api/x").PoW.Enabled {
		t.Error("host normalization must apply before path resolution")
	}
	// Unknown hosts fall back to defaults, which carry no overlays here.
	if cfg.ConfigFor("unknown.test", "/api/x") != &cfg.Defaults {
		t.Error("unknown host must resolve to defaults regardless of path")
	}
}

const defaultsPathOverlayYAML = `
listen: 127.0.0.1:9999
signing_key_file: test-signing.key
store:
  backend: memory
defaults:
  pow: { enabled: true, base_difficulty: 5, max_difficulty: 6 }
  allowlist:
    paths: [ "/.well-known/acme-challenge/" ]
  paths:
    "/robots.txt":
      pow: { enabled: false }
    "/manifest.json":
      pow: { enabled: false }
    "/apple-touch-icon.png":
      pow: { enabled: false }
    "/api/":
      pow: { base_difficulty: 5.5 }
domains:
  plain.test:
    pow: { base_difficulty: 6 }
  own.test:
    paths:
      "/api/":
        pow: { enabled: false }
      "/shop/":
        pow: { base_difficulty: 5.25 }
  optout.test:
    paths:
      "/robots.txt":
        pow: { enabled: true }
`

// TestDefaultsPathOverlayInherited pins the fleet-wide overlay: a paths: entry
// under defaults: applies to unknown hosts and to every configured domain,
// over that domain's own settings rather than the defaults'.
func TestDefaultsPathOverlayInherited(t *testing.T) {
	cfg := loadTestConfig(t, defaultsPathOverlayYAML)

	// Unknown hosts resolve through the defaults' own overlays.
	if cfg.ConfigFor("unknown.test", "/robots.txt").PoW.Enabled {
		t.Error("defaults overlay must disable pow at /robots.txt for unknown hosts")
	}
	for _, path := range []string{"/manifest.json", "/apple-touch-icon.png"} {
		if cfg.ConfigFor("unknown.test", path).PoW.Enabled {
			t.Errorf("defaults overlay must disable pow at %s for unknown hosts", path)
		}
	}
	if !cfg.ConfigFor("unknown.test", "/other").PoW.Enabled {
		t.Error("unmatched path on an unknown host must keep the defaults' pow")
	}
	if cfg.ConfigFor("unknown.test", "/other") != &cfg.Defaults {
		t.Error("unmatched path must return the defaults pointer, not a copy")
	}
	if !cfg.ConfigFor("unknown.test", "/.well-known/acme-challenge/token").Allowlist.MatchPath("/.well-known/acme-challenge/token") {
		t.Error("defaults allowlist must inherit the ACME challenge prefix on unknown hosts")
	}

	// A domain that declares no paths: of its own still inherits them, and the
	// overlay sits on top of that domain's config: base_difficulty stays the
	// domain's 6, not the defaults' 5.
	plain := cfg.ConfigFor("plain.test", "/robots.txt")
	if plain.PoW.Enabled {
		t.Error("plain.test must inherit the defaults' /robots.txt overlay")
	}
	if plain.PoW.BaseDifficulty != 6 {
		t.Errorf("inherited overlay base_difficulty = %v, want the domain's 6", plain.PoW.BaseDifficulty)
	}
	if got := cfg.ConfigFor("plain.test", "/api/x").PoW.BaseDifficulty; got != 5.5 {
		t.Errorf("plain.test /api/ base_difficulty = %v, want the inherited 5.5", got)
	}

	// A domain with its own paths: keeps the inherited keys too, and its own
	// entry for a shared key merges over the inherited one field by field.
	if cfg.ConfigFor("own.test", "/robots.txt").PoW.Enabled {
		t.Error("own paths: must not drop the inherited /robots.txt overlay")
	}
	api := cfg.ConfigFor("own.test", "/api/x")
	if api.PoW.Enabled {
		t.Error("own.test /api/ must win over the inherited overlay")
	}
	if api.PoW.BaseDifficulty != 5.5 {
		t.Errorf("own.test /api/ base_difficulty = %v, want the inherited layer's 5.5", api.PoW.BaseDifficulty)
	}
	if got := cfg.ConfigFor("own.test", "/shop/x").PoW.BaseDifficulty; got != 5.25 {
		t.Errorf("own.test /shop/ base_difficulty = %v, want 5.25", got)
	}

	// Naming the same key is how a domain opts out of an inherited overlay.
	if !cfg.ConfigFor("optout.test", "/robots.txt").PoW.Enabled {
		t.Error("optout.test must be able to re-enable pow at an inherited key")
	}

	// Neither the defaults nor a domain config is mutated by its overlays.
	if !cfg.Defaults.PoW.Enabled || cfg.Defaults.PoW.BaseDifficulty != 5 {
		t.Errorf("defaults mutated by path overlays: %+v", cfg.Defaults.PoW)
	}
	if dom := cfg.DomainFor("plain.test"); !dom.PoW.Enabled || dom.PoW.BaseDifficulty != 6 {
		t.Errorf("domain mutated by inherited path overlays: %+v", dom.PoW)
	}
}

// TestDefaultsPathOverlayScopeWalks: config walks that must cover every scope
// (files to watch, allowlist union, behaviour windows, metric labels) have to
// see the defaults' overlays too, not just the domains'.
func TestDefaultsPathOverlayScopeWalks(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
geoip: { asn_db: /x.mmdb }
defaults:
  allowlist: { ips: [ "10.0.0.0/8" ] }
  paths:
    "/robots.txt":
      allowlist: { ips: [ "192.0.2.0/24" ] }
      waf:
        rules: { enabled: true, files: [ rules.yaml ] }
        ip_behaviour: { enabled: true, thresholds: { rule_match: 3/h } }
domains:
  a.test: {}
`)
	overlay := cfg.ConfigFor("unknown.test", "/robots.txt")
	if !overlay.Allowlist.MatchIP(netip.MustParseAddr("192.0.2.7")) {
		t.Error("defaults path overlay allowlist must be compiled")
	}
	if overlay.label != "default" {
		t.Errorf("defaults overlay label = %q, want %q", overlay.label, "default")
	}
	var found bool
	for _, p := range cfg.AllowlistUnion() {
		if p == netip.MustParsePrefix("192.0.2.0/24") {
			found = true
		}
	}
	if !found {
		t.Error("AllowlistUnion must include prefixes from defaults path overlays")
	}
	if files := cfg.RuleFiles(); len(files) != 1 || files[0] != "rules.yaml" {
		t.Errorf("RuleFiles = %v, want [rules.yaml] from the defaults path overlay", files)
	}
	if scopes := cfg.RuleVariants()[0].Scopes; len(scopes) == 0 || scopes[0] != "defaults path /robots.txt" {
		t.Errorf("RuleVariants scopes = %v, want the defaults path overlay named", scopes)
	}
	if !slices.Contains(cfg.BehaviourWindows(), BehaviourWindow{Event: "rule_match", Window: time.Hour}) {
		t.Errorf("BehaviourWindows = %v, want the defaults path overlay 1h rule_match window", cfg.BehaviourWindows())
	}
}

// TestPathOverlayNormalizedMatch: overlay selection happens on the
// dot-segment-normalized path (what Angie actually serves), so "/api/../x"
// can neither adopt the lax /api/ overlay nor escape a strict one.
func TestPathOverlayNormalizedMatch(t *testing.T) {
	cfg := loadTestConfig(t, pathOverlayYAML)
	for uri, wantBase := range map[string]float64{
		"/api/../admin/panel":        6, // serves /admin/panel: strict overlay applies
		"/static/../api/v1/x":        5, // serves /api/v1/x: that overlay applies
		"/api/../../admin/./panel":   6, // ".." above root clamps at /
		"//admin//panel":             6, // duplicate slashes merge like Angie's merge_slashes
		"/api/%2e%2e/admin/panel":    6, // encoded dot segments decode before cleaning
		"/api/v1/solve/../solve?x=1": 6, // exact key still reachable through a dot segment
	} {
		if got := cfg.ConfigFor("example.com", uri).PoW.BaseDifficulty; got != wantBase {
			t.Errorf("ConfigFor(%q).base = %v, want %v", uri, got, wantBase)
		}
	}
	if cfg.ConfigFor("example.com", "/api/../api/x").PoW.Enabled {
		t.Error("/api/../api/x serves /api/x and must keep the /api/ overlay")
	}
}

// TestPathOverlayCompiled: compiled state (list prefixes, UA needles) must be
// rebuilt for the merged path config after the yaml round-trip.
func TestPathOverlayCompiled(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
defaults:
  allowlist:
    ips: [ "10.0.0.0/8" ]
domains:
  a.test:
    paths:
      "/api/":
        allowlist:
          ips: [ "10.0.0.0/8", "192.0.2.0/24" ]
`)
	pc := cfg.DomainFor("a.test").ForPath("/api/x")
	if !pc.Allowlist.MatchIP(netip.MustParseAddr("192.0.2.7")) {
		t.Error("path overlay allowlist must be compiled and match its own entry")
	}
	if !pc.Allowlist.MatchIP(netip.MustParseAddr("10.1.2.3")) {
		t.Error("path overlay must keep the inherited allowlist entries")
	}
	if cfg.DomainFor("a.test").Allowlist.MatchIP(netip.MustParseAddr("192.0.2.7")) {
		t.Error("domain config must not gain the path overlay's entry")
	}
}

// TestPathOverlayFileCollection: rule and model files referenced only by a
// path overlay must reach the snapshot caches.
func TestPathOverlayFileCollection(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
domains:
  a.test:
    paths:
      "/api/":
        waf:
          rules: { enabled: true, files: [ path-rules.yaml ] }
          anomaly: { enabled: true, model: path-model.json, challenge_at: 0.8, deny_at: 0.9 }
`)
	rules := cfg.RuleFiles()
	if len(rules) != 1 || rules[0] != "path-rules.yaml" {
		t.Errorf("RuleFiles = %v, want [path-rules.yaml]", rules)
	}
	models := cfg.ModelFiles()
	if len(models) != 1 || models[0] != "path-model.json" {
		t.Errorf("ModelFiles = %v, want [path-model.json]", models)
	}
	specs := cfg.ModelSpecs()
	if len(specs) != 1 || !slices.Equal(specs[0].RequiredHosts, []string{"a.test"}) {
		t.Errorf("ModelSpecs = %#v, want required host a.test", specs)
	}
}

// TestDisabledIDsOverlay pins the list-overlay semantics for
// waf.rules.disabled_ids: omitted inherits, a non-empty list replaces
// wholesale, an explicit [] clears, and a path overlay replaces the domain's
// resolved list. RuleVariants must collect one spec per distinct
// (files, exclusions) pair with the scope labels that use it, including a
// parked (enabled: false) scope that still carries exclusions.
func TestDisabledIDsOverlay(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
defaults:
  waf:
    rules: { enabled: true, files: [ common.yaml ], disabled_ids: [ wp-cms-probe ] }
domains:
  inherit.test:
  replace.test:
    waf: { rules: { disabled_ids: [ scanner-ua, sqli-tautology ] } }
  clear.test:
    waf: { rules: { disabled_ids: [] } }
  otherfile.test:
    waf: { rules: { files: [ api.yaml ], disabled_ids: [ scanner-ua ] } }
  parked.test:
    waf: { rules: { enabled: false, disabled_ids: [ sqli-tautology ] } }
  pathed.test:
    paths:
      "/legacy/":
        waf: { rules: { disabled_ids: [ sqli-tautology ] } }
`)
	ids := func(dc *DomainConfig) []string { return dc.WAF.Rules.DisabledIDs }
	if got := ids(cfg.DomainFor("inherit.test")); !slices.Equal(got, []string{"wp-cms-probe"}) {
		t.Errorf("inherit.test = %v, want inherited [wp-cms-probe]", got)
	}
	if got := ids(cfg.DomainFor("replace.test")); !slices.Equal(got, []string{"scanner-ua", "sqli-tautology"}) {
		t.Errorf("replace.test = %v, want replacement [scanner-ua sqli-tautology]", got)
	}
	if got := ids(cfg.DomainFor("clear.test")); len(got) != 0 {
		t.Errorf("clear.test = %v, want [] to clear the inherited list", got)
	}
	if got := ids(cfg.DomainFor("pathed.test")); !slices.Equal(got, []string{"wp-cms-probe"}) {
		t.Errorf("pathed.test domain = %v, want inherited [wp-cms-probe]", got)
	}
	if got := ids(cfg.DomainFor("pathed.test").ForPath("/legacy/x")); !slices.Equal(got, []string{"sqli-tautology"}) {
		t.Errorf("pathed.test /legacy/ = %v, want overlay [sqli-tautology]", got)
	}

	specs := cfg.RuleVariants()
	byScope := make(map[string]string) // scope label -> "path|sorted ids"
	for _, s := range specs {
		sorted := slices.Clone(s.DisabledIDs)
		slices.Sort(sorted)
		for _, scope := range s.Scopes {
			byScope[scope] = strings.Join(s.Paths, "+") + "|" + strings.Join(sorted, ",")
		}
	}
	want := map[string]string{
		"defaults":                         "common.yaml|wp-cms-probe",
		"domain inherit.test":              "common.yaml|wp-cms-probe",
		"domain replace.test":              "common.yaml|scanner-ua,sqli-tautology",
		"domain clear.test":                "common.yaml|",
		"domain otherfile.test":            "common.yaml+api.yaml|scanner-ua",
		"domain parked.test":               "common.yaml|sqli-tautology",
		"domain pathed.test":               "common.yaml|wp-cms-probe",
		"domain pathed.test path /legacy/": "common.yaml|sqli-tautology",
	}
	for scope, wantVariant := range want {
		if got, ok := byScope[scope]; !ok || got != wantVariant {
			t.Errorf("scope %q resolved to %q (present=%v), want %q", scope, got, ok, wantVariant)
		}
	}
	// One spec per distinct (files, exclusions) pair: defaults, inherit.test and
	// pathed.test share one; parked.test and the /legacy/ overlay share another.
	if len(specs) != 5 {
		t.Errorf("RuleVariants returned %d specs, want 5 distinct variants: %+v", len(specs), specs)
	}
	files := cfg.RuleFiles()
	slices.Sort(files)
	if !slices.Equal(files, []string{"api.yaml", "common.yaml"}) {
		t.Errorf("RuleFiles = %v, want [api.yaml common.yaml]", files)
	}
}

func TestRuleFilesAccumulateAcrossScopes(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
defaults:
  waf:
    rules: { enabled: true, files: [ common.yaml ] }
domains:
  inherit.test:
  api.test:
    waf: { rules: { files: [ api.yaml ], disabled_ids: [ common-exception ] } }
    paths:
      "/private/":
        waf: { rules: { files: [ private.yaml ] } }
`)

	if got := cfg.DomainFor("inherit.test").WAF.Rules.Files; !slices.Equal(got, []string{"common.yaml"}) {
		t.Fatalf("inherited files = %v, want [common.yaml]", got)
	}
	api := cfg.DomainFor("api.test")
	if got := api.WAF.Rules.Files; !slices.Equal(got, []string{"common.yaml", "api.yaml"}) {
		t.Fatalf("domain files = %v, want common then api", got)
	}
	if got := api.ForPath("/private/item").WAF.Rules.Files; !slices.Equal(got, []string{"common.yaml", "api.yaml", "private.yaml"}) {
		t.Fatalf("path files = %v, want common then api then private", got)
	}
	if got := api.WAF.Rules.DisabledIDs; !slices.Equal(got, []string{"common-exception"}) {
		t.Fatalf("domain exclusions = %v, want combined-set exclusion", got)
	}
}

func TestPoWAnywhere(t *testing.T) {
	cfg := loadTestConfig(t, `
signing_key_file: test-signing.key
store: { backend: memory }
domains:
  off.test:
    pow: { enabled: false }
  pathonly.test:
    pow: { enabled: false }
    paths:
      "/app/":
        pow: { enabled: true }
`)
	if cfg.DomainFor("off.test").PoWAnywhere() {
		t.Error("off.test has pow disabled everywhere")
	}
	if !cfg.DomainFor("pathonly.test").PoWAnywhere() {
		t.Error("pathonly.test enables pow on /app/, PoWAnywhere must be true")
	}
	if pc := cfg.DomainFor("pathonly.test").ForPath("/app/x"); !pc.PoW.Enabled {
		t.Error("/app/ overlay must enable pow")
	}
}

// TestPathOverlayNullAndEmpty: a null overlay body equals the domain config;
// an empty paths map is a no-op.
func TestPathOverlayNullAndEmpty(t *testing.T) {
	cfg := loadTestConfig(t, `
signing_key_file: test-signing.key
store: { backend: memory }
domains:
  a.test:
    pow: { enabled: true }
    paths:
      "/api/":
  b.test:
    paths: {}
`)
	dom := cfg.DomainFor("a.test")
	pc := dom.ForPath("/api/x")
	if pc == dom {
		t.Error("null overlay still creates a distinct config")
	}
	if !pc.PoW.Enabled {
		t.Error("null overlay must equal the domain config")
	}
	if got := cfg.DomainFor("b.test").PathOverrideViews(); got != nil {
		t.Errorf("empty paths map must yield no overlays, got %v", got)
	}
}

// TestWarningsHoneypotNoPaths: a honeypot enabled with no paths is a no-op, so
// Warnings() flags it for every scope it appears in (defaults, domain, path
// overlay), and stays silent when paths are present or the honeypot is off.
func TestWarningsHoneypotNoPaths(t *testing.T) {
	cfg := loadTestConfig(t, `
listen: 127.0.0.1:9999
signing_key_file: test-signing.key
store:
  backend: memory
defaults:
  waf:
    honeypot: { enabled: true }        # no paths: inert, must warn
domains:
  good.test:
    waf:
      honeypot: { enabled: true, paths: [ "/trap/" ] }   # has paths: no warn
  bad.test:
    waf:
      honeypot: { enabled: true, paths: [] }             # inert: must warn
  off.test:
    waf:
      honeypot: { enabled: false }                       # disabled: no warn
`)
	ws := cfg.Warnings()

	joined := ""
	for _, w := range ws {
		joined += w + "\n"
	}
	// defaults inherit to good/off too, but those override honeypot, so only the
	// scopes with enabled+no-paths should appear: defaults, and bad.test.
	mustContain := []string{"defaults", "domain bad.test"}
	for _, want := range mustContain {
		found := false
		for _, w := range ws {
			if containsAll(w, "waf.honeypot", want) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a honeypot warning for %q, got:\n%s", want, joined)
		}
	}
	// good.test (has paths) and off.test (disabled) must NOT be warned about.
	for _, notWant := range []string{"good.test", "off.test"} {
		for _, w := range ws {
			if containsAll(w, "waf.honeypot", notWant) {
				t.Errorf("did not expect a honeypot warning for %q, got: %s", notWant, w)
			}
		}
	}
}

// Honeypot trap paths that could never match (empty/whitespace/relative) or
// that would match everything ("/") are copied-config mistakes and must be
// rejected at load, in every scope and even while the honeypot is disabled.
func TestHoneypotPathValidation(t *testing.T) {
	load := func(pathsYAML, scope string) error {
		var body string
		switch scope {
		case "defaults":
			body = "defaults:\n  waf:\n    honeypot: { enabled: true, paths: " + pathsYAML + " }\n"
		case "domain":
			body = "domains:\n  bad.test:\n    waf:\n      honeypot: { enabled: true, paths: " + pathsYAML + " }\n"
		case "overlay":
			body = "domains:\n  bad.test:\n    paths:\n      \"/x/\":\n        waf:\n          honeypot: { enabled: true, paths: " + pathsYAML + " }\n"
		case "disabled":
			body = "defaults:\n  waf:\n    honeypot: { enabled: false, paths: " + pathsYAML + " }\n"
		}
		p := filepath.Join(t.TempDir(), "guardian.yaml")
		if err := os.WriteFile(p, []byte("listen: 127.0.0.1:9999\nsigning_key_file: test-signing.key\nstore:\n  backend: memory\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(p)
		return err
	}
	for _, tc := range []struct {
		paths, wantErr string
	}{
		{`[ "" ]`, "empty or whitespace-only"},
		{`[ "   " ]`, "empty or whitespace-only"},
		{`[ "backup/" ]`, "not absolute"},
		{`[ "/ok/", "backup/" ]`, "not absolute"}, // one bad entry poisons the list
		{`[ "/" ]`, "match every request"},
	} {
		for _, scope := range []string{"defaults", "domain", "overlay", "disabled"} {
			err := load(tc.paths, scope)
			if err == nil {
				t.Errorf("paths %s in %s: want load error containing %q, got nil", tc.paths, scope, tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("paths %s in %s: error %q does not contain %q", tc.paths, scope, err, tc.wantErr)
			}
		}
	}
	// Sane absolute traps still load, prefix and exact alike.
	if err := load(`[ "/old-admin/", "/trap.txt" ]`, "domain"); err != nil {
		t.Fatalf("valid trap paths rejected: %v", err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// TestSilentlyInertConfigIsRejected covers the class of mistake that is worst
// in a security product: a configuration that loads clean, reads as protective
// in every admin view, and protects nothing. Each case here was accepted before
// and its effect was only observable in production traffic.
func TestSilentlyInertConfigIsRejected(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			"allowlist path / turns the whole product off",
			"defaults:\n  allowlist:\n    paths: [ \"/\" ]\n",
			"prefix-matches every URL",
		},
		{
			"denylist path / denies the whole site",
			"defaults:\n  denylist:\n    paths: [ \"/\" ]\n",
			"prefix-matches every URL",
		},
		{
			"an empty allowlist path entry matches nothing",
			"defaults:\n  allowlist:\n    paths: [ \"  \" ]\n",
			"empty or whitespace-only entry",
		},
		{
			"a relative denylist path entry can never match",
			"defaults:\n  denylist:\n    paths: [ \"admin\" ]\n",
			"is not absolute",
		},
		{
			"an allowlist path with a doubled slash half-matches at best",
			"defaults:\n  allowlist:\n    paths: [ \"/admin//\" ]\n",
			"not in normalized form",
		},
		{
			"a denylist path with dot segments can never match",
			"defaults:\n  denylist:\n    paths: [ \"/a/../admin\" ]\n",
			"not in normalized form",
		},
		{
			"a percent-encoded allowlist path can never match the decoded request",
			"defaults:\n  allowlist:\n    paths: [ \"/%61dmin\" ]\n",
			"not in normalized form",
		},
		{
			"an allowlist path carrying a query can never match",
			"defaults:\n  allowlist:\n    paths: [ \"/admin?debug=1\" ]\n",
			"must not contain ? or #",
		},
		{
			"a denylist path carrying a fragment can never match",
			"defaults:\n  denylist:\n    paths: [ \"/admin#section\" ]\n",
			"must not contain ? or #",
		},
		{
			"a honeypot trap carrying a query can never fire",
			"defaults:\n  waf:\n    honeypot: { enabled: true, paths: [ \"/trap?x=1\" ] }\n",
			"must not contain ? or #",
		},
		{
			"a honeypot trap that can never fire",
			"defaults:\n  waf:\n    honeypot: { enabled: true, paths: [ \"/a/../trap\" ] }\n",
			"not in normalized form",
		},
		{
			"a paths overlay key with a doubled slash is dead",
			"defaults:\n  paths:\n    \"/api//v1/\": { pow: { enabled: false } }\n",
			"must be written in normalized form",
		},
		{
			"a paths overlay key with a dot segment is dead",
			"defaults:\n  paths:\n    \"/a/./b\": { pow: { enabled: false } }\n",
			"must be written in normalized form",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfigErr(t, "store: { backend: memory }\n"+tc.yaml)
			if err == nil {
				t.Fatalf("config loaded clean, but it protects nothing:\n%s", tc.yaml)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The normalized-key rule must not reject the forms operators actually write,
// including the shipped defaults.
func TestNormalizedPathKeysAreAccepted(t *testing.T) {
	for _, key := range []string{"/robots.txt", "/favicon.ico", "/favicon.svg", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/manifest.json", "/manifest.webmanifest", "/site.webmanifest", "/sitemap.xml", "/api/v1/", "/a", "/"} {
		yaml := "store: { backend: memory }\ndefaults:\n  paths:\n    \"" + key + "\": { pow: { enabled: false } }\n"
		if _, err := loadConfigErr(t, yaml); err != nil {
			t.Errorf("paths key %q was rejected: %v", key, err)
		}
	}
}

// TestInertPoWIsWarnedAbout: suspicion hands every challenge decision to the
// anomaly stage and observe_only stops that stage deciding, so together they
// leave nothing able to challenge while PoW still reads as enabled.
func TestInertPoWIsWarnedAbout(t *testing.T) {
	yaml := `store: { backend: memory }
signing_key_file: k.key
defaults:
  pow: { enabled: true, mode: suspicion }
  waf:
    anomaly: { enabled: true, model: m.json, challenge_at: 0.5, deny_at: 0.85, observe_only: true }
`
	cfg, err := loadConfigErr(t, yaml)
	if err != nil {
		t.Fatalf("this is a legitimate rollout waypoint and must still load: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "inert") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning that proof of work cannot fire; got %v", cfg.Warnings())
	}

	// The control: the same config without observe_only can challenge, so it
	// must not warn.
	ok := strings.Replace(yaml, ", observe_only: true", "", 1)
	cfg2, err := loadConfigErr(t, ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range cfg2.Warnings() {
		if strings.Contains(w, "inert") {
			t.Errorf("warned about a config that can challenge: %q", w)
		}
	}
}
