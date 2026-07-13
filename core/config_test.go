// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testYAML = `
listen: 127.0.0.1:9999
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

	g := vb.match("Mozilla/5.0 (compatible; googlebot/2.1; +http://www.google.com/bot.html)")
	if g == nil || g.Name != "googlebot" {
		t.Fatalf("preset UA needle should match, got %v", g)
	}
	// googlebot.com ONLY: google.com belongs to the special-case crawler and
	// user-triggered fetcher categories, which must not vouch for Googlebot.
	if len(g.domainsLower) != 1 || g.domainsLower[0] != "googlebot.com" {
		t.Errorf("preset domains = %v, want [googlebot.com]", g.domainsLower)
	}

	s := vb.match("AdsBot-Google-Mobile (+http://www.google.com/mobile/adsbot.html)")
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

	if vb.match("Mozilla/5.0 Firefox/140.0") != nil {
		t.Error("plain browser UA must not match any bot")
	}

	if _, ok := cfg.Defaults.WAF.IPBehaviour.Thresholds["bot_spoof"]; !ok {
		t.Error("default thresholds should include bot_spoof")
	}
}

func TestConfigValidation(t *testing.T) {
	for name, yaml := range map[string]string{
		"bad backend":                            "store: { backend: etcd }",
		"bbolt sans path":                        "store: { backend: bbolt }",
		"bad difficulty":                         "defaults: { pow: { base_difficulty: 9 } }",
		"max below base":                         "defaults: { pow: { base_difficulty: 5, max_difficulty: 4 } }",
		"difficulty below one":                   "defaults: { pow: { base_difficulty: 0.5 } }",
		"negative challenge_ttl":                  "domains: { a.test: { pow: { enabled: true, challenge_ttl: -1s } } }",
		"zero token_ttl when enabled":             "domains: { a.test: { pow: { enabled: true, token_ttl: 0s } } }",
		"negative default token_ttl":              "defaults: { pow: { token_ttl: -5m } }",
		"pow ttl above cap":                       "domains: { a.test: { pow: { enabled: true, challenge_ttl: 192h } } }",
		"difficulty off the quarter grid":        "defaults: { pow: { base_difficulty: 4.3 } }",
		"max off the quarter grid":               "defaults: { pow: { base_difficulty: 4, max_difficulty: 6.1 } }",
		"bad cidr":                               "defaults: { allowlist: { ips: [ \"10.0.0.0/99\" ] } }",
		"bad rate":                               "defaults: { waf: { ip_behaviour: { thresholds: { x: 20/fortnight } } } }",
		"unknown field":                          "listne: 1.2.3.4:80",
		"unknown field in domain overlay":        "domains: { a.test: { waf: { keywrods: { enabled: true } } } }",
		"unknown nested field in domain overlay":  "domains: { a.test: { pow: { enabeld: true } } }",
		"duplicate host":                         "domains: { a.test: , \"A.test:443\": }",
		"non-loopback listen sans trusted_proxy": "listen: 0.0.0.0:8071",
		"max_block_ttl below block_ttl":          "defaults: { waf: { ip_behaviour: { block_ttl: 1h, max_block_ttl: 15m } } }",
		"negative max_block_ttl":                 "defaults: { waf: { ip_behaviour: { max_block_ttl: -5m } } }",
		"bot without name":                       "defaults: { verified_bots: { bots: [ { uas: [X], domains: [x.test] } ] } }",
		"unknown bot preset":                     "defaults: { verified_bots: { bots: [ { name: mybot } ] } }",
		"bot empty domain":                       "defaults: { verified_bots: { bots: [ { name: mybot, uas: [MyBot], domains: [\"\"] } ] } }",
		"bad spoof_action":                       "defaults: { verified_bots: { spoof_action: block } }",
		"negative dns_timeout":                   "defaults: { verified_bots: { dns_timeout: -1s } }",
		"bot also in ua allowlist":               "defaults: { allowlist: { uas: [ Googlebot ] }, verified_bots: { bots: [ { name: googlebot } ] } }",
		"bot overlaps ua allowlist per-domain":   "domains: { a.test: { allowlist: { uas: [ googlebot ] }, verified_bots: { bots: [ { name: googlebot } ] } } }",
		"bad country code":                       "geoip: { country_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { countries: [ Netherlands ] } } }",
		"country in two selectors":               "geoip: { country_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { countries: [ NL ] }, challenge: { countries: [ nl ] } } }",
		"asn in two selectors":                   "geoip: { asn_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { asns: [ 64500 ] }, allow: { asns: [ 64500 ] } } }",
		"geo enabled but inert":                  "geoip: { country_db: /x.mmdb }\ndefaults: { geo: { enabled: true } }",
		"geo without databases":                  "defaults: { geo: { enabled: true, deny: { countries: [ NL ] } } }",
		"country rules sans country_db":          "geoip: { asn_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { countries: [ NL ] } } }",
		"asn rules sans asn_db":                  "geoip: { country_db: /x.mmdb }\ndefaults: { geo: { enabled: true, deny: { asns: [ 64500 ] } } }",
		"bad geo default_action":                 "geoip: { country_db: /x.mmdb }\ndefaults: { geo: { enabled: true, default_action: block, deny: { countries: [ NL ] } } }",
		"geo on domain without databases":        "domains: { a.test: { geo: { enabled: true, deny: { countries: [ NL ] } } } }",
		"feed sans source":                       "reputation: { feeds: [ { name: x } ] }",
		"feed with two sources":                  "reputation: { feeds: [ { name: x, url: \"https://a/b\", file: /a/b } ] }",
		"feed bad name":                          "reputation: { feeds: [ { name: \"sp aces\", file: /a/b } ] }",
		"feed dup name":                          "reputation: { feeds: [ { name: x, file: /a }, { name: x, file: /b } ] }",
		"feed bad action":                        "reputation: { feeds: [ { name: x, file: /a/b, action: block } ] }",
		"feed bad url scheme":                    "reputation: { feeds: [ { name: x, url: \"ftp://a/b\" } ] }",
		"feed refresh too low":                   "reputation: { feeds: [ { name: x, url: \"https://a/b\", refresh: 10s } ] }",
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

const geoYAML = `
geoip:
  country_db: /var/lib/test/country.mmdb
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
	if ic.CountryDB == "" || ic.ASNDB == "" || ic.CacheDir == "" {
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
