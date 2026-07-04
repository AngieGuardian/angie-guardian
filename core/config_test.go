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
		t.Errorf("example.com base_difficulty = %d, want override 5", ex.PoW.BaseDifficulty)
	}
	if ex.PoW.TokenTTL.Std() != 2*time.Hour {
		t.Errorf("example.com token_ttl = %v, want override 2h", ex.PoW.TokenTTL.Std())
	}
	if ex.PoW.MaxDifficulty != 6 {
		t.Errorf("example.com max_difficulty = %d, want inherited 6", ex.PoW.MaxDifficulty)
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
		t.Errorf("api.example.com base_difficulty = %d, want inherited 4", api.PoW.BaseDifficulty)
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

func TestConfigValidation(t *testing.T) {
	for name, yaml := range map[string]string{
		"bad backend":     "store: { backend: etcd }",
		"bbolt sans path": "store: { backend: bbolt }",
		"bad difficulty":  "defaults: { pow: { base_difficulty: 9 } }",
		"max below base":  "defaults: { pow: { base_difficulty: 5, max_difficulty: 4 } }",
		"bad cidr":        "defaults: { allowlist: { ips: [ \"10.0.0.0/99\" ] } }",
		"bad rate":        "defaults: { waf: { ip_behaviour: { thresholds: { x: 20/fortnight } } } }",
		"unknown field":   "listne: 1.2.3.4:80",
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
