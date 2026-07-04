// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package core contains the transport-agnostic decision engine of Guardian.
// All business logic lives here so the same core can be driven by the HTTP
// auth_request sidecar today and by a cgo or WASM embedding later.
package core

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration parses YAML scalars like "15m" or "4h" into a time.Duration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func (d Duration) Std() time.Duration { return time.Duration(d) }

// Rate parses YAML scalars like "20/min", "5/s" or "100/h" into a count per window.
type Rate struct {
	Count int
	Per   time.Duration
}

func (r *Rate) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("rate must be a string like \"20/min\": %w", err)
	}
	count, unit, ok := strings.Cut(s, "/")
	if !ok {
		return fmt.Errorf("invalid rate %q: expected <count>/<unit>", s)
	}
	n, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil || n <= 0 {
		return fmt.Errorf("invalid rate %q: count must be a positive integer", s)
	}
	var per time.Duration
	switch strings.TrimSpace(unit) {
	case "s", "sec", "second":
		per = time.Second
	case "m", "min", "minute":
		per = time.Minute
	case "h", "hour":
		per = time.Hour
	default:
		return fmt.Errorf("invalid rate %q: unit must be s, min or h", s)
	}
	*r = Rate{Count: n, Per: per}
	return nil
}

func (r Rate) MarshalYAML() (any, error) {
	unit := map[time.Duration]string{time.Second: "s", time.Minute: "min", time.Hour: "h"}[r.Per]
	return fmt.Sprintf("%d/%s", r.Count, unit), nil
}

// Config is the top-level guardian.yaml.
type Config struct {
	Listen         string               `yaml:"listen"`
	LogLevel       string               `yaml:"log_level"`
	SigningKeyFile string               `yaml:"signing_key_file"`
	Store          StoreConfig          `yaml:"store"`
	Defaults       DomainConfig         `yaml:"defaults"`
	Domains        map[string]yaml.Node `yaml:"domains"`

	resolved map[string]*DomainConfig
}

type StoreConfig struct {
	Backend string `yaml:"backend"` // memory | bbolt (redis planned)
	Path    string `yaml:"path"`    // bbolt database file
}

// DomainConfig is the per-domain feature configuration. Domain entries are
// merged over Defaults field-by-field at load time.
type DomainConfig struct {
	WAF       WAFConfig  `yaml:"waf"`
	PoW       PoWConfig  `yaml:"pow"`
	Allowlist ListConfig `yaml:"allowlist"`
	Denylist  ListConfig `yaml:"denylist"`
}

type WAFConfig struct {
	IPBehaviour IPBehaviourConfig `yaml:"ip_behaviour"`
	Keywords    KeywordsConfig    `yaml:"keywords"`    // enforced from P2
	Anomaly     AnomalyConfig     `yaml:"anomaly"`     // enforced from P3
	Honeypot    ToggleConfig      `yaml:"honeypot"`    // enforced from P2
	UUIDTamper  ToggleConfig      `yaml:"uuid_tamper"` // enforced from P2
}

type IPBehaviourConfig struct {
	Enabled    bool            `yaml:"enabled"`
	BlockTTL   Duration        `yaml:"block_ttl"`
	Thresholds map[string]Rate `yaml:"thresholds"`
}

type KeywordsConfig struct {
	Enabled   bool   `yaml:"enabled"`
	RulesFile string `yaml:"rules_file"`
}

type AnomalyConfig struct {
	Enabled     bool    `yaml:"enabled"`
	Model       string  `yaml:"model"`
	ChallengeAt float64 `yaml:"challenge_at"`
	DenyAt      float64 `yaml:"deny_at"`
}

type ToggleConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PoWConfig struct {
	Enabled          bool     `yaml:"enabled"`
	BaseDifficulty   int      `yaml:"base_difficulty"`
	MaxDifficulty    int      `yaml:"max_difficulty"`
	TokenTTL         Duration `yaml:"token_ttl"`
	ChallengeTTL     Duration `yaml:"challenge_ttl"`
	NoScriptFallback bool     `yaml:"noscript_fallback"`
}

// ListConfig is a static allow- or denylist. Matching rules:
//   - ips: CIDRs or bare IPv4/IPv6 addresses
//   - uas: case-insensitive substring match on User-Agent
//   - paths: exact match, or prefix match when the entry ends with "/"
type ListConfig struct {
	IPs   []string `yaml:"ips"`
	UAs   []string `yaml:"uas"`
	Paths []string `yaml:"paths"`

	prefixes []netip.Prefix
	uasLower []string
}

func (l *ListConfig) compile() error {
	l.prefixes = l.prefixes[:0]
	for _, s := range l.IPs {
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", s, err)
			}
			l.prefixes = append(l.prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("invalid IP %q: %w", s, err)
		}
		l.prefixes = append(l.prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	l.uasLower = l.uasLower[:0]
	for _, ua := range l.UAs {
		l.uasLower = append(l.uasLower, strings.ToLower(ua))
	}
	return nil
}

func (l *ListConfig) MatchIP(addr netip.Addr) bool {
	for _, p := range l.prefixes {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func (l *ListConfig) MatchUA(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	for _, needle := range l.uasLower {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (l *ListConfig) MatchPath(path string) bool {
	for _, entry := range l.Paths {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(path, entry) || path == strings.TrimSuffix(entry, "/") {
				return true
			}
		} else if path == entry {
			return true
		}
	}
	return false
}

// LoadConfig reads, validates and resolves guardian.yaml. Per-domain configs
// are precomputed here so the request hot path is a single map lookup.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.finalize(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) finalize() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8071"
	}
	switch c.LogLevel {
	case "":
		c.LogLevel = "info"
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn or error, got %q", c.LogLevel)
	}
	switch c.Store.Backend {
	case "":
		c.Store.Backend = "memory"
	case "memory":
	case "bbolt":
		if c.Store.Path == "" {
			return fmt.Errorf("store.path is required for the bbolt backend")
		}
	default:
		return fmt.Errorf("store.backend must be memory or bbolt, got %q", c.Store.Backend)
	}

	// Defaults for the defaults.
	if c.Defaults.PoW.BaseDifficulty == 0 {
		c.Defaults.PoW.BaseDifficulty = 4
	}
	if c.Defaults.PoW.MaxDifficulty == 0 {
		c.Defaults.PoW.MaxDifficulty = 6
	}
	if c.Defaults.PoW.TokenTTL == 0 {
		c.Defaults.PoW.TokenTTL = Duration(4 * time.Hour)
	}
	if c.Defaults.PoW.ChallengeTTL == 0 {
		c.Defaults.PoW.ChallengeTTL = Duration(30 * time.Minute)
	}
	if c.Defaults.WAF.IPBehaviour.BlockTTL == 0 {
		c.Defaults.WAF.IPBehaviour.BlockTTL = Duration(15 * time.Minute)
	}

	// Domain configs = defaults deep-copied, then the domain's own YAML node
	// decoded on top so only the fields it mentions are overridden.
	defaultsRaw, err := yaml.Marshal(&c.Defaults)
	if err != nil {
		return fmt.Errorf("marshal defaults: %w", err)
	}
	c.resolved = make(map[string]*DomainConfig, len(c.Domains))
	for host, node := range c.Domains {
		dc := &DomainConfig{}
		if err := yaml.Unmarshal(defaultsRaw, dc); err != nil {
			return fmt.Errorf("copy defaults for %s: %w", host, err)
		}
		if node.Kind != 0 && node.Tag != "!!null" {
			if err := node.Decode(dc); err != nil {
				return fmt.Errorf("domain %s: %w", host, err)
			}
		}
		if err := dc.validate(); err != nil {
			return fmt.Errorf("domain %s: %w", host, err)
		}
		c.resolved[normalizeHost(host)] = dc
	}
	if err := c.Defaults.validate(); err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	return nil
}

func (dc *DomainConfig) validate() error {
	p := &dc.PoW
	if p.BaseDifficulty < 1 || p.BaseDifficulty > 8 {
		return fmt.Errorf("pow.base_difficulty must be 1..8, got %d", p.BaseDifficulty)
	}
	if p.MaxDifficulty < p.BaseDifficulty || p.MaxDifficulty > 8 {
		return fmt.Errorf("pow.max_difficulty must be %d..8, got %d", p.BaseDifficulty, p.MaxDifficulty)
	}
	a := &dc.WAF.Anomaly
	if a.Enabled && (a.ChallengeAt <= 0 || a.DenyAt <= a.ChallengeAt || a.DenyAt > 1) {
		return fmt.Errorf("waf.anomaly: need 0 < challenge_at < deny_at <= 1, got %v / %v", a.ChallengeAt, a.DenyAt)
	}
	if err := dc.Allowlist.compile(); err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	if err := dc.Denylist.compile(); err != nil {
		return fmt.Errorf("denylist: %w", err)
	}
	return nil
}

// DomainFor returns the resolved config for a host, falling back to Defaults
// for unknown hosts. The host may carry a port suffix and any case.
func (c *Config) DomainFor(host string) *DomainConfig {
	if dc, ok := c.resolved[normalizeHost(host)]; ok {
		return dc
	}
	return &c.Defaults
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(host, ".")
}
