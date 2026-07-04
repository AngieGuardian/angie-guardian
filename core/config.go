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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core/stateless"
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
	Listen         string `yaml:"listen"`
	LogLevel       string `yaml:"log_level"`
	SigningKeyFile string `yaml:"signing_key_file"`
	PreviousKeyDir string `yaml:"previous_key_dir"` // retired signing keys, still verified
	// TrustedProxy must be set true to bind the auth hot path to a non-loopback
	// address. The sidecar trusts the X-Guardian-* headers (client IP, host,
	// cookie) that Angie sets on the subrequest; if the listener is reachable
	// by clients directly, anyone could forge those headers (spoof another
	// client's IP, frame it into a block, or ride an allowlisted identity).
	// Only enable this when the listener is isolated to Angie (private network,
	// firewall, or mTLS) so no untrusted client can reach it.
	TrustedProxy bool                 `yaml:"trusted_proxy"`
	Admin        AdminConfig          `yaml:"admin"`
	Store        StoreConfig          `yaml:"store"`
	Defaults     DomainConfig         `yaml:"defaults"`
	Domains      map[string]yaml.Node `yaml:"domains"`

	resolved map[string]*DomainConfig
}

// AdminConfig configures the admin + metrics listener. It is separate from
// the auth listener so it can bind to loopback / a management interface.
type AdminConfig struct {
	Listen string `yaml:"listen"` // empty disables the admin+metrics server
	Token  string `yaml:"token"`  // bearer token; or ADMIN_TOKEN env var
}

type StoreConfig struct {
	Backend  string `yaml:"backend"`  // memory | bbolt | redis
	Path     string `yaml:"path"`     // bbolt database file
	Addr     string `yaml:"addr"`     // redis host:port
	Password string `yaml:"password"` // redis password (or use REDIS_PASSWORD)
	DB       int    `yaml:"db"`       // redis database number
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
	Keywords    KeywordsConfig    `yaml:"keywords"`
	Anomaly     AnomalyConfig     `yaml:"anomaly"` // enforced from P3
	Honeypot    HoneypotConfig    `yaml:"honeypot"`
	UUIDTamper  ToggleConfig      `yaml:"uuid_tamper"`
}

// IPBehaviourConfig drives the behavioural scoreboard: how many bad events
// of a given type (threshold key) an IP may produce per window before it is
// temporarily blocked, with exponential backoff up to max_block_ttl.
type IPBehaviourConfig struct {
	Enabled     bool            `yaml:"enabled"`
	BlockTTL    Duration        `yaml:"block_ttl"`
	MaxBlockTTL Duration        `yaml:"max_block_ttl"`
	Thresholds  map[string]Rate `yaml:"thresholds"`
}

// HoneypotConfig configures trap paths: URLs no legitimate client ever
// requests (hidden links, robots.txt-disallowed paths). One hit blocks.
// Aliased from the leaf package so the sidecar and WASM guest share the type.
type HoneypotConfig = stateless.HoneypotConfig

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
	Enabled bool `yaml:"enabled"`
	// Mode "always" challenges every unvouched browser; "suspicion" only
	// challenges clients the anomaly scorer flags (requires waf.anomaly).
	Mode             string   `yaml:"mode"`
	BaseDifficulty   int      `yaml:"base_difficulty"`
	MaxDifficulty    int      `yaml:"max_difficulty"`
	TokenTTL         Duration `yaml:"token_ttl"`
	ChallengeTTL     Duration `yaml:"challenge_ttl"`
	NoScriptFallback bool     `yaml:"noscript_fallback"`
}

// ListConfig is a static allow- or denylist (aliased from the leaf package so
// the sidecar and WASM guest share one implementation). Matching rules:
//   - IPs: CIDRs or bare IPv4/IPv6 addresses
//   - UAs: case-insensitive substring match on User-Agent
//   - Paths: exact match, or prefix match when the entry ends with "/"
type ListConfig = stateless.ListConfig

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
	if !c.TrustedProxy && !listenIsLoopback(c.Listen) {
		return fmt.Errorf("listen %s is not loopback: the auth hot path trusts client-identity headers from its caller, so a non-loopback bind lets clients spoof them. Isolate the listener to Angie and set trusted_proxy: true to allow this", c.Listen)
	}
	switch c.LogLevel {
	case "":
		c.LogLevel = "info"
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn or error, got %q", c.LogLevel)
	}
	if c.Admin.Token == "" {
		c.Admin.Token = os.Getenv("ADMIN_TOKEN")
	}
	switch c.Store.Backend {
	case "":
		c.Store.Backend = "memory"
	case "memory":
	case "bbolt":
		if c.Store.Path == "" {
			return fmt.Errorf("store.path is required for the bbolt backend")
		}
	case "redis":
		if c.Store.Addr == "" {
			return fmt.Errorf("store.addr is required for the redis backend")
		}
	default:
		return fmt.Errorf("store.backend must be memory, bbolt or redis, got %q", c.Store.Backend)
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
	if c.Defaults.WAF.IPBehaviour.MaxBlockTTL == 0 {
		c.Defaults.WAF.IPBehaviour.MaxBlockTTL = Duration(4 * time.Hour)
	}
	if c.Defaults.WAF.IPBehaviour.Thresholds == nil {
		c.Defaults.WAF.IPBehaviour.Thresholds = map[string]Rate{
			"signature": {Count: 10, Per: time.Minute},
			"pow_fail":  {Count: 10, Per: time.Minute},
			"tamper":    {Count: 10, Per: time.Minute},
		}
	}

	// Domain configs = defaults deep-copied, then the domain's own YAML node
	// decoded on top so only the fields it mentions are overridden.
	defaultsRaw, err := yaml.Marshal(&c.Defaults)
	if err != nil {
		return fmt.Errorf("marshal defaults: %w", err)
	}
	c.resolved = make(map[string]*DomainConfig, len(c.Domains))
	seen := make(map[string]string, len(c.Domains))
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
		key, err := stateless.NormalizeHostKey(seen, host)
		if err != nil {
			return err
		}
		c.resolved[key] = dc
	}
	if err := c.Defaults.validate(); err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	return nil
}

func (dc *DomainConfig) validate() error {
	p := &dc.PoW
	switch p.Mode {
	case "":
		p.Mode = "always"
	case "always":
	case "suspicion":
		if p.Enabled && !dc.WAF.Anomaly.Enabled {
			return fmt.Errorf("pow.mode suspicion requires waf.anomaly to be enabled")
		}
	default:
		return fmt.Errorf("pow.mode must be always or suspicion, got %q", p.Mode)
	}
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
	b := &dc.WAF.IPBehaviour
	if b.BlockTTL < 0 || b.MaxBlockTTL < 0 {
		return fmt.Errorf("waf.ip_behaviour: block_ttl and max_block_ttl must be >= 0, got %v / %v", b.BlockTTL.Std(), b.MaxBlockTTL.Std())
	}
	if b.MaxBlockTTL > 0 && b.BlockTTL > 0 && b.MaxBlockTTL < b.BlockTTL {
		return fmt.Errorf("waf.ip_behaviour: max_block_ttl (%v) must be >= block_ttl (%v)", b.MaxBlockTTL.Std(), b.BlockTTL.Std())
	}
	if err := dc.Allowlist.Compile(); err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	if err := dc.Denylist.Compile(); err != nil {
		return fmt.Errorf("denylist: %w", err)
	}
	return nil
}

// RuleFiles returns every distinct WAF rules file referenced by an enabled
// keywords config, for the rule cache to load and watch.
func (c *Config) RuleFiles() []string {
	seen := make(map[string]bool)
	add := func(dc *DomainConfig) {
		if dc.WAF.Keywords.Enabled && dc.WAF.Keywords.RulesFile != "" {
			seen[dc.WAF.Keywords.RulesFile] = true
		}
	}
	add(&c.Defaults)
	for _, dc := range c.resolved {
		add(dc)
	}
	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	return files
}

// ModelFiles returns every distinct anomaly model artifact referenced by an
// enabled anomaly config, for the model cache to load and watch.
func (c *Config) ModelFiles() []string {
	seen := make(map[string]bool)
	add := func(dc *DomainConfig) {
		if dc.WAF.Anomaly.Enabled && dc.WAF.Anomaly.Model != "" {
			seen[dc.WAF.Anomaly.Model] = true
		}
	}
	add(&c.Defaults)
	for _, dc := range c.resolved {
		add(dc)
	}
	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	return files
}

// DomainViews returns the resolved per-domain configs keyed by host, for
// admin inspection. The map is the engine's own; callers must not mutate it.
func (c *Config) DomainViews() map[string]*DomainConfig {
	return c.resolved
}

// DomainFor returns the resolved config for a host, falling back to Defaults
// for unknown hosts. The host may carry a port suffix and any case.
func (c *Config) DomainFor(host string) *DomainConfig {
	if dc, ok := c.resolved[normalizeHost(host)]; ok {
		return dc
	}
	return &c.Defaults
}

// DomainLabel maps a request host to a bounded metric label: the normalized
// key of a configured domain, or "default" for anything else. The raw Host
// header is client-controlled and unbounded, so it must never be a label value
// directly — a flood of distinct Host headers would otherwise explode the
// Prometheus series count and OOM both this process and the scrape target.
func (c *Config) DomainLabel(host string) string {
	key := normalizeHost(host)
	if _, ok := c.resolved[key]; ok {
		return key
	}
	return "default"
}

func normalizeHost(host string) string { return stateless.NormalizeHost(host) }

// listenIsLoopback reports whether a listen address binds only the loopback
// interface. A wildcard bind ("0.0.0.0", "::", or an empty host) is NOT
// loopback: it accepts connections from anywhere, so it is treated as remote.
func listenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
