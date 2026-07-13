// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package core contains the transport-agnostic decision engine of Guardian.
// All business logic lives here so the same core can be driven by the HTTP
// auth_request sidecar today and by a cgo or WASM embedding later.
package core

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core/intel"
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
	GeoIP        GeoIPConfig          `yaml:"geoip"`
	Reputation   ReputationFeeds      `yaml:"reputation"`
	Defaults     DomainConfig         `yaml:"defaults"`
	Domains      map[string]yaml.Node `yaml:"domains"`

	resolved map[string]*DomainConfig
}

// AdminConfig configures the admin + metrics listener. It is separate from
// the auth listener so it can bind to loopback / a management interface.
type AdminConfig struct {
	Listen string `yaml:"listen"` // empty disables the admin+metrics server
	Token  string `yaml:"token"`  // bearer token; or ADMIN_TOKEN env var

	// TokenFile persists an auto-generated bearer token (like the PoW signing
	// key: created 0600 on first start, never regenerated). Used when Token
	// and ADMIN_TOKEN are unset, so the operator never invents a token by
	// hand. With neither token nor token_file, a loopback admin listener gets
	// a fresh ephemeral token per start (printed in the startup log).
	TokenFile string `yaml:"token_file"`

	// Dashboard serves the built-in reporting page at GET /admin/dashboard.
	// The page itself is a static shell (all data flows through the
	// token-guarded /admin/* endpoints), but it stays off by default so the
	// admin surface exposes nothing extra unless asked to.
	Dashboard bool `yaml:"dashboard"`
}

type StoreConfig struct {
	Backend  string `yaml:"backend"`  // memory | bbolt | redis
	Path     string `yaml:"path"`     // bbolt database file
	Addr     string `yaml:"addr"`     // redis host:port
	Password string `yaml:"password"` // redis password (or use REDIS_PASSWORD)
	DB       int    `yaml:"db"`       // redis database number
}

// GeoIPConfig points at MaxMind-format (.mmdb) databases: MaxMind
// GeoLite2/GeoIP2, DB-IP or any other publisher of the format. The files are
// hot-reloaded when replaced on disk (geoipupdate does this atomically), so
// scheduled updates need no restart. Either may be omitted; geo rules that
// would need the missing database are refused at config load.
type GeoIPConfig struct {
	CountryDB string `yaml:"country_db"`
	ASNDB     string `yaml:"asn_db"`
}

// ReputationFeeds is the global list of external IP reputation feeds. Feeds
// are defined once here; each domain opts in via reputation.enabled.
type ReputationFeeds struct {
	// CacheDir persists the last good copy of every URL feed, so a restart
	// enforces yesterday's list immediately instead of nothing until the
	// first fetch completes. Strongly recommended when URL feeds are used.
	CacheDir string       `yaml:"cache_dir"`
	Feeds    []FeedConfig `yaml:"feeds"`
}

// FeedConfig is one reputation feed: a plain-text list of IPs/CIDRs (one per
// line, '#'/';' comments), like the FireHOL netsets or a hand-maintained
// local file. Exactly one of url/file must be set.
type FeedConfig struct {
	Name    string   `yaml:"name"`    // label in reasons/metrics and the cache file name
	URL     string   `yaml:"url"`     // fetched in the background every refresh interval
	File    string   `yaml:"file"`    // local list, hot-reloaded like the WAF rules files
	Refresh Duration `yaml:"refresh"` // URL feeds only; default 12h, minimum 1m
	Action  string   `yaml:"action"`  // deny (default) | challenge
}

// DomainConfig is the per-domain feature configuration. Domain entries are
// merged over Defaults field-by-field at load time.
type DomainConfig struct {
	WAF          WAFConfig          `yaml:"waf"`
	PoW          PoWConfig          `yaml:"pow"`
	Geo          GeoConfig          `yaml:"geo"`
	Reputation   ReputationConfig   `yaml:"reputation"`
	Allowlist    ListConfig         `yaml:"allowlist"`
	Denylist     ListConfig         `yaml:"denylist"`
	VerifiedBots VerifiedBotsConfig `yaml:"verified_bots"`
}

// VerifiedBotsConfig allowlists well-known crawlers by verified identity
// instead of by their (freely forgeable) User-Agent string: a client whose
// UA claims a listed bot is admitted only if its IP reverse-DNS + forward-
// confirms to one of the bot's published domains (core/botverify). A client
// that claims the UA but definitively fails verification is an impostor and
// is handled per SpoofAction.
type VerifiedBotsConfig struct {
	Bots []BotConfig `yaml:"bots"`
	// DNSTimeout is the total DNS budget for one first-sight verification;
	// results are cached, so this cost is paid once per IP per CacheTTL.
	DNSTimeout  Duration `yaml:"dns_timeout"`
	CacheTTL    Duration `yaml:"cache_ttl"`
	NegativeTTL Duration `yaml:"negative_ttl"`
	// SpoofAction is what happens to a proven impostor: "deny" (default)
	// rejects and scores a bot_spoof event; "continue" just withholds the
	// allowlist skip and lets the rest of the pipeline handle the request.
	SpoofAction string `yaml:"spoof_action"`
}

// BotConfig is one verifiable crawler: UA needles that claim it, and the
// domains its reverse DNS must confirm to. For well-known names (see
// botPresets) both lists may be omitted.
type BotConfig struct {
	Name    string   `yaml:"name"`
	UAs     []string `yaml:"uas"`
	Domains []string `yaml:"domains"`

	uasLower     []string
	domainsLower []string
}

// botPresets carries the published UA substrings and rDNS domains of
// well-known crawlers, so a config entry can be just "name: googlebot".
//
// Google splits its traffic into three rDNS categories, and the presets keep
// them apart on purpose:
//   - common crawlers (Googlebot UAs): PTR under googlebot.com ONLY. The
//     preset must not also accept google.com, because that domain belongs to
//     the other two categories and would let e.g. a user-triggered fetch
//     carrying a Googlebot UA ride the allowlist.
//   - special-case crawlers (AdsBot, Mediapartners, APIs-Google): PTR under
//     google.com — the separate "google-special" preset.
//   - user-triggered fetchers (Feedfetcher, Read-Aloud, Apps Script...):
//     deliberately NOT a preset. Third parties can aim those at any site on
//     demand, so allowlisting them is an operator decision; write a custom
//     bot entry if you truly want it.
//
// (DuckDuckBot is absent on purpose too: DuckDuckGo publishes an IP list,
// not rDNS domains — use allowlist.ips for it.)
var botPresets = map[string]struct{ uas, domains []string }{
	"googlebot":      {[]string{"Googlebot"}, []string{"googlebot.com"}},
	"google-special": {[]string{"AdsBot-Google", "Mediapartners-Google", "APIs-Google"}, []string{"google.com"}},
	"bingbot":        {[]string{"bingbot"}, []string{"search.msn.com"}},
	"applebot":       {[]string{"Applebot"}, []string{"applebot.apple.com"}},
	"yandexbot":      {[]string{"Yandex"}, []string{"yandex.ru", "yandex.net", "yandex.com"}},
	"baiduspider":    {[]string{"Baiduspider"}, []string{"baidu.com", "baidu.jp"}},
}

// compile expands presets, validates and precomputes lowercase needles.
func (vb *VerifiedBotsConfig) compile() error {
	switch vb.SpoofAction {
	case "":
		vb.SpoofAction = "deny"
	case "deny", "continue":
	default:
		return fmt.Errorf("verified_bots.spoof_action must be deny or continue, got %q", vb.SpoofAction)
	}
	if vb.DNSTimeout < 0 || vb.CacheTTL < 0 || vb.NegativeTTL < 0 {
		return fmt.Errorf("verified_bots: dns_timeout, cache_ttl and negative_ttl must be >= 0")
	}
	for i := range vb.Bots {
		b := &vb.Bots[i]
		if b.Name == "" {
			return fmt.Errorf("verified_bots.bots[%d]: name is required", i)
		}
		preset, known := botPresets[strings.ToLower(b.Name)]
		if len(b.UAs) == 0 {
			if !known {
				return fmt.Errorf("verified_bots bot %q: not a built-in preset, so uas is required", b.Name)
			}
			b.UAs = preset.uas
		}
		if len(b.Domains) == 0 {
			if !known {
				return fmt.Errorf("verified_bots bot %q: not a built-in preset, so domains is required", b.Name)
			}
			b.Domains = preset.domains
		}
		b.uasLower = b.uasLower[:0]
		for _, ua := range b.UAs {
			b.uasLower = append(b.uasLower, strings.ToLower(ua))
		}
		b.domainsLower = b.domainsLower[:0]
		for _, d := range b.Domains {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if d == "" {
				return fmt.Errorf("verified_bots bot %q: empty domain entry", b.Name)
			}
			b.domainsLower = append(b.domainsLower, d)
		}
	}
	return nil
}

// GeoConfig scopes a domain by request origin: deny or challenge selected
// countries/ASNs, with default_action covering everything unlisted (so
// "serve only my own country" is default_action: deny plus the home country
// under allow). An IP with no record in
// the databases (private ranges, brand-new allocations) matches no selector
// and gets default_action; keep internal ranges on the static allowlist when
// tightening it. deny wins over challenge when both match.
type GeoConfig struct {
	Enabled       bool        `yaml:"enabled"`
	Deny          GeoSelector `yaml:"deny"`
	Challenge     GeoSelector `yaml:"challenge"`
	Allow         GeoSelector `yaml:"allow"`          // exempt from default_action
	DefaultAction string      `yaml:"default_action"` // allow (default) | challenge | deny
}

// GeoSelector matches ISO 3166-1 alpha-2 country codes (any case in config)
// and/or autonomous system numbers.
type GeoSelector struct {
	Countries []string `yaml:"countries"`
	ASNs      []uint32 `yaml:"asns"`

	countries map[string]bool
	asns      map[uint32]bool
}

func (s *GeoSelector) compile() error {
	s.countries = make(map[string]bool, len(s.Countries))
	for _, c := range s.Countries {
		cc := strings.ToUpper(strings.TrimSpace(c))
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			return fmt.Errorf("invalid country code %q: want ISO 3166-1 alpha-2 like \"NL\"", c)
		}
		s.countries[cc] = true
	}
	s.asns = make(map[uint32]bool, len(s.ASNs))
	for _, a := range s.ASNs {
		if a == 0 {
			return fmt.Errorf("invalid asn 0")
		}
		s.asns[a] = true
	}
	return nil
}

// match returns the first bot whose UA needle appears in ua, or nil.
func (vb *VerifiedBotsConfig) match(ua string) *BotConfig {
	if len(vb.Bots) == 0 || ua == "" {
		return nil
	}
	lower := strings.ToLower(ua)
	for i := range vb.Bots {
		for _, needle := range vb.Bots[i].uasLower {
			if strings.Contains(lower, needle) {
				return &vb.Bots[i]
			}
		}
	}
	return nil
}

// match reports whether the country or ASN is selected, with the reason
// detail ("country:CN" / "asn:64500"). Unknown values never match.
func (s *GeoSelector) match(country string, asn uint32) (string, bool) {
	if country != "" && s.countries[country] {
		return "country:" + country, true
	}
	if asn != 0 && s.asns[asn] {
		return fmt.Sprintf("asn:%d", asn), true
	}
	return "", false
}

func (s *GeoSelector) empty() bool { return len(s.Countries) == 0 && len(s.ASNs) == 0 }

// Action resolves the geo policy for a looked-up origin: "deny" or
// "challenge" with a reason, or ("", "") for pass. Precedence: deny,
// challenge, allow, then default_action.
func (g *GeoConfig) Action(country string, asn uint32) (action, reason string) {
	if !g.Enabled {
		return "", ""
	}
	if detail, ok := g.Deny.match(country, asn); ok {
		return "deny", "geo:" + detail
	}
	if detail, ok := g.Challenge.match(country, asn); ok {
		return "challenge", "geo:" + detail
	}
	if _, ok := g.Allow.match(country, asn); ok {
		return "", ""
	}
	if g.DefaultAction != "allow" {
		return g.DefaultAction, "geo:default"
	}
	return "", ""
}

// ReputationConfig opts a domain in to the globally configured feeds.
type ReputationConfig struct {
	Enabled bool `yaml:"enabled"`
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
	Mode string `yaml:"mode"`
	// Difficulty is configured on the historical hex-digit scale (1..8, one
	// step = 16x the work) but accepts quarter steps for fine-grained control:
	// each +0.25 doubles the work (4.25 is 2x harder than 4). Internally a
	// difficulty is the number of leading zero BITS required of the SHA-256,
	// i.e. round(difficulty * 4); see BaseBits/MaxBits.
	BaseDifficulty   float64  `yaml:"base_difficulty"`
	MaxDifficulty    float64  `yaml:"max_difficulty"`
	TokenTTL         Duration `yaml:"token_ttl"`
	ChallengeTTL     Duration `yaml:"challenge_ttl"`
	NoScriptFallback bool     `yaml:"noscript_fallback"`
}

// maxPoWTTL caps token_ttl and challenge_ttl so a mistyped unit (e.g. a value
// meant as minutes read as hours, or an accidental huge number) cannot create
// effectively-permanent store records. A week is far above any legitimate
// challenge or token lifetime.
const maxPoWTTL = Duration(7 * 24 * time.Hour)

// BaseBits is the floor difficulty in leading zero bits (what every clean
// client pays); MaxBits the ceiling reached only via anomaly scaling.
func (p *PoWConfig) BaseBits() int { return difficultyBits(p.BaseDifficulty) }
func (p *PoWConfig) MaxBits() int  { return difficultyBits(p.MaxDifficulty) }

// difficultyBits converts the configured hex-digit-scale difficulty to bits.
// The scale is 4 bits per unit, so quarter steps land exactly on whole bits.
func difficultyBits(d float64) int { return int(math.Round(d * 4)) }

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

// decodeStrict decodes a yaml.Node into v with unknown-field checking, which
// yaml.Node.Decode does not do on its own. It re-marshals the node and runs it
// through a KnownFields decoder, so a typo inside a per-domain overlay (e.g.
// waf.keywrods) is a load error rather than a silently ignored field that
// leaves protection off for one vhost while `guardiand -t` reports success.
// (Mirrors stateless.decodeStrict for the WASM guest config.)
func decodeStrict(node *yaml.Node, v any) error {
	raw, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	return dec.Decode(v)
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
	if err := c.Reputation.validate(); err != nil {
		return err
	}

	// Defaults for the defaults. Difficulty 5 = 20 leading zero bits: with the
	// in-page JS solver that is roughly a second on a mid-range phone and near
	// instant on a desktop (see USAGE.md for the measured table).
	if c.Defaults.PoW.BaseDifficulty == 0 {
		c.Defaults.PoW.BaseDifficulty = 5
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
			"bot_spoof": {Count: 5, Per: time.Minute},
		}
	}
	if c.Defaults.VerifiedBots.DNSTimeout == 0 {
		// Generous on purpose: a cold recursive PTR resolution can exceed
		// 500ms, and the budget is paid once per IP per cache_ttl.
		c.Defaults.VerifiedBots.DNSTimeout = Duration(time.Second)
	}
	if c.Defaults.VerifiedBots.CacheTTL == 0 {
		c.Defaults.VerifiedBots.CacheTTL = Duration(12 * time.Hour)
	}
	if c.Defaults.VerifiedBots.NegativeTTL == 0 {
		c.Defaults.VerifiedBots.NegativeTTL = Duration(time.Hour)
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
			if err := decodeStrict(&node, dc); err != nil {
				return fmt.Errorf("domain %s: %w", host, err)
			}
		}
		if err := dc.validate(); err != nil {
			return fmt.Errorf("domain %s: %w", host, err)
		}
		if err := c.checkGeoRefs(dc); err != nil {
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
	if err := c.checkGeoRefs(&c.Defaults); err != nil {
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
		return fmt.Errorf("pow.base_difficulty must be 1..8, got %v", p.BaseDifficulty)
	}
	if p.MaxDifficulty < p.BaseDifficulty || p.MaxDifficulty > 8 {
		return fmt.Errorf("pow.max_difficulty must be %v..8, got %v", p.BaseDifficulty, p.MaxDifficulty)
	}
	for _, d := range []float64{p.BaseDifficulty, p.MaxDifficulty} {
		if math.Abs(d*4-math.Round(d*4)) > 1e-9 {
			return fmt.Errorf("pow difficulty %v is not a multiple of 0.25 (each 0.25 step doubles the work)", d)
		}
	}
	// PoW TTLs must be positive. For store backends a non-positive TTL means no
	// expiry, so a negative challenge_ttl makes issued and spent challenge
	// records permanent (unbounded store growth) and breaks the local counter
	// window, and a non-positive token_ttl yields unusable cookies. A negative
	// value is never meaningful, so reject it whether or not PoW is enabled;
	// require strictly positive values once PoW is on. Cap at maxPoWTTL so a
	// fat-fingered unit can't set an effectively-permanent record.
	for _, t := range []struct {
		name string
		d    Duration
	}{{"token_ttl", p.TokenTTL}, {"challenge_ttl", p.ChallengeTTL}} {
		if t.d < 0 {
			return fmt.Errorf("pow.%s must be > 0, got %v", t.name, t.d.Std())
		}
		if p.Enabled && t.d <= 0 {
			return fmt.Errorf("pow.%s must be > 0 when pow is enabled, got %v", t.name, t.d.Std())
		}
		if t.d > maxPoWTTL {
			return fmt.Errorf("pow.%s must be <= %v, got %v", t.name, time.Duration(maxPoWTTL), t.d.Std())
		}
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
	g := &dc.Geo
	switch g.DefaultAction {
	case "":
		g.DefaultAction = "allow"
	case "allow", "challenge", "deny":
	default:
		return fmt.Errorf("geo.default_action must be allow, challenge or deny, got %q", g.DefaultAction)
	}
	for name, sel := range map[string]*GeoSelector{"deny": &g.Deny, "challenge": &g.Challenge, "allow": &g.Allow} {
		if err := sel.compile(); err != nil {
			return fmt.Errorf("geo.%s: %w", name, err)
		}
	}
	for c := range g.Deny.countries {
		if g.Challenge.countries[c] || g.Allow.countries[c] {
			return fmt.Errorf("geo: country %s appears in more than one selector", c)
		}
	}
	for c := range g.Challenge.countries {
		if g.Allow.countries[c] {
			return fmt.Errorf("geo: country %s appears in more than one selector", c)
		}
	}
	for a := range g.Deny.asns {
		if g.Challenge.asns[a] || g.Allow.asns[a] {
			return fmt.Errorf("geo: asn %d appears in more than one selector", a)
		}
	}
	for a := range g.Challenge.asns {
		if g.Allow.asns[a] {
			return fmt.Errorf("geo: asn %d appears in more than one selector", a)
		}
	}
	if g.Enabled && g.Deny.empty() && g.Challenge.empty() && g.DefaultAction == "allow" {
		return fmt.Errorf("geo: enabled but no deny/challenge selectors and default_action is allow; it would never do anything")
	}
	if err := dc.Allowlist.Compile(); err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	if err := dc.Denylist.Compile(); err != nil {
		return fmt.Errorf("denylist: %w", err)
	}
	if err := dc.VerifiedBots.compile(); err != nil {
		return err
	}
	// A bot listed under verified_bots must not also appear in allowlist.uas:
	// the plain UA allowlist runs first and matches by substring, so an
	// overlapping entry would admit any client claiming the UA, unverified —
	// exactly what verified_bots exists to prevent. Fail fast at load.
	for i := range dc.VerifiedBots.Bots {
		b := &dc.VerifiedBots.Bots[i]
		for _, an := range dc.Allowlist.UAs {
			anLower := strings.ToLower(an)
			for _, bn := range b.uasLower {
				if strings.Contains(bn, anLower) || strings.Contains(anLower, bn) {
					return fmt.Errorf("allowlist.uas entry %q overlaps verified_bots bot %q: it would allowlist the bot's User-Agent without verification; remove it from allowlist.uas", an, b.Name)
				}
			}
		}
	}
	return nil
}

// checkGeoRefs refuses geo rules that could never match because the database
// they need is not configured: a silently inert country block is a security
// hole, not a default.
func (c *Config) checkGeoRefs(dc *DomainConfig) error {
	g := &dc.Geo
	if !g.Enabled {
		return nil
	}
	if c.GeoIP.CountryDB == "" && c.GeoIP.ASNDB == "" {
		return fmt.Errorf("geo is enabled but no geoip.country_db or geoip.asn_db is configured")
	}
	usesCountries := len(g.Deny.Countries)+len(g.Challenge.Countries)+len(g.Allow.Countries) > 0
	usesASNs := len(g.Deny.ASNs)+len(g.Challenge.ASNs)+len(g.Allow.ASNs) > 0
	if usesCountries && c.GeoIP.CountryDB == "" {
		return fmt.Errorf("geo uses country selectors but geoip.country_db is not configured")
	}
	if usesASNs && c.GeoIP.ASNDB == "" {
		return fmt.Errorf("geo uses asn selectors but geoip.asn_db is not configured")
	}
	return nil
}

// validate checks the global feed list: names must be unique and safe to use
// as file names and metric labels, and every feed needs exactly one source.
func (r *ReputationFeeds) validate() error {
	seen := make(map[string]bool, len(r.Feeds))
	for i := range r.Feeds {
		f := &r.Feeds[i]
		if !validFeedName(f.Name) {
			return fmt.Errorf("reputation.feeds[%d]: name %q must be 1..64 chars of [a-zA-Z0-9._-]", i, f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("reputation.feeds: duplicate name %q", f.Name)
		}
		seen[f.Name] = true
		if (f.URL == "") == (f.File == "") {
			return fmt.Errorf("reputation feed %s: exactly one of url or file must be set", f.Name)
		}
		if f.URL != "" && !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "https://") {
			return fmt.Errorf("reputation feed %s: url must be http(s), got %q", f.Name, f.URL)
		}
		switch f.Action {
		case "":
			f.Action = "deny"
		case "deny", "challenge":
		default:
			return fmt.Errorf("reputation feed %s: action must be deny or challenge, got %q", f.Name, f.Action)
		}
		if f.Refresh == 0 {
			f.Refresh = Duration(12 * time.Hour)
		}
		if f.URL != "" && f.Refresh.Std() < time.Minute {
			return fmt.Errorf("reputation feed %s: refresh must be at least 1m, got %v", f.Name, f.Refresh.Std())
		}
	}
	return nil
}

func validFeedName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// IntelConfig assembles the intel provider's configuration (GeoIP databases
// plus reputation feeds) from the loaded top-level config.
func (c *Config) IntelConfig() intel.Config {
	ic := intel.Config{
		CountryDB: c.GeoIP.CountryDB,
		ASNDB:     c.GeoIP.ASNDB,
		CacheDir:  c.Reputation.CacheDir,
	}
	for _, f := range c.Reputation.Feeds {
		ic.Feeds = append(ic.Feeds, intel.FeedConfig{
			Name: f.Name, URL: f.URL, File: f.File,
			Refresh: f.Refresh.Std(), Action: f.Action,
		})
	}
	return ic
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
