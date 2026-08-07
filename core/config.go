// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package core contains the transport-agnostic decision engine of Guardian.
// All business logic lives here so the same core can be driven by the HTTP
// auth_request sidecar today and by a cgo or WASM embedding later.
package core

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/intel"
	"github.com/melroy89/angie-guardian/core/stateless"
	"github.com/melroy89/angie-guardian/core/waf"
	"github.com/melroy89/angie-guardian/internal/duration"
	"github.com/melroy89/angie-guardian/internal/safefile"
	"gopkg.in/yaml.v3"
)

// Duration parses YAML scalars like "15m", "4h" or "30d" into a
// time.Duration. Go's own units plus d/w/mon/y, via internal/duration, which
// is the same parser the admin API's TTL fields use so the two never disagree
// about what is a valid duration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\": %w", err)
	}
	v, err := duration.Parse(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML normalises through time.Duration.String(), so a config written
// as "30d" reads back as "720h0m0s". Deliberate: one canonical output form
// beats a round-trip that has to guess which unit the operator typed.
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
	// Rate windows carry the same units as Duration, so "500/d" works. Spelled
	// out rather than routed through duration.Parse because a rate window is a
	// bare unit with no number in front of it, and because the long spellings
	// ("min", "hour") predate this and stay supported.
	var per time.Duration
	switch strings.TrimSpace(unit) {
	case "s", "sec", "second":
		per = time.Second
	case "m", "min", "minute":
		per = time.Minute
	case "h", "hour":
		per = time.Hour
	case "d", "day":
		per = duration.Day
	case "w", "week":
		per = duration.Week
	case "mon", "month":
		per = duration.Month
	case "y", "year":
		per = duration.Year
	default:
		return fmt.Errorf("invalid rate %q: unit must be s, min, h, d, w, mon or y", s)
	}
	*r = Rate{Count: n, Per: per}
	return nil
}

func (r Rate) MarshalYAML() (any, error) {
	unit := map[time.Duration]string{
		time.Second: "s", time.Minute: "min", time.Hour: "h",
		duration.Day: "d", duration.Week: "w", duration.Month: "mon", duration.Year: "y",
	}[r.Per]
	return fmt.Sprintf("%d/%s", r.Count, unit), nil
}

// ThresholdRate is a Rate that additionally accepts the literal "off",
// disabling that one scored event type: the built-in threshold defaults merge
// per key, so without it an operator could tune a default but never switch a
// single key off (only ip_behaviour.enabled kills all scoring). Only the
// thresholds map uses this type; every other rate field keeps the strict
// parser, where a zero rate has no meaning.
type ThresholdRate struct{ Rate }

func (t *ThresholdRate) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil && strings.EqualFold(strings.TrimSpace(s), "off") {
		*t = ThresholdRate{}
		return nil
	}
	return t.Rate.UnmarshalYAML(node)
}

// MarshalYAML must round-trip the zero value as "off": domain configs are
// built by marshalling the defaults and decoding the domain YAML on top, and
// "0/…" would be rejected on the way back in.
func (t ThresholdRate) MarshalYAML() (any, error) {
	if t.Count <= 0 {
		return "off", nil
	}
	return t.Rate.MarshalYAML()
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
	TrustedProxy bool `yaml:"trusted_proxy"`
	// RequireProxied rejects guard requests (auth/challenge/pass) that arrive
	// without the X-Guardian-* headers the Angie glue always sets, instead of
	// falling back to the socket address. A tripwire for the listener's header
	// trust: if the guard port is ever reachable directly (firewall mistake,
	// shared host), stray traffic is refused and surfaces in the
	// unproxied-rejects metric instead of being processed under its socket
	// identity. It is not a spoofing defense: a deliberate direct client can
	// still send forged X-Guardian-* headers and pass this gate, so listener
	// isolation (see TrustedProxy) remains the only control that prevents
	// spoofing. Off by default so probing Guardian directly (dev, tests, curl)
	// keeps working; healthz and the denied page are never gated.
	RequireProxied bool              `yaml:"require_proxied"`
	Admin          AdminConfig       `yaml:"admin"`
	Store          StoreConfig       `yaml:"store"`
	Enforcement    EnforcementConfig `yaml:"enforcement"`
	AttackMode     AttackModeConfig  `yaml:"attack_mode"`
	GeoIP          GeoIPConfig       `yaml:"geoip"`
	Reputation     ReputationFeeds   `yaml:"reputation"`
	// DefaultsNode is the raw defaults: mapping. It is captured as a node, not
	// decoded straight into a DomainConfig, so its paths: key can be split off
	// before the struct decode exactly like a domain's (see splitPathsNode):
	// DomainConfig has no Paths field, so the strict decoder would otherwise
	// reject it. Read Defaults, not this, after finalize.
	DefaultsNode yaml.Node            `yaml:"defaults"`
	Domains      map[string]yaml.Node `yaml:"domains"`

	// Defaults is DefaultsNode resolved: the fleet-wide base every domain is
	// merged over, and the effective config for unknown hosts. Its own
	// pathOverrides are the defaults: paths: entries, inherited by every
	// domain (see resolvePaths).
	Defaults DomainConfig `yaml:"-"`

	resolved map[string]*DomainConfig
}

// AdminConfig configures the admin + metrics listener. It is separate from
// the auth listener so it can bind to loopback / a management interface.
type AdminConfig struct {
	Listen string `yaml:"listen"` // empty disables the admin+metrics server
	Token  string `yaml:"token"`  // bearer token; or ADMIN_TOKEN env var

	// RecentSize bounds the per-instance, in-memory non-allow decision window.
	// It is scanned by live admin reports, cleared on restart, and intentionally
	// not a replacement for Prometheus/Grafana history. Start-time only.
	RecentSize int `yaml:"recent_size"`

	// TokenFile persists an auto-generated bearer token (like the PoW signing
	// key: created 0600 on first start, never regenerated). Used when Token
	// and ADMIN_TOKEN are unset, so the operator never invents a token by
	// hand. With neither token nor token_file, a loopback admin listener gets
	// a fresh ephemeral token per start. It is printed once at startup; the
	// dashboard URL itself never contains configured or persistent secrets.
	TokenFile string `yaml:"token_file"`

	// MetricsAuth puts /metrics behind the admin bearer token. Off by default
	// so scrapers need no secret, but worth enabling on a routable admin bind:
	// /metrics exposes every protected vhost name plus per-domain traffic and
	// attack posture. /healthz and /readyz always stay unauthenticated so
	// orchestrator probes keep working. Prometheus supports the token via
	// authorization.credentials / credentials_file. Pair it with a stable
	// token (token or token_file): an ephemeral per-start token would break
	// the scrape config on every restart.
	MetricsAuth bool `yaml:"metrics_auth"`

	// Dashboard serves the built-in reporting page at GET /admin/dashboard.
	// The page itself is a static shell (all data flows through the
	// token-guarded /admin/* endpoints), but it stays off by default so the
	// admin surface exposes nothing extra unless asked to.
	Dashboard bool `yaml:"dashboard"`

	// AngieAPI, when set, lets the dashboard show what Guardian itself never
	// sees, by reading Angie's own HTTP API: per-domain requests and bandwidth,
	// connections, upstream peer health, proxy-cache hit rates, Angie's own rate
	// limit zones and shared memory pressure. Off when unset.
	AngieAPI AngieAPIConfig `yaml:"angie_api"`
}

// AngieAPIConfig points guardiand at Angie's HTTP API location so the admin
// server can relay its status endpoints to the dashboard. This is a read of
// another service; it never touches Guardian's hot path.
type AngieAPIConfig struct {
	// URL is the base of Angie's http_api location (e.g. http://127.0.0.1:81/status/).
	// Empty disables the integration. guardiand only ever appends a fixed,
	// known-safe set of suffixes (see angiePaths in transport/http/angie.go:
	// /angie/, /connections/, /slabs/ and the /http/ zone endpoints), so there is
	// no client-controlled request target.
	URL string `yaml:"url"`
	// Timeout bounds each fetch from Angie's API. Default 2s.
	Timeout Duration `yaml:"timeout"`
}

type StoreConfig struct {
	Backend  string `yaml:"backend"`  // memory | buntdb | pebble | redis
	Path     string `yaml:"path"`     // buntdb database file, or pebble directory
	Addr     string `yaml:"addr"`     // redis host:port
	Password string `yaml:"password"` // redis password (or use REDIS_PASSWORD)
	DB       int    `yaml:"db"`       // redis database number
	// Sync makes the pebble backend fsync every write (fully durable, slower).
	// When false (default), writes are flushed without a per-write fsync, much
	// faster, at the cost of losing the unflushed tail on a power/OS crash (a
	// bounded, <=challenge_ttl replay window). buntdb REJECTS sync: true at
	// load (single writer, fsync-per-commit is ~100x slower; see applyDefaults);
	// other backends ignore it.
	Sync bool `yaml:"sync"`
}

// EnforcementConfig moves active-block enforcement onto layers cheaper than
// the per-request store lookup: the always-on in-process mirror, and an
// optional nftables sink that drops blocked clients in the kernel before
// they reach Angie at all. Every field is restart-required (the mirror seed,
// sink and netlink wiring happen at startup).
type EnforcementConfig struct {
	Mirror   MirrorConfig   `yaml:"mirror"`
	NFTables NFTablesConfig `yaml:"nftables"`
}

// MirrorConfig tunes the in-process block mirror. It has no enabled toggle
// on purpose: the mirror is strictly cheaper than the store lookup it fronts
// and degrades to it in every failure mode, so there is nothing to turn off.
type MirrorConfig struct {
	// ReconcileInterval is the cadence of the active-block index read that
	// seeds the mirror, corrects learned entries and repairs sink drift. It
	// also bounds cross-replica propagation of unblocks in read_through mode.
	ReconcileInterval Duration `yaml:"reconcile_interval"` // default 10s, min 1s
	// MaxEntries bounds the mirror; overflow entries fall back to store reads.
	MaxEntries int `yaml:"max_entries"` // default 1048576
	// Mode: auto (default) picks authoritative for embedded single-instance
	// backends (memory, buntdb, pebble) and read_through for a shared store
	// (redis), where a mirror miss must still consult the store so another
	// replica's blocks bite before the next indexed reconcile.
	Mode string `yaml:"mode"` // auto | authoritative | read_through
}

// NFTablesConfig is the optional kernel enforcement sink (Linux only; needs
// CAP_NET_ADMIN in the network namespace where client traffic arrives).
type NFTablesConfig struct {
	Enabled bool `yaml:"enabled"`
	// Mode managed (default) owns a table with a base chain whose drop rule
	// matches only Ports, so SSH and the admin listener are structurally out
	// of reach. sets_only just maintains the sets for an operator-owned rule.
	Mode  string `yaml:"mode"`  // managed | sets_only
	Table string `yaml:"table"` // default "guardian"
	Hook  string `yaml:"hook"`  // managed only: input (default) | prerouting
	// Ports the managed drop rule applies to. Refused empty in managed mode:
	// an all-ports drop could cut off SSH and the admin API.
	Ports []int `yaml:"ports"` // default [80, 443]
	// NetNS is a network namespace file (e.g. /proc/1/ns/net or a bind mount)
	// to program instead of the daemon's own namespace.
	NetNS      string `yaml:"netns"`
	MaxEntries int    `yaml:"max_entries"` // kernel set size bound, default 65536
	// MinTTL skips offloading short blocks (kernel churn is not worth it for
	// them); 0 offloads every block.
	MinTTL Duration `yaml:"min_ttl"`
	// NeverBlock CIDRs are never sent to the kernel. Put load balancer and
	// CDN ranges here: dropping an LB address at L3 takes down everything
	// behind it. Configured allowlists are excluded automatically on top.
	NeverBlock []string `yaml:"never_block"`
	// AllowPrivate permits private / special-purpose ranges (RFC1918, CGNAT,
	// ULA, unspecified, multicast) to be kernel-dropped. Off by default: a
	// misconfigured trusted proxy that surfaces an internal hop as the client
	// IP would otherwise blackhole the load balancer or gateway, and a managed
	// block survives a daemon restart. Enable only when Guardian serves
	// routable private space directly.
	AllowPrivate bool `yaml:"allow_private"`

	neverBlock []netip.Prefix
}

func (e *EnforcementConfig) validate() error {
	m := &e.Mirror
	switch m.Mode {
	case "":
		m.Mode = "auto"
	case "auto", "authoritative", "read_through":
	default:
		return fmt.Errorf("enforcement.mirror.mode must be auto, authoritative or read_through, got %q", m.Mode)
	}
	if m.ReconcileInterval == 0 {
		m.ReconcileInterval = Duration(10 * time.Second)
	}
	if m.ReconcileInterval.Std() < time.Second {
		return fmt.Errorf("enforcement.mirror.reconcile_interval must be at least 1s, got %v", m.ReconcileInterval.Std())
	}
	if m.MaxEntries == 0 {
		m.MaxEntries = 1 << 20
	}
	if m.MaxEntries < 0 {
		return fmt.Errorf("enforcement.mirror.max_entries must be > 0, got %d", m.MaxEntries)
	}
	n := &e.NFTables
	switch n.Mode {
	case "":
		n.Mode = "managed"
	case "managed", "sets_only":
	default:
		return fmt.Errorf("enforcement.nftables.mode must be managed or sets_only, got %q", n.Mode)
	}
	switch n.Hook {
	case "":
		n.Hook = "input"
	case "input", "prerouting":
	default:
		return fmt.Errorf("enforcement.nftables.hook must be input or prerouting, got %q", n.Hook)
	}
	if n.Table == "" {
		n.Table = "guardian"
	}
	if n.Ports == nil {
		n.Ports = []int{80, 443}
	}
	for _, p := range n.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("enforcement.nftables.ports: invalid port %d", p)
		}
	}
	if n.MaxEntries == 0 {
		n.MaxEntries = 65536
	}
	if n.MaxEntries < 0 {
		return fmt.Errorf("enforcement.nftables.max_entries must be > 0, got %d", n.MaxEntries)
	}
	if n.MinTTL < 0 {
		return fmt.Errorf("enforcement.nftables.min_ttl must be >= 0, got %v", n.MinTTL.Std())
	}
	n.neverBlock = n.neverBlock[:0]
	for _, s := range n.NeverBlock {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			return fmt.Errorf("enforcement.nftables.never_block: %w", err)
		}
		n.neverBlock = append(n.neverBlock, p)
	}
	if n.Enabled {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("enforcement.nftables is only supported on Linux (running on %s)", runtime.GOOS)
		}
		if n.Mode == "managed" && len(n.Ports) == 0 {
			return fmt.Errorf("enforcement.nftables.ports must not be empty in managed mode: an all-ports drop rule could cut off SSH and the admin API; use mode sets_only to write your own rule")
		}
	}
	return nil
}

// parsePrefixOrAddr accepts a CIDR or a bare IP (as ListConfig does).
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// AttackModeConfig drives the fleet-wide attack posture. Absent or
// enabled: false keeps behaviour identical to today. Signals are measured
// per instance over a sliding window; when a threshold is crossed the
// instance raises PoW difficulty fleet-wide, optionally forces challenges and
// switches challenge issuance to a store-free (stateless) path, so a flood of
// new clients stops saturating the store. Hot-reloadable.
type AttackModeConfig struct {
	Enabled bool `yaml:"enabled"`
	// Window is the sliding measurement window (bucketed in 5s steps).
	Window Duration `yaml:"window"`
	// MinDwell is the minimum time at a level before it decays one step, so a
	// posture cannot flap on threshold-straddling load. Must be >= Window.
	MinDwell Duration `yaml:"min_dwell"`
	// SharePosture broadcasts the level through the shared store (one op per
	// tick) so replicas move together; a failing store degrades to local-only.
	SharePosture *bool               `yaml:"share_posture"`
	Signals      AttackSignalsConfig `yaml:"signals"`
	Effects      AttackEffectsConfig `yaml:"effects"`
}

// AttackSignalsConfig are the thresholds that move the posture. A signal is
// disabled by omission (a rate cannot be written "0/s"); a fully-omitted
// signals block instead receives the standard defaults.
type AttackSignalsConfig struct {
	ChallengeRate       Rate    `yaml:"challenge_rate"`        // issuance/s entering elevated
	AttackChallengeRate Rate    `yaml:"attack_challenge_rate"` // issuance/s entering attack
	MinSolveRatio       float64 `yaml:"min_solve_ratio"`       // attack entry needs solved/issued below this
	RequestRate         Rate    `yaml:"request_rate"`          // global Evaluate/s; omit to disable
	StoreErrorRatio     float64 `yaml:"store_error_ratio"`     // store op error fraction entering elevated
	StoreSlowRatio      float64 `yaml:"store_slow_ratio"`      // slow (>25ms) op fraction entering elevated
}

// AttackEffectsConfig are the independently-toggleable effects. Difficulty
// raises are on the historical 1..8 quarter-step scale (each 0.25 = 1 bit).
// The raises and the cap are pointers so an explicit 0 (raise nothing) is
// distinguishable from an omitted field (use the default); the accessors below
// resolve them.
type AttackEffectsConfig struct {
	ElevatedDifficultyRaise *float64 `yaml:"elevated_difficulty_raise"`
	AttackDifficultyRaise   *float64 `yaml:"attack_difficulty_raise"`
	DifficultyCap           *float64 `yaml:"difficulty_cap"` // ceiling for the shifted window
	ForceAlways             *bool    `yaml:"force_always"`   // attack: suspicion behaves as always
	StatelessIssuance       *bool    `yaml:"stateless_issuance"`
	ScoreboardFactor        float64  `yaml:"scoreboard_factor"` // attack: multiply thresholds (0<f<=1)
	// MaxInflight bounds concurrent Evaluate calls (Part C load-shedding);
	// over the bound, token holders still pass and others get 503. 0 = off.
	MaxInflight int `yaml:"max_inflight"`
}

// elevatedRaise/attackRaise/cap resolve the *float64 fields to their value,
// applying the default only when the operator omitted the field entirely. An
// explicit 0 raise is honoured (raise nothing at that level).
func (e *AttackEffectsConfig) elevatedRaise() float64 { return floatOr(e.ElevatedDifficultyRaise, 0.5) }
func (e *AttackEffectsConfig) attackRaise() float64   { return floatOr(e.AttackDifficultyRaise, 1.0) }
func (e *AttackEffectsConfig) cap() float64           { return floatOr(e.DifficultyCap, 7.0) }

func floatOr(p *float64, def float64) float64 {
	if p == nil {
		return def
	}
	return *p
}

// ExtraBits returns the fleet difficulty raise in leading-zero bits for the
// given level (0 normal, 1 elevated, 2 attack).
func (a *AttackModeConfig) ExtraBits(level int) int {
	switch level {
	case 1:
		return difficultyBits(a.Effects.elevatedRaise())
	case 2:
		return difficultyBits(a.Effects.attackRaise())
	default:
		return 0
	}
}

// CapBits is the ceiling for the shifted difficulty window, in bits.
func (a *AttackModeConfig) CapBits() int { return difficultyBits(a.Effects.cap()) }

// SharePostureEnabled resolves the *bool default (true).
func (a *AttackModeConfig) SharePostureEnabled() bool {
	return a.SharePosture == nil || *a.SharePosture
}

// ForceAlwaysEnabled resolves the *bool default (true).
func (a *AttackEffectsConfig) ForceAlwaysEnabled() bool {
	return a.ForceAlways == nil || *a.ForceAlways
}

// StatelessEnabled resolves the *bool default (true).
func (a *AttackEffectsConfig) StatelessEnabled() bool {
	return a.StatelessIssuance == nil || *a.StatelessIssuance
}

func (a *AttackModeConfig) validate() error {
	if a.Window == 0 {
		a.Window = Duration(30 * time.Second)
	}
	if a.Window.Std() < 10*time.Second || a.Window.Std() > 10*time.Minute {
		return fmt.Errorf("attack_mode.window must be 10s..10m, got %v", a.Window.Std())
	}
	if a.MinDwell == 0 {
		a.MinDwell = Duration(60 * time.Second)
	}
	if a.MinDwell < a.Window {
		return fmt.Errorf("attack_mode.min_dwell (%v) must be >= window (%v)", a.MinDwell.Std(), a.Window.Std())
	}
	// Whole-block defaulting: when the operator supplied NO signals/effects
	// block at all (every field is the zero value), fill the standard
	// defaults. Once any field is set, omitted fields keep their zero value, so
	// an omitted signal stays disabled and elevated_difficulty_raise: 0.0
	// raises nothing at elevated, instead of being silently defaulted.
	s := &a.Signals
	if (AttackSignalsConfig{}) == *s {
		s.ChallengeRate = Rate{Count: 200, Per: time.Second}
		s.AttackChallengeRate = Rate{Count: 1000, Per: time.Second}
		s.MinSolveRatio = 0.2
		s.StoreErrorRatio = 0.05
		s.StoreSlowRatio = 0.25
	}
	// min_solve_ratio only matters when the attack issuance signal is active,
	// and 0 is not a usable value for it (the ratio qualifier would never
	// pass), so it keeps a sane default even in a partial block.
	if s.MinSolveRatio == 0 {
		s.MinSolveRatio = 0.2
	}
	if s.ChallengeRate.Count != 0 && s.AttackChallengeRate.Count != 0 &&
		perSecond(s.AttackChallengeRate) < perSecond(s.ChallengeRate) {
		return fmt.Errorf("attack_mode.signals.attack_challenge_rate must be >= challenge_rate")
	}
	if err := ratioField("min_solve_ratio", s.MinSolveRatio); err != nil {
		return err
	}
	// The ratio signals accept 0 (disabled); validate only non-zero values.
	if s.StoreErrorRatio != 0 {
		if err := ratioField("store_error_ratio", s.StoreErrorRatio); err != nil {
			return err
		}
	}
	if s.StoreSlowRatio != 0 {
		if err := ratioField("store_slow_ratio", s.StoreSlowRatio); err != nil {
			return err
		}
	}
	e := &a.Effects
	// Raises are pointers, so an explicit 0 (raise nothing) is honoured while
	// an omitted field takes the default. Validate the RESOLVED values.
	for _, r := range []struct {
		name string
		v    float64
	}{{"elevated_difficulty_raise", e.elevatedRaise()}, {"attack_difficulty_raise", e.attackRaise()}} {
		if math.IsNaN(r.v) || math.IsInf(r.v, 0) || r.v < 0 || r.v > 2 {
			return fmt.Errorf("attack_mode.effects.%s must be 0..2, got %v", r.name, r.v)
		}
		if math.Abs(r.v*4-math.Round(r.v*4)) > 1e-9 {
			return fmt.Errorf("attack_mode.effects.%s must be a multiple of 0.25, got %v", r.name, r.v)
		}
	}
	if c := e.cap(); math.IsNaN(c) || math.IsInf(c, 0) || c < 1 || c > 8 {
		return fmt.Errorf("attack_mode.effects.difficulty_cap must be 1..8, got %v", c)
	}
	if e.ScoreboardFactor == 0 {
		e.ScoreboardFactor = 1.0
	}
	if math.IsNaN(e.ScoreboardFactor) || math.IsInf(e.ScoreboardFactor, 0) || e.ScoreboardFactor <= 0 || e.ScoreboardFactor > 1 {
		return fmt.Errorf("attack_mode.effects.scoreboard_factor must be 0<f<=1, got %v", e.ScoreboardFactor)
	}
	if e.MaxInflight < 0 {
		return fmt.Errorf("attack_mode.effects.max_inflight must be >= 0, got %d", e.MaxInflight)
	}
	return nil
}

// perSecond normalizes a Rate to a per-second float for comparison.
func perSecond(r Rate) float64 {
	if r.Per <= 0 {
		return 0
	}
	return float64(r.Count) / r.Per.Seconds()
}

func ratioField(name string, v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > 1 {
		return fmt.Errorf("attack_mode.signals.%s must be 0<r<=1, got %v", name, v)
	}
	return nil
}

// GeoIPConfig points at MaxMind-format (.mmdb) databases: MaxMind
// GeoLite2/GeoIP2, DB-IP or any other publisher of the format. The files are
// hot-reloaded when replaced on disk (geoipupdate does this atomically), so
// scheduled updates need no restart. Either may be omitted; geo rules that
// would need the missing database are refused at config load.
type GeoIPConfig struct {
	// LocationDB answers "where is this IP". A Country database
	// (GeoLite2-Country) and a City database (GeoLite2-City) are both valid
	// here: City is a superset, carrying the same country.iso_code plus
	// city/subdivision detail, so country rules behave identically either
	// way. City costs ~7.5x the file size and only adds admin-view detail,
	// never new selectors. GeoIP2-Enterprise and DB-IP files work too, which
	// is why this key is not named after any one product.
	LocationDB string `yaml:"location_db"`
	ASNDB      string `yaml:"asn_db"`
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
// merged over Defaults field-by-field at load time. A domain entry, and the
// defaults block itself, may also carry a paths: map of per-path overlays;
// that key is split off before this struct is decoded (see finalize), so
// DomainConfig itself deliberately has no Paths field. That keeps paths:
// nested inside another path overlay an unknown-field load error.
type DomainConfig struct {
	WAF          WAFConfig          `yaml:"waf"`
	PoW          PoWConfig          `yaml:"pow"`
	Geo          GeoConfig          `yaml:"geo"`
	Reputation   ReputationConfig   `yaml:"reputation"`
	Allowlist    ListConfig         `yaml:"allowlist"`
	Denylist     ListConfig         `yaml:"denylist"`
	VerifiedBots VerifiedBotsConfig `yaml:"verified_bots"`

	// pathOverrides are the compiled paths: entries, sorted most specific
	// first (see resolvePaths); populated only on resolved domain configs.
	pathOverrides []pathOverride

	// label is the bounded metric label for the host this config was resolved
	// for: the normalized domain key, or "default". Stamped once at load (see
	// resolve) rather than carried alongside the config through the request,
	// which cost the per-request stage environment a whole string header.
	//
	// Every path overlay carries its HOST's label, not its path: paths are
	// client-controlled and unbounded, so one must never reach a metric.
	//
	// Unexported on purpose. Domain and overlay configs are built by
	// marshalling a parent config to YAML and decoding it onto a fresh value,
	// so an exported field would have every domain inherit the defaults' label
	// and silently relabel the entire fleet as "default".
	label string
}

// pathOverride is one compiled paths: entry: a full DomainConfig resolved as
// defaults, then the domain's overlay, then this path's overlay on top.
type pathOverride struct {
	key    string // as configured, e.g. "/api/v1/"
	bare   string // key minus any trailing "/", the specificity ruler
	prefix bool   // key ends with "/", so it prefix-matches
	cfg    *DomainConfig
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
	if vb.CacheTTL.Std() > MaxStateTTL || vb.NegativeTTL.Std() > MaxStateTTL {
		return fmt.Errorf("verified_bots: cache_ttl and negative_ttl must be <= %v", MaxStateTTL)
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
			ua = strings.TrimSpace(ua)
			if ua == "" {
				return fmt.Errorf("verified_bots bot %q: empty user-agent entry", b.Name)
			}
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

// match returns the first bot whose UA needle appears in the already-lowercased
// User-Agent (RequestContext.LowerUA), or nil.
func (vb *VerifiedBotsConfig) match(lower string) *BotConfig {
	if len(vb.Bots) == 0 || lower == "" {
		return nil
	}
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
	Rules       RulesConfig       `yaml:"rules"`
	Anomaly     AnomalyConfig     `yaml:"anomaly"` // enforced from P3
	Honeypot    HoneypotConfig    `yaml:"honeypot"`
	// SignedID reserves the signed-ID feature: opaque
	// HMAC-bound identifiers whose forgery, replay or cross-domain reuse is
	// detectable. The primitive exists in core/waf.Signer; no flow mints signed
	// IDs yet, so this toggle is dormant. It does NOT gate PoW tamper scoring:
	// forged or replayed PoW challenge IDs are always scored via the
	// waf.ip_behaviour "tamper" threshold.
	SignedID ToggleConfig `yaml:"signed_id"`
}

// IPBehaviourConfig drives the behavioural scoreboard: how many bad events
// of a given type (threshold key) an IP may produce per window before it is
// temporarily blocked, with exponential backoff up to max_block_ttl. A value
// of "off" disables that one event type individually.
type IPBehaviourConfig struct {
	Enabled     bool                     `yaml:"enabled"`
	BlockTTL    Duration                 `yaml:"block_ttl"`
	MaxBlockTTL Duration                 `yaml:"max_block_ttl"`
	Thresholds  map[string]ThresholdRate `yaml:"thresholds"`
}

// HoneypotConfig configures trap paths: URLs no legitimate client ever
// requests (hidden links, robots.txt-disallowed paths). One hit blocks.
// Aliased from the leaf package so the sidecar and WASM guest share the type.
type HoneypotConfig = stateless.HoneypotConfig

type RulesConfig struct {
	Enabled bool `yaml:"enabled"`
	// Files is the ordered effective rule policy for this scope. Files named by
	// narrower domain and path overlays are appended to the inherited list, so
	// the shared defaults remain active and run first.
	Files []string `yaml:"files"`
	// DisabledIDs removes rules from the effective files for this
	// scope by their exact, case-sensitive id, without copying the files. Like
	// every list field it overlays wholesale: omitted inherits the parent's
	// list, [] clears it, a non-empty list replaces it (re-list inherited IDs
	// to keep them). Every ID must exist in the effective files; typos
	// are load/reload errors, never silently-enabled rules.
	DisabledIDs []string `yaml:"disabled_ids"`

	// ruleKey is the precomputed RuleCache variant key for this scope's
	// (files, disabled_ids) pair, set in validate() so the request
	// hot path stays a single map lookup with no per-request filtering.
	ruleKey string
}

type AnomalyConfig struct {
	Enabled     bool    `yaml:"enabled"`
	ObserveOnly bool    `yaml:"observe_only"`
	Model       string  `yaml:"model"`
	ChallengeAt float64 `yaml:"challenge_at"`
	DenyAt      float64 `yaml:"deny_at"`
}

type ToggleConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PoWConfig struct {
	Enabled bool `yaml:"enabled"`
	// Mode "always" challenges every unvouched request; "suspicion" only
	// challenges clients the anomaly scorer flags (requires waf.anomaly).
	Mode string `yaml:"mode"`
	// Difficulty is configured on the historical hex-digit scale (1..8, one
	// step = 16x the work) but accepts quarter steps for fine-grained control:
	// each +0.25 doubles the work (4.25 is 2x harder than 4). Internally a
	// difficulty is the number of leading zero BITS required of the SHA-256,
	// i.e. round(difficulty * 4); see BaseBits/MaxBits.
	BaseDifficulty float64  `yaml:"base_difficulty"`
	MaxDifficulty  float64  `yaml:"max_difficulty"`
	TokenTTL       Duration `yaml:"token_ttl"`
	ChallengeTTL   Duration `yaml:"challenge_ttl"`
	// IssuanceRateLimit caps how many challenges one IP may be issued per
	// window, so the interstitial cannot itself be used to flood the store.
	// Promoted from a compile-time constant so operators can tune it under
	// attack. Default 60/min preserves the historical behaviour.
	IssuanceRateLimit Rate `yaml:"issuance_rate_limit"`
	NoScriptFallback  bool `yaml:"noscript_fallback"`
	// RefuseUnchallengeable withholds a challenge from a request classified as
	// unable to complete one (a declared subresource, which provably cannot run
	// the interstitial, or a request whose destination is unrecognized or
	// absent, is not a navigation by Sec-Fetch-Mode either, and whose Accept
	// names no HTML, which is a behavioural heuristic), answering a terse 403
	// instead of an interstitial it would only drop. Default true; set false to
	// restore the older challenge-everything path.
	//
	// This is a config key rather than the `proxy_set_header Accept "";` lever
	// it replaces because the decision is now taken twice per request, at the
	// auth subrequest (which records the outcome) and at the challenge handler
	// (which serves it). A header cleared in one Angie location and not the
	// other made those two disagree: the decision log said a challenge was
	// withheld while the client was handed one. Both hops resolve this same key
	// for the same host and path, and the auth hop relays the verdict it reached
	// (X-Guardian-Refusal) so the challenge hop obeys rather than deciding
	// again: reading one key is not enough on its own, since the two hops read
	// it at different moments and a reload landing in that gap would still drift
	// them apart. Unlike a proxy_set_header it is also hot-reloadable and does
	// not hide the header from WAF header:<name> rules. Scoped per domain and
	// per path like the rest of PoW.
	RefuseUnchallengeable *bool `yaml:"refuse_unchallengeable"`
}

// RefusesUnchallengeable resolves the *bool default (true).
func (p *PoWConfig) RefusesUnchallengeable() bool {
	return p.RefuseUnchallengeable == nil || *p.RefuseUnchallengeable
}

// maxPoWTTL caps token_ttl and challenge_ttl so a mistyped unit (e.g. a value
// meant as minutes read as hours, or an accidental huge number) cannot create
// effectively-permanent store records. A week is far above any legitimate
// challenge or token lifetime.
const maxPoWTTL = Duration(7 * 24 * time.Hour)

// MaxStateTTL is the longest operator-configurable lifetime for blocks and
// identity-cache records. It prevents unit typos from creating effectively
// permanent state while leaving ample room for long-lived administrative
// policy. PoW has its stricter seven-day cap above.
const MaxStateTTL = 365 * 24 * time.Hour

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

// maxConfigBytes bounds guardian.yaml reads; defaultListen is the guard
// listen applied when the config omits one. Shared by LoadConfig/finalize and
// the lenient ListenAddrs so the healthcheck probe can never drift from what
// the daemon actually binds.
const (
	maxConfigBytes = 4 << 20
	defaultListen  = "127.0.0.1:8071"
)

// LoadConfig reads, validates and resolves guardian.yaml. Per-domain configs
// are precomputed here so the request hot path is a single map lookup.
func LoadConfig(path string) (*Config, error) {
	raw, err := safefile.Read(path, maxConfigBytes)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse %s: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("parse %s trailing document: %w", path, err)
	}
	if err := cfg.finalize(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// ListenAddrs leniently extracts the guard and admin listen addresses from a
// config file without validating the rest of it. The -healthcheck probe uses
// it so a half-edited or otherwise invalid guardian.yaml cannot fail a probe
// of an already-running, healthy daemon (which would crash-loop the service on
// the bad config). It applies the same default guard listen as finalize but
// runs no other validation, and tolerates unknown fields for the same reason.
func ListenAddrs(path string) (listen, adminListen string, err error) {
	raw, err := safefile.Read(path, maxConfigBytes)
	if err != nil {
		return "", "", err
	}
	var probe struct {
		Listen string `yaml:"listen"`
		Admin  struct {
			Listen string `yaml:"listen"`
		} `yaml:"admin"`
	}
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return "", "", fmt.Errorf("parse %s: %w", path, err)
	}
	if probe.Listen == "" {
		probe.Listen = defaultListen
	}
	return probe.Listen, probe.Admin.Listen, nil
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

// appendLocalRuleFiles restores cumulative rules-file inheritance after a
// normal YAML overlay decode. YAML lists otherwise replace the inherited
// value wholesale; rules.files deliberately differs because a domain or path
// policy extends the shared defaults instead of silently dropping them.
func appendLocalRuleFiles(node *yaml.Node, inherited []string, dc *DomainConfig) error {
	filesNode, ok := nestedMappingValue(node, "waf", "rules", "files")
	if !ok {
		return nil
	}
	var local []string
	if filesNode.Kind != 0 && filesNode.Tag != "!!null" {
		if err := filesNode.Decode(&local); err != nil {
			return fmt.Errorf("waf.rules.files: %w", err)
		}
	}
	dc.WAF.Rules.Files = append(append([]string(nil), inherited...), local...)
	return nil
}

func nestedMappingValue(node *yaml.Node, keys ...string) (*yaml.Node, bool) {
	cur := node
	for _, key := range keys {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil, false
		}
		found := false
		for i := 0; i+1 < len(cur.Content); i += 2 {
			if cur.Content[i].Value == key {
				cur = cur.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return cur, true
}

func (c *Config) finalize() error {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if err := validateListenAddress("listen", c.Listen); err != nil {
		return err
	}
	if !c.TrustedProxy && !listenIsLoopback(c.Listen) {
		return fmt.Errorf("listen %s is not loopback: the auth hot path trusts client-identity headers from its caller, so a non-loopback bind lets clients spoof them. Isolate the listener to Angie and set trusted_proxy: true to allow this", c.Listen)
	}
	switch c.LogLevel {
	case "":
		c.LogLevel = "warn"
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn or error, got %q", c.LogLevel)
	}
	if c.Admin.Token == "" {
		c.Admin.Token = os.Getenv("ADMIN_TOKEN")
	}
	if c.Admin.RecentSize == 0 {
		c.Admin.RecentSize = defaultRecentSize
	}
	if c.Admin.RecentSize < 0 {
		return fmt.Errorf("admin.recent_size must be > 0, got %d", c.Admin.RecentSize)
	}
	if c.Admin.RecentSize > maxRecentSize {
		return fmt.Errorf("admin.recent_size must be <= %d, got %d", maxRecentSize, c.Admin.RecentSize)
	}
	if c.Admin.Listen != "" {
		if err := validateListenAddress("admin.listen", c.Admin.Listen); err != nil {
			return err
		}
		if !listenIsLoopback(c.Admin.Listen) && c.Admin.Token == "" && c.Admin.TokenFile == "" {
			return fmt.Errorf("admin.listen %s is not loopback but no admin.token or admin.token_file is set; refusing to expose an unauthenticated admin API", c.Admin.Listen)
		}
	}
	if c.Admin.AngieAPI.URL != "" {
		u, err := url.Parse(c.Admin.AngieAPI.URL)
		if err != nil {
			return fmt.Errorf("admin.angie_api.url is not a valid URL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("admin.angie_api.url must be an http or https URL, got %q", c.Admin.AngieAPI.URL)
		}
		if u.Host == "" {
			return fmt.Errorf("admin.angie_api.url must include a host, got %q", c.Admin.AngieAPI.URL)
		}
		if c.Admin.AngieAPI.Timeout < 0 {
			return fmt.Errorf("admin.angie_api.timeout must be positive, got %v", c.Admin.AngieAPI.Timeout.Std())
		}
		if c.Admin.AngieAPI.Timeout == 0 {
			c.Admin.AngieAPI.Timeout = Duration(2 * time.Second)
		}
	}
	switch c.Store.Backend {
	case "":
		c.Store.Backend = "memory"
	case "memory":
	case "buntdb":
		if c.Store.Path == "" {
			return fmt.Errorf("store.path is required for the buntdb backend")
		}
		if c.Store.Sync {
			// buntdb is single-writer, so fsync-per-commit (sync: true) collapses
			// challenge-write throughput to a few hundred req/s, far below the
			// budget and worse than not persisting at all. Refuse it rather than
			// ship a silently crippled daemon; pebble is the synchronous-durable
			// option.
			return fmt.Errorf("store.sync is not supported on the buntdb backend " +
				"(its single writer makes fsync-per-commit ~100x slower); use " +
				"backend: pebble with sync: true for synchronous durability, or " +
				"leave buntdb in its fast async mode (sync: false)")
		}
	case "pebble":
		if c.Store.Path == "" {
			return fmt.Errorf("store.path is required for the pebble backend")
		}
	case "redis":
		if c.Store.Addr == "" {
			return fmt.Errorf("store.addr is required for the redis backend")
		}
	default:
		return fmt.Errorf("store.backend must be memory, buntdb, pebble or redis, got %q", c.Store.Backend)
	}
	if err := c.Enforcement.validate(); err != nil {
		return err
	}
	if err := c.AttackMode.validate(); err != nil {
		return err
	}
	if err := c.Reputation.validate(); err != nil {
		return err
	}

	// defaults: is decoded here rather than by the top-level decoder so its
	// paths: overlays can be split off first. Everything below this point reads
	// c.Defaults, so it has to happen before the first default is filled in.
	defaultPathsNode := splitPathsNode(&c.DefaultsNode)
	if c.DefaultsNode.Kind != 0 && c.DefaultsNode.Tag != "!!null" {
		if err := decodeStrict(&c.DefaultsNode, &c.Defaults); err != nil {
			return fmt.Errorf("defaults: %w", err)
		}
	}
	defaultPaths, err := pathNodes("defaults", defaultPathsNode)
	if err != nil {
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
	if c.Defaults.PoW.IssuanceRateLimit.Count == 0 {
		c.Defaults.PoW.IssuanceRateLimit = Rate{Count: 60, Per: time.Minute}
	}
	// The two ends of the repeat-offender ladder are chosen together: blocks
	// double from BlockTTL up to MaxBlockTTL, so 30m/12h walks
	// 30m -> 1h -> 2h -> 4h -> 8h -> 12h and reaches the cap on the sixth
	// offense. Raising the cap alone would only add rungs past the point where
	// blkct: (24h retention) expires and restarts the ladder anyway.
	if c.Defaults.WAF.IPBehaviour.BlockTTL == 0 {
		c.Defaults.WAF.IPBehaviour.BlockTTL = Duration(30 * time.Minute)
	}
	if c.Defaults.WAF.IPBehaviour.MaxBlockTTL == 0 {
		c.Defaults.WAF.IPBehaviour.MaxBlockTTL = Duration(12 * time.Hour)
	}
	// The built-in thresholds merge into whatever the operator wrote (their
	// value wins per key) instead of applying only when the map is absent.
	// A nil-only fill would make `thresholds: {notfound_rate: 20/min}` silently
	// wipe tamper/pow_fail scoring — contradicting the documented "scored by
	// default" contract — and behave differently from a domain-level overlay,
	// where yaml decodes into the inherited map and entries always merge.
	if c.Defaults.WAF.IPBehaviour.Thresholds == nil {
		c.Defaults.WAF.IPBehaviour.Thresholds = make(map[string]ThresholdRate, 4)
	}
	// challenge_farm is deliberately generous: an IP only starts scoring once
	// its unsolved-challenge escalation is pinned at the difficulty ceiling
	// (12+ abandoned challenges at default difficulties, zero solves), and
	// still needs 80 further abandoned challenges within the hour. Real
	// visitors never accumulate that; write "off" to disable blocking and
	// keep the farm_detected metric only.
	for event, rate := range map[string]ThresholdRate{
		"rule_match":     {Rate{Count: 10, Per: time.Minute}},
		"pow_fail":       {Rate{Count: 10, Per: time.Minute}},
		"tamper":         {Rate{Count: 10, Per: time.Minute}},
		"bot_spoof":      {Rate{Count: 5, Per: time.Minute}},
		"challenge_farm": {Rate{Count: 80, Per: time.Hour}},
	} {
		if _, ok := c.Defaults.WAF.IPBehaviour.Thresholds[event]; !ok {
			c.Defaults.WAF.IPBehaviour.Thresholds[event] = rate
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

	// Defaults first, including their own paths: overlays, so a mistake in the
	// fleet-wide base is reported against defaults rather than against the
	// first domain that happens to inherit it. Any host that is not a
	// configured domain resolves here, and the raw Host header must never
	// become a label value.
	c.Defaults.label = "default"
	if err := c.Defaults.validate(); err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	if err := c.checkGeoRefs(&c.Defaults); err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	if err := c.resolvePaths("defaults", &c.Defaults, nil, defaultPaths); err != nil {
		return err
	}
	for i := range c.Defaults.pathOverrides {
		c.Defaults.pathOverrides[i].cfg.label = "default"
	}

	// Domain configs = defaults deep-copied, then the domain's own YAML node
	// decoded on top so only the fields it mentions are overridden. The
	// defaults' pathOverrides are unexported, so the copy carries none: every
	// domain recompiles the inherited entries over its own resolved config.
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
		var pathsNode *yaml.Node
		if node.Kind != 0 && node.Tag != "!!null" {
			pathsNode = splitPathsNode(&node)
			inheritedRuleFiles := append([]string(nil), dc.WAF.Rules.Files...)
			if err := decodeStrict(&node, dc); err != nil {
				return fmt.Errorf("domain %s: %w", host, err)
			}
			if err := appendLocalRuleFiles(&node, inheritedRuleFiles, dc); err != nil {
				return fmt.Errorf("domain %s: %w", host, err)
			}
		}
		if err := dc.validate(); err != nil {
			return fmt.Errorf("domain %s: %w", host, err)
		}
		if err := c.checkGeoRefs(dc); err != nil {
			return fmt.Errorf("domain %s: %w", host, err)
		}
		ownPaths, err := pathNodes("domain "+host, pathsNode)
		if err != nil {
			return err
		}
		if err := c.resolvePaths("domain "+host, dc, defaultPaths, ownPaths); err != nil {
			return err
		}
		key, err := stateless.NormalizeHostKey(seen, host)
		if err != nil {
			return err
		}
		// Stamp the metric label onto the config itself, and onto every path
		// overlay, so resolving a request yields the label for free instead of
		// normalizing the host a second time or threading a string through the
		// pipeline. Overlays take the host's key, never their own path.
		dc.label = key
		for i := range dc.pathOverrides {
			dc.pathOverrides[i].cfg.label = key
		}
		c.resolved[key] = dc
	}
	if err := c.validateFeatureDependencies(); err != nil {
		return err
	}
	if err := c.validateAttackDifficultyCap(); err != nil {
		return err
	}
	return nil
}

// validateAttackDifficultyCap refuses an attack_mode.effects.difficulty_cap
// below any PoW-enabled domain or path base_difficulty. Below it, the fleet
// raise would have to clamp new challenges under the domain's own base, but
// the pow_token stage verifies against that unshifted base, so a solved token
// would be rejected and the visitor trapped in a solve loop. EffectiveBits
// also floors defensively, but a config that can never take effect is an
// operator error worth failing loudly at load.
func (c *Config) validateAttackDifficultyCap() error {
	if !c.AttackMode.Enabled {
		return nil
	}
	capBits := c.AttackMode.CapBits()
	return c.eachScope(func(label, _ string, dc *DomainConfig) error {
		if dc.PoW.Enabled && dc.PoW.BaseBits() > capBits {
			return fmt.Errorf("%s: pow.base_difficulty (%v = %d bits) exceeds attack_mode.effects.difficulty_cap (%v = %d bits); raise the cap so attack mode can never issue below the domain base",
				label, dc.PoW.BaseDifficulty, dc.PoW.BaseBits(), c.AttackMode.Effects.cap(), capBits)
		}
		return nil
	})
}

// eachScope calls fn for every effective config in a stable order: the
// defaults, the defaults' path overlays, then each domain (hosts sorted) with
// its own overlays. host is the domain key, empty for the defaults and their
// overlays, which apply to arbitrary unknown hosts. Every walk that has to
// cover "everything configured anywhere" goes through this, so adding a scope
// layer cannot leave one caller silently behind. fn returning an error stops
// the walk and propagates it.
func (c *Config) eachScope(fn func(label, host string, dc *DomainConfig) error) error {
	visit := func(label, host string, dc *DomainConfig) error {
		if err := fn(label, host, dc); err != nil {
			return err
		}
		for i := range dc.pathOverrides {
			o := &dc.pathOverrides[i]
			if err := fn(label+" path "+o.key, host, o.cfg); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit("defaults", "", &c.Defaults); err != nil {
		return err
	}
	hosts := make([]string, 0, len(c.resolved))
	for host := range c.resolved {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if err := visit("domain "+host, host, c.resolved[host]); err != nil {
			return err
		}
	}
	return nil
}

// splitPathsNode removes the paths key from a defaults or domain mapping node
// and returns its value node, so the remainder decodes into DomainConfig.
// Splitting before the decode is what lets DomainConfig stay Paths-free: a
// paths key nested inside another path overlay hits the KnownFields decoder
// and fails the load.
func splitPathsNode(node *yaml.Node) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "paths" {
			paths := node.Content[i+1]
			// Build a fresh slice rather than shifting in place: node is a copy of
			// the value stored in Config.Domains, but its Content slice shares the
			// caller's backing array, so an in-place append would corrupt the map
			// entry (leaving a duplicated trailing key/value pair behind the
			// unchanged length) for anything that re-reads it later.
			rest := make([]*yaml.Node, 0, len(node.Content)-2)
			rest = append(rest, node.Content[:i]...)
			rest = append(rest, node.Content[i+2:]...)
			node.Content = rest
			return paths
		}
	}
	return nil
}

// validatePathKey checks one paths: map key. Keys are matched against the
// percent-decoded request path, so an encoded key could never match and is
// refused rather than silently dead.
func validatePathKey(key string) error {
	if key == "" || key[0] != '/' {
		return fmt.Errorf(`must start with "/"`)
	}
	if strings.ContainsAny(key, "?#") {
		return fmt.Errorf("must not contain ? or #; only the path is matched")
	}
	if decoded := stateless.DecodePath(key); decoded != key {
		return fmt.Errorf("must be written percent-decoded (matching uses the decoded request path, write %q)", decoded)
	}
	// ForPath matches against NormalizePath output, so a key that is not itself
	// a fixed point of it can never be equal to, or a prefix of, anything it is
	// compared with: "/api//v1/" and "/a/./b" are silently dead overlays. That
	// is worst for an overlay written to TIGHTEN policy, which then simply does
	// not apply, so it is an error rather than a warning. Same reasoning as the
	// percent-decoding rule above, and it has to be a separate check: Clean
	// leaves an already-decoded key alone.
	if norm := stateless.NormalizePath(key); norm != key {
		return fmt.Errorf("must be written in normalized form, or it can never match (write %q)", norm)
	}
	return nil
}

// pathNodes decodes a paths: mapping node into its per-key overlay nodes and
// checks every key once, at the scope that wrote it: a bad key under defaults:
// must name defaults, not the first domain that happens to inherit it.
func pathNodes(label string, node *yaml.Node) (map[string]yaml.Node, error) {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return nil, nil
	}
	var nodes map[string]yaml.Node
	if err := node.Decode(&nodes); err != nil {
		return nil, fmt.Errorf("%s: paths: %w", label, err)
	}
	keys := make([]string, 0, len(nodes))
	for k := range nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validatePathKey(key); err != nil {
			return nil, fmt.Errorf("%s: paths key %q: %w", label, key, err)
		}
	}
	return nodes, nil
}

// resolvePaths compiles a scope's paths: overlays from two layers: inherited
// (the defaults: paths: entries, which every domain gets) and own (the scope's
// own entries, which win key by key and field by field). Each entry deep-copies
// the already resolved config (so defaulted scalars propagate), decodes the
// inherited node and then the own node on top, and re-runs validate so compiled
// state (list prefixes, geo maps, bot needles) is rebuilt for the merged result.
// Overlays are sorted most specific first: longest bare key, an exact key before
// a prefix key of the same length, then lexicographic for determinism.
func (c *Config) resolvePaths(label string, dc *DomainConfig, inherited, own map[string]yaml.Node) error {
	if len(inherited) == 0 && len(own) == 0 {
		return nil
	}
	baseRaw, err := yaml.Marshal(dc)
	if err != nil {
		return fmt.Errorf("%s: marshal resolved config: %w", label, err)
	}
	keys := make([]string, 0, len(inherited)+len(own))
	for k := range inherited {
		keys = append(keys, k)
	}
	for k := range own {
		if _, dup := inherited[k]; !dup {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		pc := &DomainConfig{}
		if err := yaml.Unmarshal(baseRaw, pc); err != nil {
			return fmt.Errorf("%s path %s: copy config: %w", label, key, err)
		}
		for _, layer := range []map[string]yaml.Node{inherited, own} {
			node, ok := layer[key]
			if !ok || node.Kind == 0 || node.Tag == "!!null" {
				continue
			}
			inheritedRuleFiles := append([]string(nil), pc.WAF.Rules.Files...)
			if err := decodeStrict(&node, pc); err != nil {
				return fmt.Errorf("%s path %s: %w", label, key, err)
			}
			if err := appendLocalRuleFiles(&node, inheritedRuleFiles, pc); err != nil {
				return fmt.Errorf("%s path %s: %w", label, key, err)
			}
		}
		if err := pc.validate(); err != nil {
			return fmt.Errorf("%s path %s: %w", label, key, err)
		}
		if err := c.checkGeoRefs(pc); err != nil {
			return fmt.Errorf("%s path %s: %w", label, key, err)
		}
		dc.pathOverrides = append(dc.pathOverrides, pathOverride{
			key:    key,
			bare:   strings.TrimSuffix(key, "/"),
			prefix: strings.HasSuffix(key, "/"),
			cfg:    pc,
		})
	}
	sort.SliceStable(dc.pathOverrides, func(i, j int) bool {
		a, b := &dc.pathOverrides[i], &dc.pathOverrides[j]
		if len(a.bare) != len(b.bare) {
			return len(a.bare) > len(b.bare)
		}
		if a.prefix != b.prefix {
			return !a.prefix
		}
		return a.key < b.key
	})
	return nil
}

// validateFeatureDependencies rejects configurations that say a feature is
// enabled while omitting the global or per-domain resource that makes it run.
// Run after domain inheritance has been resolved so every effective config is
// checked, including Defaults (which applies to unknown hosts).
func (c *Config) validateFeatureDependencies() error {
	return c.eachScope(func(label, _ string, dc *DomainConfig) error {
		if dc.PoW.Enabled && strings.TrimSpace(c.SigningKeyFile) == "" {
			return fmt.Errorf("%s: pow is enabled but signing_key_file is not configured", label)
		}
		if dc.WAF.Anomaly.Enabled && strings.TrimSpace(dc.WAF.Anomaly.Model) == "" {
			return fmt.Errorf("%s: waf.anomaly is enabled but model is not configured", label)
		}
		if dc.WAF.Rules.Enabled && len(dc.WAF.Rules.Files) == 0 {
			return fmt.Errorf("%s: waf.rules is enabled but files is not configured", label)
		}
		if dc.Reputation.Enabled && len(c.Reputation.Feeds) == 0 {
			return fmt.Errorf("%s: reputation is enabled but no reputation.feeds are configured", label)
		}
		return nil
	})
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
	if math.IsNaN(p.BaseDifficulty) || math.IsInf(p.BaseDifficulty, 0) || p.BaseDifficulty < 1 || p.BaseDifficulty > 8 {
		return fmt.Errorf("pow.base_difficulty must be 1..8, got %v", p.BaseDifficulty)
	}
	if math.IsNaN(p.MaxDifficulty) || math.IsInf(p.MaxDifficulty, 0) || p.MaxDifficulty < p.BaseDifficulty || p.MaxDifficulty > 8 {
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
		if t.name == "token_ttl" && p.Enabled && t.d < Duration(time.Second) {
			return fmt.Errorf("pow.token_ttl must be at least 1s when pow is enabled, got %v", t.d.Std())
		}
		if t.d > maxPoWTTL {
			return fmt.Errorf("pow.%s must be <= %v, got %v", t.name, time.Duration(maxPoWTTL), t.d.Std())
		}
	}
	rules := &dc.WAF.Rules
	seenFiles := make(map[string]bool, len(rules.Files))
	for _, file := range rules.Files {
		if strings.TrimSpace(file) == "" {
			return fmt.Errorf("waf.rules.files: empty or whitespace-only entry")
		}
		if seenFiles[file] {
			return fmt.Errorf("waf.rules.files: duplicate entry %q", file)
		}
		seenFiles[file] = true
	}
	seenIDs := make(map[string]bool, len(rules.DisabledIDs))
	for _, id := range rules.DisabledIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("waf.rules.disabled_ids: empty or whitespace-only entry; every entry must be an exact rule id")
		}
		if seenIDs[id] {
			return fmt.Errorf("waf.rules.disabled_ids: duplicate entry %q", id)
		}
		seenIDs[id] = true
	}
	// Checked whether or not rules are enabled: a parked exclusion list with
	// no file to select from would activate broken policy the day the
	// layer is switched on.
	if len(rules.DisabledIDs) > 0 && len(rules.Files) == 0 {
		return fmt.Errorf("waf.rules.disabled_ids is set but files is not configured; exclusions select ids from the effective files")
	}
	rules.ruleKey = waf.VariantKey(rules.Files, rules.DisabledIDs)
	a := &dc.WAF.Anomaly
	if a.Enabled && (math.IsNaN(a.ChallengeAt) || math.IsInf(a.ChallengeAt, 0) ||
		math.IsNaN(a.DenyAt) || math.IsInf(a.DenyAt, 0) ||
		a.ChallengeAt <= 0 || a.DenyAt <= a.ChallengeAt || a.DenyAt > 1) {
		return fmt.Errorf("waf.anomaly: need 0 < challenge_at < deny_at <= 1, got %v / %v", a.ChallengeAt, a.DenyAt)
	}
	b := &dc.WAF.IPBehaviour
	if b.BlockTTL < 0 || b.MaxBlockTTL < 0 {
		return fmt.Errorf("waf.ip_behaviour: block_ttl and max_block_ttl must be >= 0, got %v / %v", b.BlockTTL.Std(), b.MaxBlockTTL.Std())
	}
	if b.MaxBlockTTL > 0 && b.BlockTTL > 0 && b.MaxBlockTTL < b.BlockTTL {
		return fmt.Errorf("waf.ip_behaviour: max_block_ttl (%v) must be >= block_ttl (%v)", b.MaxBlockTTL.Std(), b.BlockTTL.Std())
	}
	if b.BlockTTL.Std() > MaxStateTTL || b.MaxBlockTTL.Std() > MaxStateTTL {
		return fmt.Errorf("waf.ip_behaviour: block_ttl and max_block_ttl must be <= %v", MaxStateTTL)
	}
	// Honeypot trap paths go through the shared validator, so the sidecar and
	// the WASM guest (which carries a honeypot too and validated none of it)
	// cannot disagree about what a usable trap path is. Checked whether or not
	// the honeypot is enabled, so a parked block cannot go live with a broken
	// trap list.
	if err := dc.WAF.Honeypot.Validate(); err != nil {
		return err
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
	if c.GeoIP.LocationDB == "" && c.GeoIP.ASNDB == "" {
		return fmt.Errorf("geo is enabled but no geoip.location_db or geoip.asn_db is configured")
	}
	usesCountries := len(g.Deny.Countries)+len(g.Challenge.Countries)+len(g.Allow.Countries) > 0
	usesASNs := len(g.Deny.ASNs)+len(g.Challenge.ASNs)+len(g.Allow.ASNs) > 0
	if usesCountries && c.GeoIP.LocationDB == "" {
		return fmt.Errorf("geo uses country selectors but geoip.location_db is not configured")
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
		LocationDB: c.GeoIP.LocationDB,
		ASNDB:      c.GeoIP.ASNDB,
		CacheDir:   c.Reputation.CacheDir,
	}
	for _, f := range c.Reputation.Feeds {
		ic.Feeds = append(ic.Feeds, intel.FeedConfig{
			Name: f.Name, URL: f.URL, File: f.File,
			Refresh: f.Refresh.Std(), Action: f.Action,
		})
	}
	return ic
}

// EnforceConfig assembles the enforcement manager's configuration. The mirror
// mode "auto" resolves here: embedded single-instance backends (memory, buntdb,
// pebble) make the seeded mirror authoritative, while a shared store (redis)
// keeps the per-request store fallback so blocks placed by another replica bite
// before the next indexed reconcile.
func (c *Config) EnforceConfig() enforce.Config {
	mode := c.Enforcement.Mirror.Mode
	if mode == "" || mode == "auto" {
		if c.Store.Backend == "redis" {
			mode = enforce.ModeReadThrough
		} else {
			mode = enforce.ModeAuthoritative
		}
	}
	n := &c.Enforcement.NFTables
	ports := make([]uint16, 0, len(n.Ports))
	for _, p := range n.Ports {
		ports = append(ports, uint16(p))
	}
	// The kernel sees neither Host nor path, so an allowlist entry anywhere
	// in the config must win globally at that layer: union them all into the
	// never-offload filter.
	never := append(append([]netip.Prefix{}, n.neverBlock...), c.AllowlistUnion()...)
	return enforce.Config{
		KeyPrefix:         blockKeyPrefix,
		ReconcileInterval: c.Enforcement.Mirror.ReconcileInterval.Std(),
		MaxEntries:        c.Enforcement.Mirror.MaxEntries,
		Mode:              mode,
		NFTables: enforce.NFTConfig{
			Enabled:      n.Enabled,
			Mode:         n.Mode,
			Table:        n.Table,
			Hook:         n.Hook,
			Ports:        ports,
			NetNS:        n.NetNS,
			MaxEntries:   n.MaxEntries,
			MinTTL:       n.MinTTL.Std(),
			NeverBlock:   never,
			AllowPrivate: n.AllowPrivate,
		},
	}
}

// AttackModeSettings assembles the attack-mode detector's configuration from
// the loaded config, resolving the quarter-step difficulty raises to bits.
func (c *Config) AttackModeSettings() attackmode.Config {
	a := &c.AttackMode
	return attackmode.Config{
		Enabled:             a.Enabled,
		Window:              a.Window.Std(),
		MinDwell:            a.MinDwell.Std(),
		SharePosture:        a.SharePostureEnabled(),
		ChallengeRate:       perSecond(a.Signals.ChallengeRate),
		AttackChallengeRate: perSecond(a.Signals.AttackChallengeRate),
		MinSolveRatio:       a.Signals.MinSolveRatio,
		RequestRate:         perSecond(a.Signals.RequestRate),
		StoreErrorRatio:     a.Signals.StoreErrorRatio,
		StoreSlowRatio:      a.Signals.StoreSlowRatio,
		ElevatedBits:        a.ExtraBits(1),
		AttackBits:          a.ExtraBits(2),
		CapBits:             a.CapBits(),
		ForceAlways:         a.Effects.ForceAlwaysEnabled(),
		Stateless:           a.Effects.StatelessEnabled(),
	}
}

// AllowlistUnion returns every allowlist IP prefix configured anywhere:
// defaults, every domain and every path overlay. Deduplicated, order
// unspecified.
func (c *Config) AllowlistUnion() []netip.Prefix {
	seen := make(map[netip.Prefix]bool)
	_ = c.eachScope(func(_, _ string, dc *DomainConfig) error {
		for _, p := range dc.Allowlist.Prefixes() {
			seen[p] = true
		}
		return nil
	})
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// RuleVariants returns every distinct (rules files, disabled_ids) pair
// referenced by a resolved scope, for the rule cache to load, watch and
// precompile. A scope contributes when rules are enabled, or when they are
// disabled but carry exclusions: parked exclusions are still validated
// against the file so they cannot later activate broken policy. Scope labels
// are collected per variant (defaults first, then sorted hosts) so cache
// errors name who is affected.
func (c *Config) RuleVariants() []waf.VariantSpec {
	var order []string
	byKey := make(map[string]*waf.VariantSpec)
	_ = c.eachScope(func(label, _ string, dc *DomainConfig) error {
		rules := &dc.WAF.Rules
		if len(rules.Files) == 0 || (!rules.Enabled && len(rules.DisabledIDs) == 0) {
			return nil
		}
		spec, ok := byKey[rules.ruleKey]
		if !ok {
			spec = &waf.VariantSpec{Paths: rules.Files, DisabledIDs: rules.DisabledIDs}
			byKey[rules.ruleKey] = spec
			order = append(order, rules.ruleKey)
		}
		spec.Scopes = append(spec.Scopes, label)
		return nil
	})
	specs := make([]waf.VariantSpec, 0, len(order))
	for _, key := range order {
		specs = append(specs, *byKey[key])
	}
	return specs
}

// RuleFiles returns every distinct WAF rules file the rule cache would load
// and watch (see RuleVariants for the inclusion rule).
func (c *Config) RuleFiles() []string {
	seen := make(map[string]bool)
	var files []string
	for _, spec := range c.RuleVariants() {
		for _, path := range spec.Paths {
			if !seen[path] {
				seen[path] = true
				files = append(files, path)
			}
		}
	}
	return files
}

// ModelSpecs returns each distinct enabled anomaly artifact together with the
// named hosts that must exist in it. Defaults apply to arbitrary unknown hosts
// and therefore cannot contribute a finite requirement list.
func (c *Config) ModelSpecs() []anomaly.ModelSpec {
	byPath := make(map[string]map[string]bool)
	add := func(path, host string) {
		if path == "" {
			return
		}
		if byPath[path] == nil {
			byPath[path] = make(map[string]bool)
		}
		if host != "" {
			byPath[path][host] = true
		}
	}
	_ = c.eachScope(func(_, host string, dc *DomainConfig) error {
		if a := dc.WAF.Anomaly; a.Enabled {
			add(a.Model, host)
		}
		return nil
	})
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	out := make([]anomaly.ModelSpec, 0, len(paths))
	for _, path := range paths {
		hosts := make([]string, 0, len(byPath[path]))
		for host := range byPath[path] {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		out = append(out, anomaly.ModelSpec{Path: path, RequiredHosts: hosts})
	}
	return out
}

func (c *Config) ModelFiles() []string {
	specs := c.ModelSpecs()
	files := make([]string, len(specs))
	for i := range specs {
		files[i] = specs[i].Path
	}
	return files
}

// DomainViews returns the resolved per-domain configs keyed by host, for
// admin inspection. The map is the engine's own; callers must not mutate it.
func (c *Config) DomainViews() map[string]*DomainConfig {
	return c.resolved
}

// Warnings returns human-readable notes about config that is valid but almost
// certainly not what the operator intended, so guardiand can log them at startup
// (and on reload) without failing. These are not errors: the daemon runs fine,
// the setting just does nothing. Kept out of validate() because that returns a
// single fatal error; this returns a list the caller logs individually.
func (c *Config) Warnings() []string {
	var out []string
	// A honeypot with no trap paths is a no-op: CheckHoneypot returns "no match"
	// when len(Paths) == 0, so enabled: true without paths silently protects
	// nothing. Flag every scope it appears in (defaults, each domain, each path
	// overlay) so a copied example.com block does not sit enabled-but-inert.
	check := func(scope string, dc *DomainConfig) {
		if hp := dc.WAF.Honeypot; hp.Enabled && len(hp.Paths) == 0 {
			out = append(out, "waf.honeypot enabled but no paths configured for "+scope+": it has no effect (add paths, or set enabled: false)")
		}
		// pow.mode suspicion hands every challenge decision to the anomaly
		// stage, and observe_only stops that stage from reaching one, so the two
		// together leave nothing able to issue a challenge: PoW reads as enabled
		// everywhere (admin views, /admin/config) while being wholly inert.
		// validate() already requires anomaly to be enabled for suspicion; this
		// is the same requirement one level down.
		//
		// A warning and not an error, because it is a legitimate waypoint: the
		// documented rollout is to run observe_only, tune the thresholds from
		// guardian_anomaly_score, then turn it off. What is not legitimate is
		// arriving there by accident and believing PoW is on.
		if a := dc.WAF.Anomaly; dc.PoW.Enabled && dc.PoW.Mode == "suspicion" && a.Enabled && a.ObserveOnly {
			out = append(out, "pow.mode suspicion with waf.anomaly.observe_only for "+scope+
				": no challenge can be issued in this scope (the anomaly stage owns every challenge decision under suspicion, and observe_only stops it deciding), so proof of work is inert while reading as enabled")
		}
	}
	// eachScope sorts hosts, so the warning order is stable across runs (map
	// iteration is not).
	_ = c.eachScope(func(label, _ string, dc *DomainConfig) error {
		check(label, dc)
		return nil
	})
	return out
}

// BehaviourWindow is one ip_behaviour event type paired with the window its
// counter buckets by. Together they are everything needed to rebuild the ev:
// store key for an IP without enumerating the keyspace.
type BehaviourWindow struct {
	Event  string
	Window time.Duration
}

// BehaviourWindows returns every distinct event/window pair this config can
// write a behaviour counter under: the defaults, every domain, and every
// paths: overlay. Thresholds resolve per scope, so one IP can hold counters
// for the same event type bucketed several different ways, and an admin reset
// has to clear all of them. The result is sorted, so a truncated or logged
// reset reads the same way twice.
//
// A threshold of "off" (count <= 0) is skipped because recordEvents never
// writes a counter for it. ip_behaviour.enabled is deliberately not consulted:
// counters written while the layer was on outlive a reload that turns it off,
// and clearing them is still the right thing to do.
func (c *Config) BehaviourWindows() []BehaviourWindow {
	seen := make(map[BehaviourWindow]bool, 8)
	out := make([]BehaviourWindow, 0, 8)
	_ = c.eachScope(func(_, _ string, dc *DomainConfig) error {
		for event, rate := range dc.WAF.IPBehaviour.Thresholds {
			w := BehaviourWindow{Event: event, Window: rate.Per}
			if rate.Count <= 0 || rate.Per <= 0 || seen[w] {
				continue
			}
			seen[w] = true
			out = append(out, w)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Event != out[j].Event {
			return out[i].Event < out[j].Event
		}
		return out[i].Window < out[j].Window
	})
	return out
}

// DomainFor returns the resolved config for a host, falling back to Defaults
// for unknown hosts. The host may carry a port suffix and any case.
func (c *Config) DomainFor(host string) *DomainConfig {
	if dc, ok := c.resolved[normalizeHost(host)]; ok {
		return dc
	}
	return &c.Defaults
}

// ForPath returns the config for a percent-decoded request path: the most
// specific matching paths: overlay, or dc itself when none matches. Overlays
// are pre-sorted most specific first, so the first hit wins. A prefix key
// also matches its own bare path (/api/ matches /api), mirroring
// stateless.MatchPathList.
func (dc *DomainConfig) ForPath(decodedPath string) *DomainConfig {
	for i := range dc.pathOverrides {
		o := &dc.pathOverrides[i]
		if o.prefix {
			if strings.HasPrefix(decodedPath, o.key) || decodedPath == o.bare {
				return o.cfg
			}
		} else if decodedPath == o.key {
			return o.cfg
		}
	}
	return dc
}

// ConfigFor resolves a host plus request URI to the effective config. The
// path is matched percent-decoded and dot-segment-normalized (what Angie will
// actually serve), so neither an encoded /api%2Fv1/ nor a /api/../secret can
// dodge or hijack a path override.
func (c *Config) ConfigFor(host, uri string) *DomainConfig {
	return c.DomainFor(host).ForPath(stateless.NormalizePath(stateless.RequestPath(uri)))
}

// scopeForRequest resolves both the host and the path for one request, reusing
// the request's memoized normalized path so the pipeline stages that match on
// it do not each recompute it. The returned config carries its own metric
// label (see DomainConfig.label), so the host is normalized once per request
// and nothing else has to be carried alongside it.
func (c *Config) scopeForRequest(req *RequestContext) *DomainConfig {
	return c.DomainFor(req.Host).ForPath(req.NormalizedPath())
}

// PoWAnywhere reports whether PoW is enabled at the domain level or in any of
// its path overlays. The redeem endpoint gates on it: a solve may belong to
// any path's policy, and the challenge record decides which.
func (dc *DomainConfig) PoWAnywhere() bool {
	if dc.PoW.Enabled {
		return true
	}
	for i := range dc.pathOverrides {
		if dc.pathOverrides[i].cfg.PoW.Enabled {
			return true
		}
	}
	return false
}

// PathOverrideView is one compiled per-path overlay, for admin inspection.
type PathOverrideView struct {
	Path   string
	Config *DomainConfig
}

// PathOverrideViews returns the domain's compiled path overlays in lookup
// order (most specific first). Callers must not mutate the configs.
func (dc *DomainConfig) PathOverrideViews() []PathOverrideView {
	if len(dc.pathOverrides) == 0 {
		return nil
	}
	views := make([]PathOverrideView, len(dc.pathOverrides))
	for i := range dc.pathOverrides {
		views[i] = PathOverrideView{Path: dc.pathOverrides[i].key, Config: dc.pathOverrides[i].cfg}
	}
	return views
}

// DomainLabel maps a request host to a bounded metric label: the normalized
// key of a configured domain, or "default" for anything else. The raw Host
// header is client-controlled and unbounded, so it must never be a label value
// directly — a flood of distinct Host headers would otherwise explode the
// Prometheus series count and OOM both this process and the scrape target.
func (c *Config) DomainLabel(host string) string { return c.DomainFor(host).label }

// MetricLabel is the same bounded label read off a config a caller already
// resolved, so a hot-ish path that has done its DomainFor lookup does not pay
// for a second one. Path overlays carry their host's label (a path is
// client-controlled and could never be one), so this is correct at any scope.
func (dc *DomainConfig) MetricLabel() string { return dc.label }

func normalizeHost(host string) string { return stateless.NormalizeHost(host) }

func validateListenAddress(field, addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s must be a host:port listen address: %w", field, err)
	}
	if port == "" {
		return fmt.Errorf("%s must include a numeric port", field)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("%s port must be a number from 0 through 65535, got %q", field, port)
	}
	return nil
}

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
