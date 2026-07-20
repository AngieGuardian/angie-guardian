// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package waf implements the WAF layer: keyword/regex threat signatures with
// hot reload, the behavioural IP scoreboard, and tamper-proof signed IDs.
package waf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/internal/safefile"
	"gopkg.in/yaml.v3"
)

const maxRulesBytes = 8 << 20

// Action is what a matching rule asks the pipeline to do.
type Action string

const (
	ActionDeny      Action = "deny"      // reject this request
	ActionChallenge Action = "challenge" // force a PoW challenge
	ActionBlock     Action = "block"     // reject and immediately block the IP
)

type target uint8

const (
	targetPath target = 1 << iota
	targetQuery
	targetUA
)

// Rule is one compiled signature. Keywords are case-insensitive literals;
// regexes are Go RE2, which is guaranteed linear-time — a rules file cannot
// introduce catastrophic backtracking (the ReDoS class from plan §11).
type Rule struct {
	ID          string
	Description string
	Action      Action

	targets  target
	headers  []string // pre-lowered header names to match against
	methods  []string // uppercased; non-empty restricts the rule to these methods
	keywords []string // pre-lowered
	regexes  []*regexp.Regexp
}

type ruleYAML struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Action      string   `yaml:"action"`
	Targets     []string `yaml:"targets"`
	Methods     []string `yaml:"methods"`
	Keywords    []string `yaml:"keywords"`
	Regexes     []string `yaml:"regexes"`
}

type rulesFileYAML struct {
	Rules []ruleYAML `yaml:"rules"`
}

// RuleSet is an immutable compiled rules file; swapped atomically on reload.
type RuleSet struct {
	Rules []Rule

	headerTargets []string // sorted union of every rule's header targets
	needsMethod   bool     // any rule carries a methods restriction
}

// HeaderTargets returns the lowered names of every header any rule in the set
// targets, so callers fetch (and lowercase) only those before Match. Callers
// must not mutate the returned slice. Nil-safe: a nil set targets nothing.
func (rs *RuleSet) HeaderTargets() []string {
	if rs == nil {
		return nil
	}
	return rs.headerTargets
}

// NeedsMethod reports whether any rule restricts by HTTP method, so callers
// that pay per request-field (the WASM guest) can skip fetching it. Nil-safe.
func (rs *RuleSet) NeedsMethod() bool {
	if rs == nil {
		return false
	}
	return rs.needsMethod
}

// MatchInput carries the pre-normalized (decoded, lowercased) request fields
// so per-rule matching does no allocation. Headers maps lowered header name to
// lowered value and only needs the names in RuleSet.HeaderTargets; Method is
// uppercase and only consulted when RuleSet.NeedsMethod.
type MatchInput struct {
	Method  string
	Path    string
	Query   string
	UA      string
	Headers map[string][]string
}

// Match returns the first matching rule, or nil.
func (rs *RuleSet) Match(in *MatchInput) *Rule {
	for i := range rs.Rules {
		if rs.Rules[i].matches(in) {
			return &rs.Rules[i]
		}
	}
	return nil
}

func (r *Rule) matches(in *MatchInput) bool {
	if len(r.methods) > 0 {
		if !slices.Contains(r.methods, in.Method) {
			return false
		}
		// A rule with methods but no patterns matches on method alone.
		if len(r.keywords) == 0 && len(r.regexes) == 0 {
			return true
		}
	}
	if r.targets&targetPath != 0 && r.matchesText(in.Path) {
		return true
	}
	if r.targets&targetQuery != 0 && r.matchesText(in.Query) {
		return true
	}
	if r.targets&targetUA != 0 && r.matchesText(in.UA) {
		return true
	}
	for _, name := range r.headers {
		for _, value := range in.Headers[name] {
			if r.matchesText(value) {
				return true
			}
		}
	}
	return false
}

func (r *Rule) matchesText(text string) bool {
	if text == "" {
		return false
	}
	for _, kw := range r.keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	for _, re := range r.regexes {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// CompileRules compiles a rules document (the same YAML format as a
// rules_file) into an immutable RuleSet. Exported for callers that hold the
// rules in memory rather than on disk, such as the WASM guest, which receives
// its rules inline in the host config. label is used only in error messages.
func CompileRules(raw []byte, label string) (*RuleSet, error) {
	return compileRules(raw, label)
}

func compileRules(raw []byte, path string) (*RuleSet, error) {
	var file rulesFileYAML
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse %s: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("parse %s trailing document: %w", path, err)
	}
	rs := &RuleSet{Rules: make([]Rule, 0, len(file.Rules))}
	seen := make(map[string]bool, len(file.Rules))
	for _, ry := range file.Rules {
		if ry.ID == "" {
			return nil, fmt.Errorf("%s: rule without id", path)
		}
		if seen[ry.ID] {
			return nil, fmt.Errorf("%s: duplicate rule id %q", path, ry.ID)
		}
		seen[ry.ID] = true
		if len(ry.Keywords) == 0 && len(ry.Regexes) == 0 {
			if len(ry.Methods) == 0 {
				return nil, fmt.Errorf("%s: rule %s has no keywords, regexes or methods", path, ry.ID)
			}
			// Methods alone are a complete rule (e.g. deny TRACE); targets
			// without patterns to match against them are a config mistake.
			if len(ry.Targets) > 0 {
				return nil, fmt.Errorf("%s: rule %s has targets but no keywords or regexes", path, ry.ID)
			}
		}

		r := Rule{ID: ry.ID, Description: ry.Description}
		switch Action(ry.Action) {
		case ActionDeny, ActionChallenge, ActionBlock:
			r.Action = Action(ry.Action)
		case "":
			r.Action = ActionDeny
		default:
			return nil, fmt.Errorf("%s: rule %s: unknown action %q", path, ry.ID, ry.Action)
		}

		if len(ry.Targets) == 0 && (len(ry.Keywords) > 0 || len(ry.Regexes) > 0) {
			r.targets = targetPath | targetQuery
		}
		for _, t := range ry.Targets {
			switch t {
			case "path":
				r.targets |= targetPath
			case "query":
				r.targets |= targetQuery
			case "ua":
				r.targets |= targetUA
			default:
				name, ok := strings.CutPrefix(t, "header:")
				name = strings.ToLower(strings.TrimSpace(name))
				if !ok || name == "" {
					return nil, fmt.Errorf("%s: rule %s: unknown target %q (want path, query, ua or header:<name>)", path, ry.ID, t)
				}
				if !slices.Contains(r.headers, name) {
					r.headers = append(r.headers, name)
				}
			}
		}

		for _, m := range ry.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m == "" {
				return nil, fmt.Errorf("%s: rule %s: empty method", path, ry.ID)
			}
			if !slices.Contains(r.methods, m) {
				r.methods = append(r.methods, m)
			}
		}

		for _, kw := range ry.Keywords {
			if strings.TrimSpace(kw) == "" {
				return nil, fmt.Errorf("%s: rule %s: empty keyword", path, ry.ID)
			}
			r.keywords = append(r.keywords, strings.ToLower(kw))
		}
		for _, expr := range ry.Regexes {
			if strings.TrimSpace(expr) == "" {
				return nil, fmt.Errorf("%s: rule %s: empty regex", path, ry.ID)
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("%s: rule %s: %w", path, ry.ID, err)
			}
			r.regexes = append(r.regexes, re)
		}
		rs.Rules = append(rs.Rules, r)
	}
	for i := range rs.Rules {
		rs.needsMethod = rs.needsMethod || len(rs.Rules[i].methods) > 0
		for _, name := range rs.Rules[i].headers {
			if !slices.Contains(rs.headerTargets, name) {
				rs.headerTargets = append(rs.headerTargets, name)
			}
		}
	}
	slices.Sort(rs.headerTargets)
	return rs, nil
}

// VariantSpec names one effective rule set to precompile: a rules file plus
// the rule IDs a resolved config scope disables from it. Scopes carries the
// config scope labels ("defaults", "domain x path /y/") that use this exact
// (file, exclusions) pair, so validation errors can name who is affected.
type VariantSpec struct {
	Path     string
	Disabled []string // exact rule IDs; empty = the full file
	Scopes   []string
}

// VariantKey canonicalizes a (rules file, disabled IDs) pair into the cache
// key RuleCache.Get expects. Exclusion order does not matter, so the IDs are
// sorted; with no exclusions the key is the bare path, which keeps plain
// file lookups working unchanged. The exclusion set is folded into a
// fixed-size, length-prefixed SHA-256 digest rather than joined verbatim:
// the request path performs one map lookup with this key, so its length (and
// thus the per-request hash/compare cost) must not scale with the number or
// size of the excluded IDs, and length-prefixing keeps the encoding
// unambiguous for IDs containing any byte (["a\x00b"] never collides with
// ["a", "b"]).
func VariantKey(path string, disabled []string) string {
	if len(disabled) == 0 {
		return path
	}
	ids := slices.Clone(disabled)
	slices.Sort(ids)
	h := sha256.New()
	var lenBuf [8]byte
	for _, id := range ids {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(id)))
		h.Write(lenBuf[:])
		h.Write([]byte(id))
	}
	return path + "\x00" + hex.EncodeToString(h.Sum(nil))
}

// filter returns a copy of the set without the disabled rules, preserving
// file order among the rest (the next matching rule still decides), or an
// error naming every disabled ID the file does not contain: an exclusion
// typo must never silently leave a rule enabled, and a watched file must not
// silently reactivate a renamed formerly-disabled rule. With no exclusions
// the set itself is returned.
func (rs *RuleSet) filter(disabled []string) (*RuleSet, error) {
	if len(disabled) == 0 {
		return rs, nil
	}
	drop := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		drop[id] = true
	}
	out := &RuleSet{Rules: make([]Rule, 0, len(rs.Rules))}
	for i := range rs.Rules {
		if drop[rs.Rules[i].ID] {
			delete(drop, rs.Rules[i].ID)
			continue
		}
		out.Rules = append(out.Rules, rs.Rules[i])
	}
	if len(drop) > 0 {
		missing := make([]string, 0, len(drop))
		for id := range drop {
			missing = append(missing, id)
		}
		slices.Sort(missing)
		return nil, fmt.Errorf("disabled_rule_ids not present in file (ids are exact and case-sensitive): %q", missing)
	}
	for i := range out.Rules {
		out.needsMethod = out.needsMethod || len(out.Rules[i].methods) > 0
		for _, name := range out.Rules[i].headers {
			if !slices.Contains(out.headerTargets, name) {
				out.headerTargets = append(out.headerTargets, name)
			}
		}
	}
	slices.Sort(out.headerTargets)
	return out, nil
}

// RuleCache holds the compiled rule sets for every configured rules file and
// hot-reloads them when the file changes on disk. Each file is read and
// watched once; per (file, disabled_rule_ids) variant a filtered rule set is
// precompiled at load/reload time, so per-request lookup stays one map access
// with no ID filtering on the hot path. A reload that fails to parse, or that
// removes a rule ID some scope still disables, keeps the last good rule sets
// (and logs the error) rather than leaving the domain unprotected or silently
// reactivating a renamed rule.
type RuleCache struct {
	files map[string]*ruleFile
	byKey map[string]*ruleVariant
	log   *slog.Logger
	stop  chan struct{}
}

type ruleFile struct {
	path     string
	hash     atomic.Uint64 // FNV-64a of the last loaded file contents
	variants []*ruleVariant
}

// ruleVariant is one precompiled effective rule set: a rules file minus the
// IDs its scopes disable. The full file is the variant with no exclusions.
type ruleVariant struct {
	key      string
	disabled []string
	scopes   []string
	set      atomic.Pointer[RuleSet]
}

// contentHash fingerprints a file by its bytes, so change detection does not
// depend on filesystem mtime resolution or file size (two same-length,
// same-mtime edits still differ in content and reload). Rules files are tiny
// and polled infrequently, so hashing them each cycle is negligible.
func contentHash(raw []byte) uint64 {
	h := fnv.New64a()
	h.Write(raw)
	return h.Sum64()
}

// NewRuleCache loads every rules file eagerly; any parse error fails startup
// (fail fast beats silently running without signatures). It keeps the
// pre-exclusions signature for downstream users: each path becomes one
// full-file variant, exactly equivalent to NewRuleCacheVariants with
// exclusion-free specs.
func NewRuleCache(paths []string, log *slog.Logger) (*RuleCache, error) {
	specs := make([]VariantSpec, 0, len(paths))
	for _, path := range paths {
		specs = append(specs, VariantSpec{Path: path})
	}
	return NewRuleCacheVariants(specs, log)
}

// NewRuleCacheVariants loads every rules file eagerly and precompiles every
// variant; any parse error or unknown disabled rule ID fails startup (fail
// fast beats silently running without signatures, or with a mistyped
// exclusion).
func NewRuleCacheVariants(specs []VariantSpec, log *slog.Logger) (*RuleCache, error) {
	c := &RuleCache{
		files: make(map[string]*ruleFile, len(specs)),
		byKey: make(map[string]*ruleVariant, len(specs)),
		log:   log,
		stop:  make(chan struct{}),
	}
	for _, spec := range specs {
		key := VariantKey(spec.Path, spec.Disabled)
		if v, ok := c.byKey[key]; ok {
			// Same file + same exclusions: one shared variant.
			v.scopes = append(v.scopes, spec.Scopes...)
			continue
		}
		f, ok := c.files[spec.Path]
		if !ok {
			f = &ruleFile{path: spec.Path}
			c.files[spec.Path] = f
		}
		v := &ruleVariant{key: key, disabled: spec.Disabled, scopes: spec.Scopes}
		f.variants = append(f.variants, v)
		c.byKey[key] = v
	}
	for _, f := range c.files {
		if _, err := f.load(); err != nil {
			return nil, err
		}
		for _, v := range f.variants {
			if len(v.disabled) > 0 {
				log.Info("waf rule exclusions active",
					"file", f.path, "disabled_rule_ids", v.disabled, "scopes", v.scopes)
			}
		}
	}
	return c, nil
}

// load reads, compiles and installs the rules file and every variant filtered
// from it, returning the content hash so the poller can record what it
// loaded. All variants are validated before any is installed, so a failure
// leaves every currently serving set unchanged.
func (f *ruleFile) load() (uint64, error) {
	raw, err := safefile.Read(f.path, maxRulesBytes)
	if err != nil {
		return 0, err
	}
	rs, err := compileRules(raw, f.path)
	if err != nil {
		return 0, err
	}
	sets := make([]*RuleSet, len(f.variants))
	for i, v := range f.variants {
		filtered, err := rs.filter(v.disabled)
		if err != nil {
			return 0, fmt.Errorf("%s (used by %s): %w", f.path, strings.Join(v.scopes, ", "), err)
		}
		sets[i] = filtered
	}
	for i, v := range f.variants {
		v.set.Store(sets[i])
	}
	hash := contentHash(raw)
	f.hash.Store(hash)
	return hash, nil
}

// Get returns the current rule set for a variant key (a bare rules file path,
// or VariantKey for a scope with exclusions), or nil.
func (c *RuleCache) Get(key string) *RuleSet {
	v, ok := c.byKey[key]
	if !ok {
		return nil
	}
	return v.set.Load()
}

// Start begins polling for file changes. Polling (rather than inotify) keeps
// it dependency-free and handles editors that replace files.
func (c *RuleCache) Start(interval time.Duration) {
	if len(c.files) == 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-t.C:
				c.reloadChanged()
			}
		}
	}()
}

func (c *RuleCache) reloadChanged() {
	for _, f := range c.files {
		raw, err := safefile.Read(f.path, maxRulesBytes)
		if err != nil {
			c.log.Warn("rules file unreadable, keeping loaded rules", "file", f.path, "err", err)
			continue
		}
		hash := contentHash(raw)
		if hash == f.hash.Load() {
			continue
		}
		rs, err := compileRules(raw, f.path)
		if err != nil {
			c.log.Error("rules reload failed, keeping previous rules", "file", f.path, "err", err)
			f.hash.Store(hash) // don't retry-spam the same broken version
			continue
		}
		// Validate every variant before installing any: an update that removes
		// or renames a rule ID some scope still disables is rejected wholesale,
		// so a formerly-disabled rule can never become active silently. To
		// intentionally delete a disabled rule, drop its ID from guardian.yaml
		// and reload first, then edit the rules file.
		sets := make([]*RuleSet, len(f.variants))
		ok := true
		for i, v := range f.variants {
			filtered, err := rs.filter(v.disabled)
			if err != nil {
				c.log.Error("rules reload rejected, keeping previous rules",
					"file", f.path, "scopes", v.scopes, "err", err)
				ok = false
				break
			}
			sets[i] = filtered
		}
		if !ok {
			f.hash.Store(hash) // don't retry-spam the same broken version
			continue
		}
		for i, v := range f.variants {
			v.set.Store(sets[i])
			if len(v.disabled) > 0 {
				c.log.Info("waf rule exclusions active",
					"file", f.path, "disabled_rule_ids", v.disabled, "scopes", v.scopes)
			}
		}
		f.hash.Store(hash)
		c.log.Info("rules reloaded", "file", f.path, "rules", len(rs.Rules))
	}
}

func (c *RuleCache) Close() {
	close(c.stop)
}
