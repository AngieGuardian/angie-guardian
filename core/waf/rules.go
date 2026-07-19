// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package waf implements the WAF layer: keyword/regex threat signatures with
// hot reload, the behavioural IP scoreboard, and tamper-proof signed IDs.
package waf

import (
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

// RuleCache holds the compiled rule sets for every configured rules file and
// hot-reloads them when the file changes on disk. A reload that fails to
// parse keeps the last good rule set (and logs the error) rather than
// leaving the domain unprotected.
type RuleCache struct {
	files map[string]*ruleFile
	log   *slog.Logger
	stop  chan struct{}
}

type ruleFile struct {
	path string
	hash atomic.Uint64 // FNV-64a of the last loaded file contents
	set  atomic.Pointer[RuleSet]
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
// (fail fast beats silently running without signatures).
func NewRuleCache(paths []string, log *slog.Logger) (*RuleCache, error) {
	c := &RuleCache{files: make(map[string]*ruleFile, len(paths)), log: log, stop: make(chan struct{})}
	for _, path := range paths {
		f := &ruleFile{path: path}
		if _, err := f.load(); err != nil {
			return nil, err
		}
		c.files[path] = f
	}
	return c, nil
}

// load reads, compiles and installs the rules file, returning its content
// hash so the poller can record what it loaded.
func (f *ruleFile) load() (uint64, error) {
	raw, err := safefile.Read(f.path, maxRulesBytes)
	if err != nil {
		return 0, err
	}
	rs, err := compileRules(raw, f.path)
	if err != nil {
		return 0, err
	}
	hash := contentHash(raw)
	f.set.Store(rs)
	f.hash.Store(hash)
	return hash, nil
}

// Get returns the current rule set for a configured file, or nil.
func (c *RuleCache) Get(path string) *RuleSet {
	f, ok := c.files[path]
	if !ok {
		return nil
	}
	return f.set.Load()
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
		f.set.Store(rs)
		f.hash.Store(hash)
		c.log.Info("rules reloaded", "file", f.path, "rules", len(rs.Rules))
	}
}

func (c *RuleCache) Close() {
	close(c.stop)
}
