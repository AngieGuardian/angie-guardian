// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package anomaly implements Guardian's offline-trained statistical anomaly
// model and its bounded online scorer.
package anomaly

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/melroy89/angie-guardian/core/stateless"
	"github.com/melroy89/angie-guardian/internal/safefile"
)

const (
	// ModelVersion and FeatureSchema version both the JSON shape and the exact
	// feature semantics. A model is useful only when trainer and scorer agree.
	ModelVersion  = 2
	FeatureSchema = "decoded-uri-method-route"

	maxModelBytes       = 64 << 20
	maxArtifactSegments = 4096
	maxFreqEntries      = 1000
)

// Model is the complete trained artifact.
type Model struct {
	Version       int                     `json:"version"`
	FeatureSchema string                  `json:"feature_schema"`
	TrainedAt     time.Time               `json:"trained_at"`
	Domains       map[string]*DomainModel `json:"domains"`
}

// DomainModel contains a mandatory domain-wide baseline and optional bounded
// route/method specialisations.
type DomainModel struct {
	Baseline *Baseline `json:"baseline"`
	Segments []Segment `json:"segments,omitempty"`

	index map[SegmentKey]*Baseline
}

// Segment identifies one specialised baseline. Empty Method means route-only;
// empty Route means method-only. Both populated means an exact combination.
type Segment struct {
	Method   string    `json:"method,omitempty"`
	Route    string    `json:"route,omitempty"`
	Baseline *Baseline `json:"baseline"`
}

// Stat is a numeric feature's learned distribution.
type Stat struct {
	Mean float64 `json:"mean"`
	Std  float64 `json:"std"`
}

// Baseline is what ordinary traffic looks like for one domain or segment.
type Baseline struct {
	Requests       int64              `json:"requests"`
	PathDepth      Stat               `json:"path_depth"`
	PathLen        Stat               `json:"path_len"`
	PathEntropy    Stat               `json:"path_entropy"`
	QueryParams    Stat               `json:"query_params"`
	UAFreq         map[string]float64 `json:"ua_freq"`
	PathPrefixFreq map[string]float64 `json:"path_prefix_freq"`
}

// ScoreResult makes absence and fallback explicit instead of conflating a
// missing baseline with a perfectly ordinary score of zero.
type ScoreResult struct {
	Score float64
	Found bool
	Level string // exact | route | method | domain | missing
	Route string
}

const (
	zCap               = 4.0
	stdFloor           = 0.5
	weightPathShape    = 0.35
	weightQueryParams  = 0.10
	weightUARarity     = 0.30
	weightPrefixRarity = 0.25
	uaPrefixBytes      = 24
)

// Score selects the most specific sufficiently-trained baseline and scores a
// request against it. path and query must already be percent-decoded.
func (m *Model) Score(host, method, path, query, ua string) ScoreResult {
	d, ok := m.Domains[stateless.NormalizeHost(host)]
	if !ok || d == nil || d.Baseline == nil {
		return ScoreResult{Level: "missing", Route: routeKey(path)}
	}
	method = strings.ToUpper(method)
	route := routeKey(path)
	b, level := d.Baseline, "domain"
	if candidate := d.lookup(method, route); candidate != nil {
		b, level = candidate, "exact"
	} else if candidate := d.lookup("", route); candidate != nil {
		b, level = candidate, "route"
	} else if candidate := d.lookup(method, ""); candidate != nil {
		b, level = candidate, "method"
	}
	return ScoreResult{Score: b.score(path, query, ua), Found: true, Level: level, Route: route}
}

func (b *Baseline) score(path, query, ua string) float64 {
	pathShape := (b.PathDepth.zScore(float64(pathDepth(path))) +
		b.PathLen.zScore(float64(len(path))) +
		b.PathEntropy.zScore(entropy(path))) / 3
	return math.Min(1,
		weightPathShape*pathShape+
			weightQueryParams*b.QueryParams.zScore(float64(queryParams(query)))+
			weightUARarity*rarity(b.UAFreq, uaPrefix(ua))+
			weightPrefixRarity*rarity(b.PathPrefixFreq, pathPrefix(path)))
}

func (s Stat) zScore(x float64) float64 {
	std := math.Max(s.Std, stdFloor)
	return math.Min(1, math.Abs(x-s.Mean)/std/zCap)
}

func rarity(freq map[string]float64, key string) float64 {
	return 1 - math.Min(1, freq[key]*50)
}

func pathDepth(path string) int {
	depth, inSegment := 0, false
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			inSegment = false
		} else if !inSegment {
			depth++
			inSegment = true
		}
	}
	return depth
}

func queryParams(query string) int {
	if query == "" {
		return 0
	}
	return strings.Count(query, "&") + 1
}

func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func uaPrefix(ua string) string {
	ua = strings.ToLower(strings.ToValidUTF8(ua, "�"))
	if len(ua) <= uaPrefixBytes {
		return ua
	}
	end := uaPrefixBytes
	for end > 0 && !utf8.ValidString(ua[:end]) {
		end--
	}
	return ua[:end]
}

func pathPrefix(path string) string {
	path = strings.ToLower(path)
	seen := 0
	for i := 1; i < len(path); i++ {
		if path[i] == '/' {
			seen++
			if seen == 2 {
				return path[:i]
			}
		}
	}
	return path
}

// routeKey deliberately uses only the first decoded segment: it is bounded
// enough to learn automatically while still separating major site surfaces.
func routeKey(path string) string {
	if path == "*" {
		return "*"
	}
	path = strings.ToLower(path)
	if path == "" || path == "/" {
		return "/"
	}
	if path[0] == '/' {
		if i := strings.IndexByte(path[1:], '/'); i >= 0 {
			return path[:i+1]
		}
		return path
	}
	trimmed := path
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		trimmed = trimmed[:i]
	}
	return "/" + trimmed
}

func (d *DomainModel) buildIndex() {
	d.index = make(map[SegmentKey]*Baseline, len(d.Segments))
	for i := range d.Segments {
		s := &d.Segments[i]
		d.index[SegmentKey{Method: s.Method, Route: s.Route}] = s.Baseline
	}
}

func (d *DomainModel) lookup(method, route string) *Baseline {
	if d.index != nil {
		return d.index[SegmentKey{Method: method, Route: route}]
	}
	// Models loaded from disk always have an index. The linear fallback keeps
	// manually assembled models race-free without mutating them during Score.
	for i := range d.Segments {
		s := &d.Segments[i]
		if s.Method == method && s.Route == route {
			return s.Baseline
		}
	}
	return nil
}

func Load(path string) (*Model, error) {
	raw, err := safefile.Read(path, maxModelBytes)
	if err != nil {
		return nil, err
	}
	return ParseModel(raw, path)
}

func ParseModel(raw []byte, path string) (*Model, error) {
	m := &Model{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("parse model %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("trailing JSON value")
		}
		return nil, fmt.Errorf("parse model %s: %w", path, err)
	}
	if m.Version != ModelVersion {
		return nil, fmt.Errorf("model %s: unsupported format version %d", path, m.Version)
	}
	if m.FeatureSchema != FeatureSchema {
		return nil, fmt.Errorf("model %s: unsupported feature schema %q", path, m.FeatureSchema)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("model %s: %w", path, err)
	}
	return m, nil
}

func (m *Model) validate() error {
	if m.Version != ModelVersion {
		return fmt.Errorf("unsupported format version %d", m.Version)
	}
	if m.FeatureSchema != FeatureSchema {
		return fmt.Errorf("unsupported feature schema %q", m.FeatureSchema)
	}
	if m.TrainedAt.IsZero() {
		return fmt.Errorf("trained_at is required")
	}
	if len(m.Domains) == 0 {
		return fmt.Errorf("no domain baselines")
	}
	normalized := make(map[string]*DomainModel, len(m.Domains))
	for host, d := range m.Domains {
		key := stateless.NormalizeHost(host)
		if key == "" {
			return fmt.Errorf("domain %q normalizes to empty", host)
		}
		if _, dup := normalized[key]; dup {
			return fmt.Errorf("domain %q: duplicate after host normalization", host)
		}
		if d == nil || d.Baseline == nil {
			return fmt.Errorf("domain %q: global baseline is required", host)
		}
		if err := d.Baseline.validate(host + " global"); err != nil {
			return err
		}
		if len(d.Segments) > maxArtifactSegments {
			return fmt.Errorf("domain %q: %d segments exceeds %d", host, len(d.Segments), maxArtifactSegments)
		}
		seen := make(map[SegmentKey]bool, len(d.Segments))
		for i := range d.Segments {
			s := &d.Segments[i]
			s.Method = strings.ToUpper(s.Method)
			s.Route = strings.ToLower(s.Route)
			if (s.Method == "" && s.Route == "") || (s.Route != "" && routeKey(s.Route) != s.Route) {
				return fmt.Errorf("domain %q segment %d: invalid method/route %q/%q", host, i, s.Method, s.Route)
			}
			if s.Method != "" && !validMethod(s.Method) {
				return fmt.Errorf("domain %q segment %d: invalid method %q", host, i, s.Method)
			}
			mapKey := SegmentKey{Method: s.Method, Route: s.Route}
			if seen[mapKey] {
				return fmt.Errorf("domain %q: duplicate segment %q/%q", host, s.Method, s.Route)
			}
			seen[mapKey] = true
			if s.Baseline == nil {
				return fmt.Errorf("domain %q segment %q/%q: baseline is required", host, s.Method, s.Route)
			}
			if err := s.Baseline.validate(fmt.Sprintf("%s segment %s/%s", host, s.Method, s.Route)); err != nil {
				return err
			}
		}
		sort.Slice(d.Segments, func(i, j int) bool {
			if d.Segments[i].Method != d.Segments[j].Method {
				return d.Segments[i].Method < d.Segments[j].Method
			}
			return d.Segments[i].Route < d.Segments[j].Route
		})
		d.buildIndex()
		normalized[key] = d
	}
	m.Domains = normalized
	return nil
}

func (b *Baseline) validate(label string) error {
	if b.Requests <= 0 {
		return fmt.Errorf("%s: requests must be positive", label)
	}
	for name, s := range map[string]Stat{
		"path_depth": b.PathDepth, "path_len": b.PathLen,
		"path_entropy": b.PathEntropy, "query_params": b.QueryParams,
	} {
		if !finite(s.Mean) || !finite(s.Std) || s.Mean < 0 || s.Std < 0 {
			return fmt.Errorf("%s %s: invalid mean/std %v/%v", label, name, s.Mean, s.Std)
		}
	}
	for name, freq := range map[string]map[string]float64{"ua_freq": b.UAFreq, "path_prefix_freq": b.PathPrefixFreq} {
		if len(freq) > maxFreqEntries {
			return fmt.Errorf("%s %s: too many entries", label, name)
		}
		for key, value := range freq {
			if !finite(value) || value < 0 || value > 1 {
				return fmt.Errorf("%s %s[%q]: invalid frequency %v", label, name, key, value)
			}
		}
	}
	return nil
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func (m *Model) Save(path string) error {
	if err := m.validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// HasDomain reports whether a usable global baseline exists for host.
func (m *Model) HasDomain(host string) bool {
	d := m.Domains[stateless.NormalizeHost(host)]
	return d != nil && d.Baseline != nil
}

// DomainSummary exposes bounded artifact metadata without returning mutable
// baseline internals.
func (m *Model) DomainSummary() map[string]int {
	out := make(map[string]int, len(m.Domains))
	for host, d := range m.Domains {
		out[host] = len(d.Segments)
	}
	return out
}
