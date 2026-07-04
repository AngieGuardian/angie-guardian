// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package anomaly implements the statistical baseline anomaly detector
// (plan §4.3, "start simple"): guardian-train learns per-domain traffic
// statistics offline from Angie JSON access logs and emits a compact model
// artifact; the online scorer loads it and scores each request in
// microseconds against that baseline. The artifact format is versioned so a
// future ML implementation (Isolation Forest & co.) can slot in behind the
// same Score() seam — ML stays optional.
package anomaly

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// ModelVersion is bumped when the artifact schema changes; a scorer refuses
// artifacts it does not understand rather than misinterpreting them.
const ModelVersion = 1

// Model is the trained artifact: one Baseline per domain.
type Model struct {
	Version   int                  `json:"version"`
	Kind      string               `json:"kind"` // "statistical-baseline"
	TrainedAt time.Time            `json:"trained_at"`
	Domains   map[string]*Baseline `json:"domains"`
}

// Stat is a feature's learned distribution.
type Stat struct {
	Mean float64 `json:"mean"`
	Std  float64 `json:"std"`
}

// Baseline is what "normal" looks like for one domain.
type Baseline struct {
	Requests    int64 `json:"requests"`
	PathDepth   Stat  `json:"path_depth"`
	PathLen     Stat  `json:"path_len"`
	PathEntropy Stat  `json:"path_entropy"`
	QueryParams Stat  `json:"query_params"`
	// UAFreq and PathPrefixFreq map lowered UA prefixes / first-two-segment
	// path prefixes to their observed share of traffic, top entries only.
	UAFreq         map[string]float64 `json:"ua_freq"`
	PathPrefixFreq map[string]float64 `json:"path_prefix_freq"`
}

// zCap is where a z-score saturates to feature score 1.0: four standard
// deviations from baseline is maximally weird, more adds nothing.
const zCap = 4.0

// stdFloor prevents near-constant features (tiny std) from exploding the
// z-score on any deviation.
const stdFloor = 0.5

// Feature weights; they sum to 1 so the final score stays in [0,1].
const (
	weightPathShape    = 0.35 // depth+len+entropy combined
	weightQueryParams  = 0.10
	weightUARarity     = 0.30
	weightPrefixRarity = 0.25
)

// Score rates one request against the domain baseline: 0 = perfectly
// ordinary, 1 = maximally anomalous. Unknown domains score 0 (no baseline,
// no opinion — the other pipeline stages still apply).
func (m *Model) Score(host, path, query, ua string) float64 {
	b, ok := m.Domains[strings.ToLower(host)]
	if !ok {
		return 0
	}

	pathShape := (b.PathDepth.zScore(float64(pathDepth(path))) +
		b.PathLen.zScore(float64(len(path))) +
		b.PathEntropy.zScore(entropy(path))) / 3

	score := weightPathShape*pathShape +
		weightQueryParams*b.QueryParams.zScore(float64(queryParams(query))) +
		weightUARarity*rarity(b.UAFreq, uaPrefix(ua)) +
		weightPrefixRarity*rarity(b.PathPrefixFreq, pathPrefix(path))
	return math.Min(1, score)
}

func (s Stat) zScore(x float64) float64 {
	std := math.Max(s.Std, stdFloor)
	return math.Min(1, math.Abs(x-s.Mean)/std/zCap)
}

// rarity maps an observed traffic share to [0,1]: anything that makes up
// ≥2% of baseline traffic is fully ordinary; unseen values are fully rare.
func rarity(freq map[string]float64, key string) float64 {
	return 1 - math.Min(1, freq[key]*50)
}

// --- request feature extraction (shared by trainer and scorer) -------------

func pathDepth(path string) int {
	depth := 0
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			depth++
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

// entropy is the Shannon entropy of the path's bytes — random-looking blobs
// (scanner payloads, encoded junk) score high, human URLs low.
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// uaPrefix normalizes a User-Agent to its identifying head, so version
// bumps don't turn every browser into a rarity.
func uaPrefix(ua string) string {
	ua = strings.ToLower(ua)
	if len(ua) > 24 {
		ua = ua[:24]
	}
	return ua
}

// pathPrefix is the first two path segments — the "section" of the site.
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

// --- artifact I/O -----------------------------------------------------------

func Load(path string) (*Model, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseModel(raw, path)
}

// ParseModel decodes and validates a model artifact from bytes. The cache
// uses this to parse the same bytes it hashed for change detection, avoiding
// a second read.
func ParseModel(raw []byte, path string) (*Model, error) {
	m := &Model{}
	if err := json.Unmarshal(raw, m); err != nil {
		return nil, fmt.Errorf("parse model %s: %w", path, err)
	}
	if m.Version != ModelVersion {
		return nil, fmt.Errorf("model %s: version %d, this build understands %d", path, m.Version, ModelVersion)
	}
	if m.Kind != "statistical-baseline" {
		return nil, fmt.Errorf("model %s: unknown kind %q", path, m.Kind)
	}
	return m, nil
}

func (m *Model) Save(path string) error {
	raw, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path) // atomic swap: scorers never see a half-written model
}
