// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core/stateless"
)

// LogRecord is one Angie access-log line in the guardian_json format
// (deploy/angie-json-log.conf).
type LogRecord struct {
	Host      string `json:"host"`
	URI       string `json:"uri"`
	UserAgent string `json:"user_agent"`
	Status    int    `json:"status"`
}

// Trainer aggregates log records into per-domain baselines using streaming
// (Welford) statistics — memory stays flat no matter how large the logs are,
// except for the frequency tables, which are pruned on Finish.
type Trainer struct {
	domains map[string]*aggregate
}

type aggregate struct {
	n           int64
	pathDepth   welford
	pathLen     welford
	pathEntropy welford
	queryParams welford
	uaCounts    map[string]int64
	prefixCount map[string]int64
}

type welford struct {
	n    int64
	mean float64
	m2   float64
}

func (w *welford) add(x float64) {
	w.n++
	d := x - w.mean
	w.mean += d / float64(w.n)
	w.m2 += d * (x - w.mean)
}

func (w *welford) stat() Stat {
	if w.n < 2 {
		return Stat{Mean: w.mean}
	}
	return Stat{Mean: w.mean, Std: math.Sqrt(w.m2 / float64(w.n-1))}
}

// Add feeds one log line into the baseline. Error responses (4xx/5xx) are
// skipped: the baseline should model what normal, successful traffic looks
// like, not the scanners already probing the site.
func (t *Trainer) Add(rec *LogRecord) {
	if rec.Host == "" || rec.Status >= 400 {
		return
	}
	if t.domains == nil {
		t.domains = make(map[string]*aggregate)
	}
	host := stateless.NormalizeHost(rec.Host)
	agg, ok := t.domains[host]
	if !ok {
		agg = &aggregate{uaCounts: make(map[string]int64), prefixCount: make(map[string]int64)}
		t.domains[host] = agg
	}

	path, query := rec.URI, ""
	if i := strings.IndexByte(rec.URI, '?'); i >= 0 {
		path, query = rec.URI[:i], rec.URI[i+1:]
	}
	// The online anomaly stage scores the percent-decoded path and query. Train
	// on that exact representation too: Angie logs $request_uri in its escaped
	// form, and allowing the two sides to drift would make ordinary encoded URLs
	// look anomalous at runtime (or teach a different query-parameter count).
	path = stateless.DecodePath(path)
	query = stateless.DecodeQuery(query)

	agg.n++
	agg.pathDepth.add(float64(pathDepth(path)))
	agg.pathLen.add(float64(len(path)))
	agg.pathEntropy.add(entropy(path))
	agg.queryParams.add(float64(queryParams(query)))
	agg.uaCounts[uaPrefix(rec.UserAgent)]++
	agg.prefixCount[pathPrefix(path)]++
}

// maxFreqEntries caps the per-domain frequency tables in the artifact.
const maxFreqEntries = 1000

// Finish builds the model artifact. Domains with fewer than minRequests
// lines are dropped — a thin baseline misclassifies everything.
func (t *Trainer) Finish(minRequests int64) *Model {
	m := &Model{
		Version:   ModelVersion,
		Kind:      "statistical-baseline",
		TrainedAt: time.Now().UTC(),
		Domains:   make(map[string]*Baseline),
	}
	for host, agg := range t.domains {
		if agg.n < minRequests {
			continue
		}
		m.Domains[host] = &Baseline{
			Requests:       agg.n,
			PathDepth:      agg.pathDepth.stat(),
			PathLen:        agg.pathLen.stat(),
			PathEntropy:    agg.pathEntropy.stat(),
			QueryParams:    agg.queryParams.stat(),
			UAFreq:         toFreq(agg.uaCounts, agg.n),
			PathPrefixFreq: toFreq(agg.prefixCount, agg.n),
		}
	}
	return m
}

// toFreq converts counts to traffic shares, keeping only the most common
// entries (everything pruned is by definition rare, which is exactly what
// an absent key means to the scorer).
func toFreq(counts map[string]int64, total int64) map[string]float64 {
	if len(counts) > maxFreqEntries {
		type kv struct {
			k string
			v int64
		}
		all := make([]kv, 0, len(counts))
		for k, v := range counts {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
		counts = make(map[string]int64, maxFreqEntries)
		for _, e := range all[:maxFreqEntries] {
			counts[e.k] = e.v
		}
	}
	freq := make(map[string]float64, len(counts))
	for k, v := range counts {
		freq[k] = float64(v) / float64(total)
	}
	return freq
}
