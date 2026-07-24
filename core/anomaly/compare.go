// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"math"
	"sort"
	"strings"

	"github.com/melroy89/angie-guardian/core/stateless"
)

const comparisonBuckets = 101

type Distribution struct {
	Count int64   `json:"count"`
	Mean  float64 `json:"mean"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

type DomainComparison struct {
	Status           string           `json:"status"`
	Current          Distribution     `json:"current"`
	Candidate        Distribution     `json:"candidate"`
	MeanDelta        float64          `json:"mean_delta"`
	P95Delta         float64          `json:"p95_delta"`
	CandidateLevels  map[string]int64 `json:"candidate_levels"`
	MissingCurrent   int64            `json:"missing_current"`
	MissingCandidate int64            `json:"missing_candidate"`
	Passed           bool             `json:"passed"`
	Failures         []string         `json:"failures,omitempty"`
}

type ComparisonReport struct {
	GeneratedAt  string                       `json:"generated_at"`
	MaxMeanDelta float64                      `json:"max_mean_delta"`
	MaxP95Delta  float64                      `json:"max_p95_delta"`
	MinRequests  int64                        `json:"min_requests"`
	Passed       bool                         `json:"passed"`
	Domains      map[string]*DomainComparison `json:"domains"`
}

type scoreDistribution struct {
	count   int64
	sum     float64
	buckets [comparisonBuckets]int64
}

func (d *scoreDistribution) add(score float64) {
	score = min(1, max(0, score))
	d.count++
	d.sum += score
	i := int(math.Round(score * 100))
	d.buckets[min(100, max(0, i))]++
}

func (d *scoreDistribution) result() Distribution {
	if d.count == 0 {
		return Distribution{}
	}
	return Distribution{
		Count: d.count, Mean: d.sum / float64(d.count),
		P50: d.percentile(.50), P90: d.percentile(.90),
		P95: d.percentile(.95), P99: d.percentile(.99),
	}
}

func (d *scoreDistribution) percentile(q float64) float64 {
	target := int64(math.Ceil(float64(d.count) * q))
	var cumulative int64
	for i, n := range d.buckets {
		cumulative += n
		if cumulative >= target {
			return float64(i) / 100
		}
	}
	return 1
}

type comparisonAggregate struct {
	current, candidate scoreDistribution
	levels             map[string]int64
	missingCurrent     int64
	missingCandidate   int64
}

// Comparator scores the same eligible records against two artifacts using
// bounded histograms, so comparison memory is independent of log volume.
type Comparator struct {
	Current, Candidate *Model
	domains            map[string]*comparisonAggregate
}

func NewComparator(current, candidate *Model) *Comparator {
	return &Comparator{Current: current, Candidate: candidate, domains: make(map[string]*comparisonAggregate)}
}

func (c *Comparator) Add(rec *LogRecord) {
	if Eligible(rec) != FilterIncluded {
		return
	}
	host := stateless.NormalizeHost(rec.Host)
	a := c.domains[host]
	if a == nil {
		a = &comparisonAggregate{levels: make(map[string]int64)}
		c.domains[host] = a
	}
	path, query := rec.URI, ""
	if i := strings.IndexByte(rec.URI, '?'); i >= 0 {
		path, query = rec.URI[:i], rec.URI[i+1:]
	}
	path, query = stateless.DecodePath(path), stateless.DecodeQuery(query)
	current := c.Current.Score(host, rec.Method, path, query, rec.UserAgent)
	candidate := c.Candidate.Score(host, rec.Method, path, query, rec.UserAgent)
	if current.Found {
		a.current.add(current.Score)
	} else {
		a.missingCurrent++
	}
	if candidate.Found {
		a.candidate.add(candidate.Score)
		a.levels[candidate.Level]++
	} else {
		a.missingCandidate++
	}
}

func (c *Comparator) Report(minRequests int64, maxMeanDelta, maxP95Delta float64, generatedAt string) ComparisonReport {
	report := ComparisonReport{GeneratedAt: generatedAt, MinRequests: minRequests,
		MaxMeanDelta: maxMeanDelta, MaxP95Delta: maxP95Delta, Passed: true,
		Domains: make(map[string]*DomainComparison)}
	hosts := make(map[string]bool)
	for host := range c.Current.Domains {
		hosts[host] = true
	}
	for host := range c.Candidate.Domains {
		hosts[host] = true
	}
	for host := range c.domains {
		hosts[host] = true
	}
	ordered := make([]string, 0, len(hosts))
	for host := range hosts {
		ordered = append(ordered, host)
	}
	sort.Strings(ordered)
	for _, host := range ordered {
		_, inCurrent := c.Current.Domains[host]
		_, inCandidate := c.Candidate.Domains[host]
		a := c.domains[host]
		if a == nil {
			a = &comparisonAggregate{levels: make(map[string]int64)}
		}
		d := &DomainComparison{Current: a.current.result(), Candidate: a.candidate.result(),
			CandidateLevels: a.levels, MissingCurrent: a.missingCurrent, MissingCandidate: a.missingCandidate}
		d.MeanDelta = d.Candidate.Mean - d.Current.Mean
		d.P95Delta = d.Candidate.P95 - d.Current.P95
		// Every eligible record lands in exactly one of these two per model, so
		// this is the host's total observed comparison volume.
		observed := a.current.count + a.missingCurrent
		switch {
		case !inCurrent && inCandidate:
			// Added coverage has no live distribution to regress against. Report it
			// explicitly and let the training-time request floor validate the model.
			d.Status = "added"
		case inCurrent && !inCandidate:
			d.Status = "removed"
			// The trainer drops domains below its request floor, so a low-traffic
			// domain's absence from the candidate is expected and must not wedge
			// unattended promotion week after week. Zero observed records is
			// different: the domain has a live baseline but its logs vanished
			// entirely, which points at a broken log pipeline, not low traffic.
			if observed == 0 || observed >= minRequests {
				d.Failures = append(d.Failures, "candidate removed domain baseline")
			}
		case !inCurrent && !inCandidate:
			d.Status = "uncovered"
			// In neither model: only volume at or above the comparison floor is
			// evidence of a coverage hole. Below it this is ordinary unmodeled
			// traffic — or an arbitrary attacker-chosen Host header answered by a
			// catch-all vhost — and failing would let a single stray request wedge
			// the rollout gate.
			if observed >= minRequests {
				d.Failures = append(d.Failures, "candidate missing observed domain baseline")
			}
		case d.Current.Count == 0 && d.Candidate.Count == 0:
			// A quiet domain supplies no drift evidence. Keeping it is not a
			// regression, so it must not wedge updates for active domains.
			d.Status = "skipped"
		default:
			d.Status = "compared"
			if d.Current.Count < minRequests || d.Candidate.Count < minRequests {
				d.Failures = append(d.Failures, "insufficient comparison records")
			}
			if a.missingCandidate > 0 {
				d.Failures = append(d.Failures, "candidate missing observed domain baseline")
			}
			if math.Abs(d.MeanDelta) > maxMeanDelta {
				d.Failures = append(d.Failures, "mean score drift exceeds limit")
			}
			if math.Abs(d.P95Delta) > maxP95Delta {
				d.Failures = append(d.Failures, "p95 score drift exceeds limit")
			}
		}
		d.Passed = len(d.Failures) == 0
		if !d.Passed {
			report.Passed = false
		}
		report.Domains[host] = d
	}
	return report
}
