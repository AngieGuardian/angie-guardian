// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"bytes"
	"container/heap"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/melroy89/angie-guardian/core/stateless"
)

const (
	MaxLogLineBytes = 1 << 20
	maxHostBytes    = 255
	maxMethodBytes  = 32
	maxURIBytes     = 64 << 10
	maxUABytes      = 16 << 10
)

// LogRecord is the strict subset of deploy/angie-json-log.conf used by the
// trainer. UserAgent may be empty; every field must nevertheless be present.
type LogRecord struct {
	Host           string `json:"host"`
	Method         string `json:"method"`
	URI            string `json:"uri"`
	Status         int    `json:"status"`
	UserAgent      string `json:"user_agent"`
	GuardianAction string `json:"guardian_action"`
}

// ParseLogRecord validates one complete JSON log line, including duplicate
// top-level fields. Unknown fields are allowed so the log format can grow.
func ParseLogRecord(line []byte) (LogRecord, error) {
	var rec LogRecord
	if len(line) > MaxLogLineBytes {
		return rec, fmt.Errorf("line exceeds %d bytes", MaxLogLineBytes)
	}
	if !utf8.Valid(line) {
		return rec, fmt.Errorf("line is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	if err != nil {
		return rec, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return rec, fmt.Errorf("record must be a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return rec, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return rec, fmt.Errorf("object key is not a string")
		}
		if _, duplicate := fields[key]; duplicate {
			return rec, fmt.Errorf("duplicate field %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return rec, fmt.Errorf("field %q: %w", key, err)
		}
		fields[key] = raw
	}
	if _, err := dec.Token(); err != nil {
		return rec, err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return rec, err
		}
		return rec, fmt.Errorf("trailing JSON value %v", tok)
	}

	requireString := func(name string, dst *string) error {
		raw, ok := fields[name]
		if !ok {
			return fmt.Errorf("missing required field %q", name)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return fmt.Errorf("field %q must be a string", name)
		}
		return nil
	}
	for name, dst := range map[string]*string{
		"host": &rec.Host, "method": &rec.Method, "uri": &rec.URI,
		"user_agent": &rec.UserAgent, "guardian_action": &rec.GuardianAction,
	} {
		if err := requireString(name, dst); err != nil {
			return rec, err
		}
	}
	rawStatus, ok := fields["status"]
	if !ok {
		return rec, fmt.Errorf("missing required field %q", "status")
	}
	if err := json.Unmarshal(rawStatus, &rec.Status); err != nil {
		return rec, fmt.Errorf("field %q must be an integer", "status")
	}

	rawHost := rec.Host
	rec.Host = stateless.NormalizeHost(rawHost)
	rec.Method = strings.ToUpper(rec.Method)
	if strings.TrimSpace(rawHost) != rawHost || strings.ContainsAny(rawHost, "/\\?#@") ||
		strings.IndexFunc(rawHost, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 ||
		rec.Host == "" || len(rec.Host) > maxHostBytes {
		return rec, fmt.Errorf("host must normalize to 1..%d bytes", maxHostBytes)
	}
	if !validMethod(rec.Method) || len(rec.Method) > maxMethodBytes {
		return rec, fmt.Errorf("method %q is not a valid HTTP token of at most %d bytes", rec.Method, maxMethodBytes)
	}
	if len(rec.URI) == 0 || len(rec.URI) > maxURIBytes ||
		(rec.URI != "*" && (rec.URI[0] != '/' || !validRequestURI(rec.URI))) {
		return rec, fmt.Errorf("uri must be /-absolute or * and at most %d bytes", maxURIBytes)
	}
	if len(rec.UserAgent) > maxUABytes {
		return rec, fmt.Errorf("user_agent exceeds %d bytes", maxUABytes)
	}
	if rec.Status < 100 || rec.Status > 599 {
		return rec, fmt.Errorf("status %d is outside 100..599", rec.Status)
	}
	switch rec.GuardianAction {
	case "allow", "challenge", "deny", "shed", "refuse":
	default:
		return rec, fmt.Errorf("guardian_action must be allow, challenge, deny, shed, or refuse")
	}
	return rec, nil
}

func validRequestURI(uri string) bool {
	_, err := url.ParseRequestURI(uri)
	return err == nil
}

func validMethod(method string) bool {
	if method == "" {
		return false
	}
	for i := 0; i < len(method); i++ {
		c := method[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

type FilterReason string

const (
	FilterIncluded FilterReason = "included"
	FilterStatus   FilterReason = "status"
	FilterAction   FilterReason = "action"
)

func Eligible(rec *LogRecord) FilterReason {
	if rec.Status >= 400 {
		return FilterStatus
	}
	if rec.GuardianAction != "" && rec.GuardianAction != "allow" {
		return FilterAction
	}
	return FilterIncluded
}

// SegmentKey selects an automatic specialised baseline.
type SegmentKey struct {
	Method string
	Route  string
}

func SegmentKeys(rec *LogRecord) [3]SegmentKey {
	method := strings.ToUpper(rec.Method)
	if method == "" {
		method = "GET"
	}
	path := rec.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	route := routeKey(stateless.DecodePath(path))
	return [3]SegmentKey{{Method: method, Route: route}, {Route: route}, {Method: method}}
}

// SegmentSelector is a bounded deterministic Space-Saving heavy-hitter pass.
type SegmentSelector struct {
	capacity int
	domains  map[string]*selectorDomain
}

func NewSegmentSelector(maxSegments int) *SegmentSelector {
	capacity := max(1, maxSegments*4)
	return &SegmentSelector{capacity: capacity, domains: make(map[string]*selectorDomain)}
}

type selectorCounter struct {
	key   SegmentKey
	count int64
	index int
}

type selectorDomain struct {
	counters map[SegmentKey]*selectorCounter
	minimums selectorHeap
}

type selectorHeap []*selectorCounter

func (h selectorHeap) Len() int { return len(h) }
func (h selectorHeap) Less(i, j int) bool {
	if h[i].count != h[j].count {
		return h[i].count < h[j].count
	}
	return segmentLess(h[i].key, h[j].key)
}
func (h selectorHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *selectorHeap) Push(value any) {
	counter := value.(*selectorCounter)
	counter.index = len(*h)
	*h = append(*h, counter)
}
func (h *selectorHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	old[len(old)-1] = nil
	last.index = -1
	*h = old[:len(old)-1]
	return last
}

func (s *SegmentSelector) Observe(rec *LogRecord) {
	host := stateless.NormalizeHost(rec.Host)
	domain := s.domains[host]
	if domain == nil {
		domain = &selectorDomain{counters: make(map[SegmentKey]*selectorCounter)}
		s.domains[host] = domain
	}
	for _, key := range SegmentKeys(rec) {
		if counter := domain.counters[key]; counter != nil {
			counter.count++
			heap.Fix(&domain.minimums, counter.index)
			continue
		}
		if len(domain.counters) < s.capacity {
			counter := &selectorCounter{key: key, count: 1}
			domain.counters[key] = counter
			heap.Push(&domain.minimums, counter)
			continue
		}
		victim := domain.minimums[0]
		delete(domain.counters, victim.key)
		victim.key = key
		victim.count++
		domain.counters[key] = victim
		heap.Fix(&domain.minimums, 0)
	}
}

func (s *SegmentSelector) Selected(maxSegments int) map[string][]SegmentKey {
	out := make(map[string][]SegmentKey, len(s.domains))
	for host, domain := range s.domains {
		type entry struct {
			key SegmentKey
			n   int64
		}
		entries := make([]entry, 0, len(domain.counters))
		for key, counter := range domain.counters {
			entries = append(entries, entry{key, counter.count})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].n != entries[j].n {
				return entries[i].n > entries[j].n
			}
			return segmentLess(entries[i].key, entries[j].key)
		})
		if len(entries) > maxSegments {
			entries = entries[:maxSegments]
		}
		keys := make([]SegmentKey, len(entries))
		for i := range entries {
			keys[i] = entries[i].key
		}
		out[host] = keys
	}
	return out
}

func segmentLess(a, b SegmentKey) bool {
	if a.Method != b.Method {
		return a.Method < b.Method
	}
	return a.Route < b.Route
}

// Trainer performs the exact aggregation pass for global baselines and the
// bounded candidate segments chosen by SegmentSelector.
type Trainer struct {
	domains            map[string]*domainAggregate
	selected           map[string]map[SegmentKey]bool
	minSegmentRequests int64
}

type domainAggregate struct {
	global   *aggregate
	segments map[SegmentKey]*aggregate
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

func NewTrainer(selected map[string][]SegmentKey, minSegmentRequests int64) *Trainer {
	t := &Trainer{minSegmentRequests: minSegmentRequests}
	if len(selected) > 0 {
		t.selected = make(map[string]map[SegmentKey]bool, len(selected))
		for host, keys := range selected {
			set := make(map[SegmentKey]bool, len(keys))
			for _, key := range keys {
				set[key] = true
			}
			t.selected[host] = set
		}
	}
	return t
}

func newAggregate() *aggregate {
	return &aggregate{uaCounts: make(map[string]int64), prefixCount: make(map[string]int64)}
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

func (t *Trainer) Add(rec *LogRecord) {
	if Eligible(rec) != FilterIncluded {
		return
	}
	if t.domains == nil {
		t.domains = make(map[string]*domainAggregate)
	}
	host := stateless.NormalizeHost(rec.Host)
	d := t.domains[host]
	if d == nil {
		d = &domainAggregate{global: newAggregate(), segments: make(map[SegmentKey]*aggregate)}
		t.domains[host] = d
	}
	path, query := rec.URI, ""
	if i := strings.IndexByte(rec.URI, '?'); i >= 0 {
		path, query = rec.URI[:i], rec.URI[i+1:]
	}
	path, query = stateless.DecodePath(path), stateless.DecodeQuery(query)
	addAggregate(d.global, path, query, rec.UserAgent)
	for _, key := range SegmentKeys(rec) {
		if !t.selected[host][key] {
			continue
		}
		a := d.segments[key]
		if a == nil {
			a = newAggregate()
			d.segments[key] = a
		}
		addAggregate(a, path, query, rec.UserAgent)
	}
}

func addAggregate(a *aggregate, path, query, ua string) {
	a.n++
	a.pathDepth.add(float64(pathDepth(path)))
	a.pathLen.add(float64(len(path)))
	a.pathEntropy.add(entropy(path))
	a.queryParams.add(float64(queryParams(query)))
	a.uaCounts[uaPrefix(ua)]++
	a.prefixCount[pathPrefix(path)]++
}

func (t *Trainer) Finish(minRequests int64) *Model {
	m := &Model{Version: ModelVersion, FeatureSchema: FeatureSchema, TrainedAt: time.Now().UTC(), Domains: make(map[string]*DomainModel)}
	for host, d := range t.domains {
		if d.global.n < minRequests {
			continue
		}
		dm := &DomainModel{Baseline: finishAggregate(d.global)}
		for key, a := range d.segments {
			if a.n < t.minSegmentRequests {
				continue
			}
			dm.Segments = append(dm.Segments, Segment{Method: key.Method, Route: key.Route, Baseline: finishAggregate(a)})
		}
		sort.Slice(dm.Segments, func(i, j int) bool {
			if dm.Segments[i].Method != dm.Segments[j].Method {
				return dm.Segments[i].Method < dm.Segments[j].Method
			}
			return dm.Segments[i].Route < dm.Segments[j].Route
		})
		dm.buildIndex()
		m.Domains[host] = dm
	}
	return m
}

func finishAggregate(a *aggregate) *Baseline {
	return &Baseline{
		Requests: a.n, PathDepth: a.pathDepth.stat(), PathLen: a.pathLen.stat(),
		PathEntropy: a.pathEntropy.stat(), QueryParams: a.queryParams.stat(),
		UAFreq: toFreq(a.uaCounts, a.n), PathPrefixFreq: toFreq(a.prefixCount, a.n),
	}
}

func toFreq(counts map[string]int64, total int64) map[string]float64 {
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(counts))
	for k, v := range counts {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if len(all) > maxFreqEntries {
		all = all[:maxFreqEntries]
	}
	freq := make(map[string]float64, len(all))
	for _, e := range all {
		freq[e.k] = float64(e.v) / float64(total)
	}
	return freq
}
