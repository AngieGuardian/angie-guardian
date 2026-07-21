// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testBaseline(requests int64) *Baseline {
	return &Baseline{Requests: requests, UAFreq: map[string]float64{}, PathPrefixFreq: map[string]float64{}}
}

func TestParseLogRecordStrictSchema(t *testing.T) {
	valid := `{"host":"Example.COM:443","method":"get","uri":"/shop?q=1","status":200,"user_agent":"curl","guardian_action":"allow"}`
	rec, err := ParseLogRecord([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Host != "example.com" || rec.Method != "GET" {
		t.Fatalf("normalization = %q/%q", rec.Host, rec.Method)
	}

	for name, line := range map[string]string{
		"missing action":    `{"host":"x.test","method":"GET","uri":"/","status":200,"user_agent":"curl"}`,
		"duplicate host":    `{"host":"x.test","host":"y.test","method":"GET","uri":"/","status":200,"user_agent":"curl","guardian_action":"allow"}`,
		"bad method":        `{"host":"x.test","method":"G ET","uri":"/","status":200,"user_agent":"curl","guardian_action":"allow"}`,
		"padded host":       `{"host":" x.test ","method":"GET","uri":"/","status":200,"user_agent":"curl","guardian_action":"allow"}`,
		"relative uri":      `{"host":"x.test","method":"GET","uri":"relative","status":200,"user_agent":"curl","guardian_action":"allow"}`,
		"bad uri escape":    `{"host":"x.test","method":"GET","uri":"/bad%ZZ","status":200,"user_agent":"curl","guardian_action":"allow"}`,
		"bad action":        `{"host":"x.test","method":"GET","uri":"/","status":200,"user_agent":"curl","guardian_action":"unknown"}`,
		"trailing document": valid + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLogRecord([]byte(line)); err == nil {
				t.Fatal("record unexpectedly accepted")
			}
		})
	}
}

func TestScoreSelectsMostSpecificBaseline(t *testing.T) {
	domain := &DomainModel{Baseline: testBaseline(100), Segments: []Segment{
		{Method: "GET", Route: "/shop", Baseline: testBaseline(30)},
		{Route: "/shop", Baseline: testBaseline(40)},
		{Method: "GET", Baseline: testBaseline(50)},
	}}
	m := &Model{Domains: map[string]*DomainModel{"x.test": domain}}
	for _, tc := range []struct {
		method, path, want string
	}{
		{"GET", "/shop/item", "exact"},
		{"PUT", "/shop/item", "route"},
		{"GET", "/other", "method"},
		{"DELETE", "/other", "domain"},
	} {
		if got := m.Score("x.test", tc.method, tc.path, "", "curl"); got.Level != tc.want || !got.Found {
			t.Errorf("%s %s selected %q, found=%t; want %q", tc.method, tc.path, got.Level, got.Found, tc.want)
		}
	}
}

func TestSegmentSelectorStaysBounded(t *testing.T) {
	s := NewSegmentSelector(2)
	for i := 0; i < 100; i++ {
		s.Observe(&LogRecord{Host: "x.test", Method: "GET", URI: fmt.Sprintf("/route-%d/item", i)})
	}
	if got := len(s.domains["x.test"].counters); got > s.capacity {
		t.Fatalf("selector retained %d keys with capacity %d", got, s.capacity)
	}
	if got := len(s.Selected(2)["x.test"]); got != 2 {
		t.Fatalf("selected %d segments, want 2", got)
	}
}

func TestSegmentSelectorIsDeterministicUnderEviction(t *testing.T) {
	selectFrom := func() []SegmentKey {
		s := NewSegmentSelector(3)
		for round := 0; round < 4; round++ {
			for i := 0; i < 100; i++ {
				s.Observe(&LogRecord{Host: "x.test", Method: "GET", URI: fmt.Sprintf("/route-%d/item", (i*17+round)%23)})
			}
		}
		return s.Selected(3)["x.test"]
	}
	want := fmt.Sprint(selectFrom())
	for i := 0; i < 10; i++ {
		if got := fmt.Sprint(selectFrom()); got != want {
			t.Fatalf("selection changed across identical runs: %s != %s", got, want)
		}
	}
}

func BenchmarkSegmentSelectorCardinality(b *testing.B) {
	routes := make([]string, 2048)
	for i := range routes {
		routes[i] = fmt.Sprintf("/route-%d/item", i)
	}
	for _, tc := range []struct {
		name string
		n    int
	}{
		{name: "low", n: 16},
		{name: "high", n: len(routes)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := NewSegmentSelector(128)
			rec := &LogRecord{Host: "x.test", Method: "GET"}
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				rec.URI = routes[i%tc.n]
				s.Observe(rec)
			}
		})
	}
}

func TestComparatorReportsObservedMissingDomain(t *testing.T) {
	model := func() *Model {
		return &Model{Domains: map[string]*DomainModel{"covered.test": {Baseline: testBaseline(10)}}}
	}
	c := NewComparator(model(), model())
	c.Add(&LogRecord{Host: "missing.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
	report := c.Report(1, 1, 1, time.Now().UTC().Format(time.RFC3339Nano))
	d := report.Domains["missing.test"]
	if d == nil || d.MissingCurrent != 1 || d.MissingCandidate != 1 || d.Passed {
		t.Fatalf("missing-domain comparison = %#v", d)
	}
}

func TestComparatorAcceptsAddedAndQuietDomains(t *testing.T) {
	model := func(hosts ...string) *Model {
		domains := make(map[string]*DomainModel, len(hosts))
		for _, host := range hosts {
			domains[host] = &DomainModel{Baseline: testBaseline(100)}
		}
		return &Model{Domains: domains}
	}
	c := NewComparator(model("steady.test", "quiet.test"), model("steady.test", "quiet.test", "added.test"))
	for i := 0; i < 10; i++ {
		c.Add(&LogRecord{Host: "steady.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
		c.Add(&LogRecord{Host: "added.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
	}
	report := c.Report(10, 0, 0, time.Now().UTC().Format(time.RFC3339Nano))
	if !report.Passed {
		t.Fatalf("comparison unexpectedly failed: %#v", report.Domains)
	}
	if got := report.Domains["steady.test"].Status; got != "compared" {
		t.Fatalf("steady status = %q, want compared", got)
	}
	if got := report.Domains["quiet.test"].Status; got != "skipped" {
		t.Fatalf("quiet status = %q, want skipped", got)
	}
	added := report.Domains["added.test"]
	if added.Status != "added" || added.MissingCurrent != 10 || !added.Passed {
		t.Fatalf("added comparison = %#v", added)
	}
}

func TestComparatorRejectsRemovedDomainWithoutTraffic(t *testing.T) {
	current := &Model{Domains: map[string]*DomainModel{"removed.test": {Baseline: testBaseline(100)}}}
	candidate := &Model{Domains: map[string]*DomainModel{}}
	report := NewComparator(current, candidate).Report(10, 1, 1, time.Now().UTC().Format(time.RFC3339Nano))
	d := report.Domains["removed.test"]
	if report.Passed || d == nil || d.Passed || d.Status != "removed" {
		t.Fatalf("removed-domain comparison = %#v, report pass=%t", d, report.Passed)
	}
}

func TestParseModelRejectsTrailingDocument(t *testing.T) {
	m := &Model{Version: ModelVersion, FeatureSchema: FeatureSchema, TrainedAt: time.Now().UTC(),
		Domains: map[string]*DomainModel{"x.test": {Baseline: testBaseline(1)}}}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"version":%d,"feature_schema":%q,"trained_at":%q,"domains":{"x.test":{"baseline":{"requests":1}}}} {}`,
		ModelVersion, FeatureSchema, m.TrainedAt.Format(time.RFC3339Nano))
	if _, err := ParseModel([]byte(raw), path); err == nil {
		t.Fatal("trailing JSON document unexpectedly accepted")
	}
}

func TestModelCacheRequiresConfiguredDomains(t *testing.T) {
	m := &Model{Version: ModelVersion, FeatureSchema: FeatureSchema, TrainedAt: time.Now().UTC(),
		Domains: map[string]*DomainModel{"covered.test": {Baseline: testBaseline(1)}}}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewModelCache([]ModelSpec{{Path: path, RequiredHosts: []string{"missing.test"}}}, log); err == nil || !strings.Contains(err.Error(), "required domain") {
		t.Fatalf("required-domain error = %v", err)
	}
}

func TestModelCacheKeepsLastGoodWhenReloadLosesRequiredDomain(t *testing.T) {
	model := func(host string) *Model {
		return &Model{Version: ModelVersion, FeatureSchema: FeatureSchema, TrainedAt: time.Now().UTC(),
			Domains: map[string]*DomainModel{host: {Baseline: testBaseline(1)}}}
	}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := model("covered.test").Save(path); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewModelCache([]ModelSpec{{Path: path, RequiredHosts: []string{"covered.test"}}}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := model("other.test").Save(path); err != nil {
		t.Fatal(err)
	}
	cache.reloadChanged()
	if active := cache.Get(path); active == nil || !active.HasDomain("covered.test") {
		t.Fatalf("reload replaced the last-good required baseline: %#v", active)
	}
}
