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
		"wrong-case host":   `{"Host":"x.test","method":"GET","uri":"/","status":200,"user_agent":"curl","guardian_action":"allow"}`,
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
	invalidUTF8 := append([]byte(`{"host":"x.test","method":"GET","uri":"/","status":200,"user_agent":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`","guardian_action":"allow"}`)...)
	if _, err := ParseLogRecord(invalidUTF8); err == nil {
		t.Fatal("record with invalid UTF-8 unexpectedly accepted")
	}
}

// TestParseLogRecordAcceptsEveryEmittedAction pins the coupling between this
// validator and the actions guardiand can write into a JSON access log. An
// unrecognized action is rejected as *invalid input*, not filtered, so adding
// one to the pipeline without adding it here silently turns ordinary traffic
// into parse errors and can fail a training run on the bad-input threshold.
// `refuse` alone is a large share of lines on any host whose visitors poll
// /favicon.ico, which is exactly how it was introduced.
func TestParseLogRecordAcceptsEveryEmittedAction(t *testing.T) {
	// Keep in sync with stateless.Action, plus the transport-only "shed".
	// Not imported, because core/anomaly must not depend on the engine.
	for _, action := range []string{"allow", "challenge", "deny", "shed", "refuse"} {
		t.Run(action, func(t *testing.T) {
			line := fmt.Sprintf(`{"host":"x.test","method":"GET","uri":"/","status":200,`+
				`"user_agent":"curl","guardian_action":%q}`, action)
			rec, err := ParseLogRecord([]byte(line))
			if err != nil {
				t.Fatalf("action %q rejected as invalid input: %v", action, err)
			}
			// Being excluded from the baseline is the correct outcome for every
			// non-allow action, and is a different thing from being malformed:
			// one is expected traffic, the other counts against the run.
			want := FilterAction
			if action == "allow" {
				want = FilterIncluded
			}
			if got := Eligible(&rec); got != want {
				t.Errorf("Eligible = %q, want %q", got, want)
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

// Below-floor volume is not evidence of a coverage hole: the trainer's own
// request floor drops such domains, and an attacker-chosen Host header must
// not be able to wedge the unattended rollout gate with a handful of requests.
func TestComparatorToleratesLowVolumeUncoveredAndRemoved(t *testing.T) {
	current := &Model{Domains: map[string]*DomainModel{"dropped.test": {Baseline: testBaseline(100)}}}
	candidate := &Model{Domains: map[string]*DomainModel{}}
	c := NewComparator(current, candidate)
	for range 3 {
		c.Add(&LogRecord{Host: "stray.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
		c.Add(&LogRecord{Host: "dropped.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
	}
	report := c.Report(10, 1, 1, time.Now().UTC().Format(time.RFC3339Nano))
	if !report.Passed {
		t.Fatalf("below-floor coverage gaps must not fail the gate: %#v", report.Domains)
	}
	if got := report.Domains["stray.test"].Status; got != "uncovered" {
		t.Fatalf("stray status = %q, want uncovered", got)
	}
	if got := report.Domains["dropped.test"].Status; got != "removed" {
		t.Fatalf("dropped status = %q, want removed", got)
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

// SetRequired scopes the hard coverage failures to the operator-declared
// domains: a mid-band vhost (above the compare floor, below the train floor)
// can never gain a baseline and must not wedge unattended promotion, while a
// declared-required domain keeps failing hard. No list keeps the historical
// unscoped behavior.
func TestComparatorScopesCoverageFailuresToRequired(t *testing.T) {
	build := func() *Comparator {
		current := &Model{Domains: map[string]*DomainModel{
			"required.test": {Baseline: testBaseline(100)},
			"dropped.test":  {Baseline: testBaseline(100)},
		}}
		candidate := &Model{Domains: map[string]*DomainModel{
			"required.test": {Baseline: testBaseline(100)},
		}}
		c := NewComparator(current, candidate)
		for range 20 {
			c.Add(&LogRecord{Host: "required.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
			c.Add(&LogRecord{Host: "dropped.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
			c.Add(&LogRecord{Host: "midband.test", Method: "GET", URI: "/", Status: 200, GuardianAction: "allow"})
		}
		return c
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)

	// Unscoped (no required list): both the over-floor uncovered vhost and the
	// removed baseline fail the gate, as before.
	report := build().Report(10, 1, 1, stamp)
	if report.Passed || report.Domains["midband.test"].Passed || report.Domains["dropped.test"].Passed {
		t.Fatalf("unscoped coverage holes must fail: %#v", report.Domains)
	}

	// Scoped to required.test: the same holes no longer wedge promotion.
	c := build()
	c.SetRequired([]string{"required.test"})
	report = c.Report(10, 1, 1, stamp)
	if !report.Passed {
		t.Fatalf("scoped coverage holes must not fail: %#v", report.Domains)
	}
	if got := report.Domains["midband.test"].Status; got != "uncovered" {
		t.Fatalf("midband status = %q, want uncovered (still reported)", got)
	}
	if got := report.Domains["dropped.test"].Status; got != "removed" {
		t.Fatalf("dropped status = %q, want removed (still reported)", got)
	}

	// A required domain losing its baseline still fails hard.
	c = build()
	c.SetRequired([]string{"required.test", "dropped.test"})
	report = c.Report(10, 1, 1, stamp)
	if report.Passed || report.Domains["dropped.test"].Passed {
		t.Fatalf("required removed baseline must fail: %#v", report.Domains["dropped.test"])
	}
	if !report.Domains["midband.test"].Passed {
		t.Fatalf("unlisted midband vhost must still pass: %#v", report.Domains["midband.test"])
	}

	// Drift checks are not scoped: a required list never mutes a compared
	// domain's insufficient-records failure.
	c = build()
	c.SetRequired([]string{"required.test"})
	report = c.Report(1000, 1, 1, stamp)
	if report.Domains["required.test"].Passed {
		t.Fatalf("drift floor must stay hard on compared domains: %#v", report.Domains["required.test"])
	}
}

func TestParseModelRejectsAmbiguousInput(t *testing.T) {
	m := &Model{Version: ModelVersion, FeatureSchema: FeatureSchema, TrainedAt: time.Now().UTC(),
		Domains: map[string]*DomainModel{"x.test": {Baseline: testBaseline(1)}}}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf(`{"version":%d,"feature_schema":%q,"trained_at":%q,"domains":{"x.test":{"baseline":{"requests":1,"path_depth":{"mean":0,"std":0},"path_len":{"mean":0,"std":0},"path_entropy":{"mean":0,"std":0},"query_params":{"mean":0,"std":0},"ua_freq":{},"path_prefix_freq":{}}}}}`,
		ModelVersion, FeatureSchema, m.TrainedAt.Format(time.RFC3339Nano))
	for name, raw := range map[string][]byte{
		"trailing value":  []byte(base + ` {}`),
		"duplicate name":  []byte(strings.Replace(base, `"version":2`, `"version":2,"version":2`, 1)),
		"unknown member":  []byte(strings.Replace(base, `"feature_schema"`, `"extra":true,"feature_schema"`, 1)),
		"wrong-case name": []byte(strings.Replace(base, `"version"`, `"Version"`, 1)),
		"invalid UTF-8":   append(append([]byte(nil), []byte(base[:len(base)-2])...), 0xff, '}', '}'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseModel(raw, path); err == nil {
				t.Fatal("ambiguous model unexpectedly accepted")
			}
		})
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
