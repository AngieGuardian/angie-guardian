// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"math"
	"testing"
	"time"
)

// FuzzParseLogRecord exercises the strict boundary between attacker-influenced
// access logs and the offline trainer. Arbitrary JSON, duplicate keys, invalid
// UTF-8, and oversized field combinations must only return a record or error.
func FuzzParseLogRecord(f *testing.F) {
	f.Add([]byte(`{"host":"x.test","method":"GET","uri":"/","status":200,"user_agent":"curl","guardian_action":"allow"}`))
	f.Add([]byte(`{"host":"x","host":"y"}`))
	f.Add([]byte("not json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseLogRecord(raw)
	})
}

// FuzzParseModel feeds arbitrary bytes to the model-artifact parser. Models
// are hot-reloaded from disk without a restart, so a malformed artifact must
// fail with an error, not panic. A model that parses is then scored against a
// request to catch a crash in the scorer reached via a valid-but-degenerate
// baseline (zero variance, NaN/Inf stats, empty freq maps).
func FuzzParseModel(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"version":2,"feature_schema":"decoded-uri-method-route","trained_at":"2026-01-01T00:00:00Z","domains":{}}`,
		`{"version":2,"feature_schema":"decoded-uri-method-route","trained_at":"2026-01-01T00:00:00Z","domains":{"x":{"baseline":{"requests":10,"path_depth":{"mean":2,"std":1},"ua_freq":{"curl":0.5}}}}}`,
		`{"version":99,"feature_schema":"decoded-uri-method-route"}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := ParseModel(raw, "fuzz")
		if err != nil {
			return
		}
		if m == nil {
			t.Fatal("ParseModel returned nil model with nil error")
		}
		// The scorer runs on the hot path against attacker-controlled request
		// fields; a parsed model must never make it panic or return NaN/Inf.
		s := score(m, "x", "/a/b/c", "q=1&r=2", "curl/8")
		if math.IsNaN(s) || math.IsInf(s, 0) {
			t.Fatalf("Score returned non-finite %v for a parsed model", s)
		}
	})
}

// FuzzScore drives the scorer directly with arbitrary request fields against a
// fixed, sane baseline, so a crash from a hostile path/query/UA (control
// bytes, huge lengths, odd unicode) surfaces independently of the parser.
func FuzzScore(f *testing.F) {
	m := &Model{
		Version: ModelVersion, FeatureSchema: FeatureSchema, TrainedAt: time.Now(),
		Domains: map[string]*DomainModel{
			"fuzz.test": {Baseline: &Baseline{
				Requests:       1000,
				PathDepth:      Stat{Mean: 2, Std: 1},
				PathLen:        Stat{Mean: 12, Std: 4},
				PathEntropy:    Stat{Mean: 3, Std: 0.5},
				QueryParams:    Stat{Mean: 1, Std: 1},
				UAFreq:         map[string]float64{"mozilla": 0.7, "curl": 0.1},
				PathPrefixFreq: map[string]float64{"/api": 0.5, "/blog": 0.3},
			}},
		},
	}
	f.Add("/a/b", "x=1", "Mozilla/5.0")
	f.Add("", "", "")
	f.Add("/\x00/\xff", "%=%&&&", "\x00\x00")
	f.Fuzz(func(t *testing.T, path, query, ua string) {
		s := score(m, "fuzz.test", path, query, ua)
		if math.IsNaN(s) || math.IsInf(s, 0) {
			t.Fatalf("Score returned non-finite %v for path=%q query=%q ua=%q", s, path, query, ua)
		}
		if s < 0 || s > 1 {
			t.Fatalf("Score %v out of [0,1] for path=%q query=%q ua=%q", s, path, query, ua)
		}
	})
}
