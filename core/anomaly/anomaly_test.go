// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"fmt"
	"path/filepath"
	"testing"
)

// trainBaseline builds a model from synthetic "normal" traffic: a blog with
// shallow human URLs, one dominant browser population and a bot minority.
func trainBaseline(t *testing.T) *Model {
	t.Helper()
	tr := &Trainer{}
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
		"Mozilla/5.0 (Windows NT 10.0) Chrome/126.0",
		"Mozilla/5.0 (Macintosh) Safari/17.0",
	}
	for i := 0; i < 3000; i++ {
		tr.Add(&LogRecord{
			Host:      "Blog.Example.com",
			URI:       fmt.Sprintf("/blog/post-%d", i%40),
			UserAgent: uas[i%len(uas)],
			Status:    200,
		})
		tr.Add(&LogRecord{
			Host:      "blog.example.com",
			URI:       fmt.Sprintf("/assets/style-%d.css", i%5),
			UserAgent: uas[i%len(uas)],
			Status:    200,
		})
	}
	// Error traffic must not shape the baseline.
	for i := 0; i < 500; i++ {
		tr.Add(&LogRecord{Host: "blog.example.com", URI: "/scanner-probe", UserAgent: "evil", Status: 404})
	}
	m := tr.Finish(100)
	if _, ok := m.Domains["blog.example.com"]; !ok {
		t.Fatal("baseline for blog.example.com missing")
	}
	return m
}

func TestScoreSeparatesNormalFromAnomalous(t *testing.T) {
	m := trainBaseline(t)

	normal := m.Score("blog.example.com", "/blog/post-7", "", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
	weirdPath := m.Score("blog.example.com",
		"/cgi-bin/luci/;stok=/x?exec=1/qQfk3zqzn0KpcnNIqIz6O0aXBs1", "exec=1&cmd=wget",
		"Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
	weirdUA := m.Score("blog.example.com", "/blog/post-7", "", "python-requests/2.31")
	weirdBoth := m.Score("blog.example.com",
		"/cgi-bin/luci/;stok=/x?exec=1/qQfk3zqzn0KpcnNIqIz6O0aXBs1", "exec=1",
		"zgrab/0.x")

	t.Logf("normal=%.3f weirdPath=%.3f weirdUA=%.3f weirdBoth=%.3f", normal, weirdPath, weirdUA, weirdBoth)
	if normal >= 0.2 {
		t.Errorf("normal request scored %.3f, want < 0.2", normal)
	}
	if weirdPath <= normal+0.2 {
		t.Errorf("weird path %.3f not clearly above normal %.3f", weirdPath, normal)
	}
	if weirdUA <= normal {
		t.Errorf("rare UA %.3f not above normal %.3f", weirdUA, normal)
	}
	if weirdBoth < 0.5 {
		t.Errorf("fully anomalous request scored %.3f, want >= 0.5", weirdBoth)
	}
	if weirdBoth <= weirdPath {
		t.Errorf("anomalies should compound: both=%.3f <= path-only=%.3f", weirdBoth, weirdPath)
	}

	// Unknown domain: no baseline, no opinion.
	if s := m.Score("other.test", "/anything", "", "zgrab"); s != 0 {
		t.Errorf("unknown domain scored %.3f, want 0", s)
	}
}

func TestThinBaselinesDropped(t *testing.T) {
	tr := &Trainer{}
	for i := 0; i < 10; i++ {
		tr.Add(&LogRecord{Host: "tiny.test", URI: "/", UserAgent: "x", Status: 200})
	}
	if m := tr.Finish(100); len(m.Domains) != 0 {
		t.Fatalf("thin baseline survived: %v", m.Domains)
	}
}

func TestModelRoundTripAndVersionCheck(t *testing.T) {
	m := trainBaseline(t)
	path := filepath.Join(t.TempDir(), "model.json")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a := m.Score("blog.example.com", "/blog/post-7", "", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
	b := loaded.Score("blog.example.com", "/blog/post-7", "", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
	if a != b {
		t.Fatalf("score changed across save/load: %v != %v", a, b)
	}

	// Future-versioned artifacts are refused.
	m.Version = ModelVersion + 1
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("future model version must be refused")
	}
}

func BenchmarkScore(b *testing.B) {
	tr := &Trainer{}
	for i := 0; i < 2000; i++ {
		tr.Add(&LogRecord{Host: "bench.test", URI: fmt.Sprintf("/p/%d", i%50), UserAgent: "Mozilla/5.0 bench", Status: 200})
	}
	m := tr.Finish(100)
	b.ReportAllocs()
	for b.Loop() {
		m.Score("bench.test", "/p/7?x=1", "x=1", "Mozilla/5.0 bench")
	}
}
