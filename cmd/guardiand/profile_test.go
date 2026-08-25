// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingProfileWriter struct{ err error }

func (w failingProfileWriter) Write([]byte) (int, error) { return 0, w.err }

func TestStartProfilerRequiresEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startProfiler(dir); err == nil {
		t.Fatal("startProfiler accepted a non-empty directory")
	}
}

func TestProfilerStopReturnsSampleWriteError(t *testing.T) {
	p, err := startProfiler(filepath.Join(t.TempDir(), "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("disk full")
	p.recordWriteErr(want)
	if err := p.stop(); !errors.Is(err, want) {
		t.Fatalf("stop error = %v, want disk-full write error", err)
	}
}

func TestProfilerRetainsJSONLSampleWriteError(t *testing.T) {
	want := errors.New("disk full")
	p := &profiler{sampleOut: failingProfileWriter{err: want}}
	p.writeSample()
	if err := p.sampleWriteErr(); !errors.Is(err, want) {
		t.Fatalf("sample write error = %v, want disk-full error", err)
	}
}

func TestStartProfilerCreatesArtifacts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles")
	p, err := startProfiler(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.stop(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cpu.pprof", "samples.jsonl", "flight.trace", "heap.pprof", "allocs.pprof", "mutex.pprof", "block.pprof", "goroutineleak.pprof"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}
