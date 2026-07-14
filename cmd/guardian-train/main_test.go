// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/melroy89/angie-guardian/core/anomaly"
)

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestAddTrainingInputClosesEachFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file descriptor accounting uses /proc")
	}
	dir := t.TempDir()
	paths := make([]string, 200)
	for i := range paths {
		paths[i] = filepath.Join(dir, string(rune('a'+i%26))+"-input.json")
		// Reuse names across groups; the close invariant is independent of content.
		if err := os.WriteFile(paths[i], []byte("not-json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := openFDs(t)
	trainer := &anomaly.Trainer{}
	var lines, badLines int64
	for _, path := range paths {
		if err := addTrainingInput(path, trainer, &lines, &badLines); err != nil {
			t.Fatal(err)
		}
	}
	after := openFDs(t)
	if after > before+2 {
		t.Fatalf("open file descriptors grew from %d to %d", before, after)
	}
	if lines != 200 || badLines != 200 {
		t.Fatalf("lines/badLines = %d/%d, want 200/200", lines, badLines)
	}
}
