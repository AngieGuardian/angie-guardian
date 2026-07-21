// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core/anomaly"
)

func validLine(host, method, uri, action string, status int) string {
	return fmt.Sprintf(`{"host":%q,"method":%q,"uri":%q,"status":%d,"user_agent":"Mozilla/5.0","guardian_action":%q}`+"\n",
		host, method, uri, status, action)
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestScanInputClosesPlainAndGzipFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file descriptor accounting uses /proc")
	}
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 100; i++ {
		path := filepath.Join(dir, fmt.Sprintf("%03d.json", i))
		if i%2 == 1 {
			path += ".gz"
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(f)
			_, _ = gz.Write([]byte(validLine("x.test", "GET", "/", "allow", 200)))
			_ = gz.Close()
			_ = f.Close()
		} else if err := os.WriteFile(path, []byte(validLine("x.test", "GET", "/", "allow", 200)), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	before, lines := openFDs(t), 0
	if err := scanInputs(paths, func(_ string, _ int64, _ []byte) error { lines++; return nil }); err != nil {
		t.Fatal(err)
	}
	after := openFDs(t)
	if after > before+2 {
		t.Fatalf("open file descriptors grew from %d to %d", before, after)
	}
	if lines != len(paths) {
		t.Fatalf("lines = %d, want %d", lines, len(paths))
	}

	wantErr := errors.New("stop")
	before = openFDs(t)
	for _, path := range paths {
		if err := scanInput(path, func(_ string, _ int64, _ []byte) error { return wantErr }); !errors.Is(err, wantErr) {
			t.Fatalf("callback error from %s = %v", path, err)
		}
	}
	after = openFDs(t)
	if after > before+2 {
		t.Fatalf("callback errors leaked file descriptors: %d -> %d", before, after)
	}
}

func TestScanInputLineSizeBoundary(t *testing.T) {
	dir := t.TempDir()
	prefix := `{"host":"x.test","method":"GET","uri":"/","status":200,"user_agent":"x","guardian_action":"allow","padding":"`
	suffix := `"}`
	line := prefix + strings.Repeat("x", anomaly.MaxLogLineBytes-len(prefix)-len(suffix)) + suffix
	if len(line) != anomaly.MaxLogLineBytes {
		t.Fatalf("test line length = %d", len(line))
	}

	path := filepath.Join(dir, "limit.json")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var scanned int
	if err := scanInput(path, func(_ string, _ int64, raw []byte) error {
		scanned++
		_, err := anomaly.ParseLogRecord(raw)
		return err
	}); err != nil {
		t.Fatalf("exact-limit line rejected: %v", err)
	}
	if scanned != 1 {
		t.Fatalf("scanned %d lines, want 1", scanned)
	}

	if err := os.WriteFile(path, []byte(line[:len(line)-len(suffix)]+"x"+suffix+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scanInput(path, func(_ string, _ int64, _ []byte) error { return nil }); err == nil {
		t.Fatal("over-limit line unexpectedly scanned")
	}
}

func TestTrainCommandStrictFilteringAndArtifact(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.json")
	var log bytes.Buffer
	for i := 0; i < 20; i++ {
		log.WriteString(validLine("shop.test", "GET", fmt.Sprintf("/shop/item-%d", i%3), "allow", 200))
	}
	log.WriteString(validLine("shop.test", "GET", "/scanner", "challenge", 302))
	log.WriteString(validLine("shop.test", "GET", "/missing", "allow", 404))
	if err := os.WriteFile(logPath, log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out, report := filepath.Join(dir, "model.json"), filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"train", "-out", out, "-report", report, "-min-requests", "10",
		"-min-segment-requests", "5", "-require-domain", "shop.test", logPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("train exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("20 included, 1 status-filtered, 1 action-filtered")) {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	compareReport := filepath.Join(dir, "comparison.json")
	code = run([]string{"compare", "-current", out, "-candidate", out,
		"-report", compareReport, "-min-requests", "10", logPath}, &stdout, &stderr)
	if code != 0 || !bytes.Contains(stdout.Bytes(), []byte("candidate comparison passed")) {
		t.Fatalf("compare exit %d: stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(compareReport); err != nil {
		t.Fatal(err)
	}
}

func TestScanEligibleInputsRevalidatesEachPass(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.json")
	if err := os.WriteFile(logPath, []byte(
		validLine("shop.test", "GET", "/", "allow", 200)+
			`{"host":"shop.test","method":"G ET","uri":"/","status":200,"user_agent":"x","guardian_action":"allow"}`+"\n"+
			validLine("shop.test", "GET", "/missing", "allow", 404)), 0o600); err != nil {
		t.Fatal(err)
	}

	for pass := 1; pass <= 2; pass++ {
		stats := inputStats{}
		var included int
		if err := scanEligibleInputs([]string{logPath}, &stats, &bytes.Buffer{}, func(*anomaly.LogRecord) {
			included++
		}); err != nil {
			t.Fatal(err)
		}
		if stats.InvalidSchema != 1 || stats.Included != 1 || stats.FilteredStatus != 1 || included != 1 {
			t.Fatalf("pass %d stats = %#v, observed=%d", pass, stats, included)
		}
	}
}

func TestTrainCommandRejectsInvalidSchema(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(logPath, []byte(`{"host":"x.test"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"train", "-out", filepath.Join(dir, "model.json"), "-min-requests", "1", logPath}, &stdout, &stderr); code == 0 {
		t.Fatal("invalid schema unexpectedly trained")
	}
}

func TestVersionAcceptsSingleAndDoubleDash(t *testing.T) {
	for _, flag := range []string{"-version", "--version"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{flag}, &stdout, &stderr); code != 0 || stdout.String() != "guardian-train dev\n" {
			t.Errorf("%s: exit=%d stdout=%q stderr=%q", flag, code, stdout.String(), stderr.String())
		}
	}
}
