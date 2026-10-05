// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func archiveFixture(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		data := []byte("binary-profile-fixture")
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const readyDiagnostics = `{"enabled":true,"capturing":false,"retry_after_seconds":0}`

func TestDiagnosticsCommands(t *testing.T) {
	archive := archiveFixture(t, "goroutineleak.pprof", "goroutine.pprof")
	captures := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" || r.URL.Path != diagnosticsPath || r.URL.RawQuery != "" {
			t.Error("incorrect authenticated diagnostics request")
		}
		if r.Method == "GET" {
			io.WriteString(w, readyDiagnostics)
			return
		}
		captures++
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 0 {
			t.Error("capture body must be empty")
		}
		w.Header().Set("Content-Type", "application/x-tar")
		// A malicious attachment name must not influence the chosen local path.
		w.Header().Set("Content-Disposition", `attachment; filename="../../escape.tar"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
		w.Write(archive)
	}))
	defer srv.Close()
	base := apiArgs(t, srv.URL)
	for _, asJSON := range []bool{false, true} {
		before := captures
		args := append(append([]string{}, base...), "diagnostics", "status")
		if asJSON {
			args = append(args, "--json")
		}
		code, out, err := invoke(args...)
		if code != 0 || err != "" || !strings.Contains(out, "enabled") || captures != before {
			t.Fatalf("status: %d %s %s", code, out, err)
		}
		dir := t.TempDir()
		dst := filepath.Join(dir, "profiles.tar")
		args = append(append([]string{}, base...), "diagnostics", "capture", "--out", dst)
		if asJSON {
			args = append(args, "--json")
		}
		code, out, err = invoke(args...)
		if code != 0 || err != "" {
			t.Fatalf("capture: %d %s %s", code, out, err)
		}
		got, readErr := os.ReadFile(dst)
		if readErr != nil || !bytes.Equal(got, archive) {
			t.Fatalf("download: %v", readErr)
		}
		info, _ := os.Stat(dst)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("mode %v", info.Mode())
		}
		if asJSON {
			var result map[string]any
			if err := json.Unmarshal([]byte(out), &result); err != nil || result["path"] != dst || result["bytes"] != float64(len(archive)) {
				t.Fatalf("metadata %s %v", out, err)
			}
		} else if !strings.Contains(out, "Saved "+dst) {
			t.Fatal(out)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("leftovers %v", entries)
		}
	}
}

func TestDiagnosticsUnavailable(t *testing.T) {
	cases := []struct {
		name, status            string
		getCode, postCode, want int
		retry, message          string
	}{
		{name: "disabled", status: `{"enabled":false,"capturing":false,"retry_after_seconds":0}`, want: 1, message: "restart Guardian"},
		{name: "active", status: `{"enabled":true,"capturing":true,"retry_after_seconds":0}`, want: 1, message: "already active"},
		{name: "cooldown", status: `{"enabled":true,"capturing":false,"retry_after_seconds":25}`, want: 1, message: "25 seconds"},
		{name: "old daemon", getCode: 404, want: 1, message: "upgrade Guardian"},
		{name: "unauthorized", getCode: 401, want: 3, message: "401"},
		{name: "forbidden", postCode: 403, want: 3, message: "403"},
		{name: "disable race", postCode: 404, want: 1, message: "restart Guardian"},
		{name: "active race", postCode: 409, want: 1, message: "already active"},
		{name: "cooldown race", postCode: 429, want: 1, retry: "42", message: "42 seconds"},
		{name: "capture failure", postCode: 500, want: 1, message: "500"},
		{name: "malformed status", status: `{"enabled":true}`, want: 1, message: "invalid diagnostics status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			posts := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					if tc.getCode != 0 {
						w.WriteHeader(tc.getCode)
						io.WriteString(w, `{"error":"test-secret"}`)
						return
					}
					status := tc.status
					if status == "" {
						status = readyDiagnostics
					}
					io.WriteString(w, status)
					return
				}
				posts++
				if tc.retry != "" {
					w.Header().Set("Retry-After", tc.retry)
				}
				w.WriteHeader(tc.postCode)
				io.WriteString(w, `{"error":"test-secret"}`)
			}))
			defer srv.Close()
			dir := t.TempDir()
			args := append(apiArgs(t, srv.URL), "diagnostics", "capture", "--out", filepath.Join(dir, "profiles.tar"))
			code, out, err := invoke(args...)
			if code != tc.want || out != "" || !strings.Contains(err, tc.message) || strings.Contains(err, "test-secret") {
				t.Fatalf("%d %s %s", code, out, err)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatalf("leftovers: %v", entries)
			}
			if tc.postCode == 0 && posts != 0 {
				t.Fatal("unavailable status admitted a capture")
			}
		})
	}
	// Disabled status is still a successful query.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"enabled":false,"capturing":false,"retry_after_seconds":0}`)
	}))
	defer srv.Close()
	code, out, err := invoke(append(apiArgs(t, srv.URL), "diagnostics", "status")...)
	if code != 0 || !strings.Contains(out, "restart Guardian") {
		t.Fatalf("%d %s %s", code, out, err)
	}
}

func TestDiagnosticsInvalidInput(t *testing.T) {
	for _, args := range [][]string{{"diagnostics"}, {"diagnostics", "wat"}, {"diagnostics", "capture"}, {"diagnostics", "capture", "--out", "-"}, {"diagnostics", "status", "--out", "x"}, {"diagnostics", "capture", "extra", "--out", "x"}, {"diagnostics", "capture", "--out", "x", "--timeout", "2m"}} {
		code, _, _ := invoke(args...)
		if code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
	for _, args := range [][]string{{"diagnostics", "--help"}, {"diagnostics", "capture", "--help"}, {"diagnostics", "status", "--help"}} {
		code, out, err := invoke(args...)
		if code != 0 || !strings.Contains(out, "diagnostics capture") {
			t.Errorf("%v: %d %s %s", args, code, out, err)
		}
	}
}

func TestDiagnosticsDownloadFailures(t *testing.T) {
	good := archiveFixture(t, "goroutineleak.pprof", "goroutine.pprof")
	cases := []struct {
		name, media                string
		data                       []byte
		length                     int
		want                       int
		chunked, stall, disconnect bool
	}{
		{name: "wrong content type", media: "application/json", data: good, want: 1},
		{name: "oversized", data: good, length: int(maxDiagnosticsBytes) + 1, want: 1},
		{name: "empty", length: 0, want: 1},
		{name: "chunked", data: good, chunked: true, want: 1},
		{name: "invalid tar", data: []byte("not a tar"), want: 1},
		{name: "missing profile", data: archiveFixture(t, "goroutine.pprof"), want: 1},
		{name: "extra profile", data: archiveFixture(t, "goroutineleak.pprof", "goroutine.pprof", "cpu.pprof"), want: 1},
		{name: "unsafe name", data: archiveFixture(t, "../goroutineleak.pprof", "goroutine.pprof"), want: 1},
		{name: "truncated trailer", data: good[:len(good)-512], want: 1},
		{name: "trailing junk", data: append(append([]byte{}, good...), make([]byte, 1024)...), want: 1},
		{name: "short response", data: good[:512], length: len(good), want: 4},
		{name: "timeout", data: good, stall: true, want: 4},
		{name: "disconnect", disconnect: true, want: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					io.WriteString(w, readyDiagnostics)
					return
				}
				if tc.disconnect {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				media := tc.media
				if media == "" {
					media = "application/x-tar"
				}
				w.Header().Set("Content-Type", media)
				length := tc.length
				if length == 0 {
					length = len(tc.data)
				}
				if !tc.chunked {
					w.Header().Set("Content-Length", strconv.Itoa(length))
				}
				w.WriteHeader(200)
				if tc.chunked || tc.stall {
					w.(http.Flusher).Flush()
				}
				if tc.stall {
					<-r.Context().Done()
					return
				}
				w.Write(tc.data)
			}))
			defer srv.Close()
			dir := t.TempDir()
			args := append(apiArgs(t, srv.URL), "diagnostics", "capture", "--out", filepath.Join(dir, "profiles.tar"))
			if tc.stall {
				args = append(args, "--timeout", "50ms")
			}
			code, out, err := invoke(args...)
			if code != tc.want || out != "" || err == "" {
				t.Fatalf("%d %s %s", code, out, err)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatalf("leftovers: %v", entries)
			}
		})
	}
}

func TestDiagnosticsDestinations(t *testing.T) {
	good := archiveFixture(t, "goroutineleak.pprof", "goroutine.pprof")
	for _, kind := range []string{"file", "directory", "symlink", "missing parent", "race"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "archive.tar")
			calls := 0
			switch kind {
			case "file":
				os.WriteFile(dst, []byte("original"), 0600)
			case "directory":
				os.Mkdir(dst, 0700)
			case "symlink":
				os.Symlink(filepath.Join(dir, "nonexistent"), dst)
			case "missing parent":
				dst = filepath.Join(dir, "missing", "archive.tar")
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method == "GET" {
					io.WriteString(w, readyDiagnostics)
					return
				}
				os.WriteFile(dst, []byte("racing file"), 0600)
				w.Header().Set("Content-Type", "application/x-tar")
				w.Header().Set("Content-Length", strconv.Itoa(len(good)))
				w.Write(good)
			}))
			defer srv.Close()
			code, out, err := invoke(append(apiArgs(t, srv.URL), "diagnostics", "capture", "--out", dst)...)
			if code != 2 || out != "" {
				t.Fatalf("%d %s %s", code, out, err)
			}
			if kind != "race" && calls != 0 {
				t.Fatal("invalid destination triggered network request")
			}
			if kind == "file" || kind == "race" {
				got, _ := os.ReadFile(dst)
				want := "original"
				if kind == "race" {
					want = "racing file"
				}
				if string(got) != want {
					t.Fatal("overwrote destination")
				}
			}
			matches, _ := filepath.Glob(filepath.Join(dir, ".guardianctl-profiles-*"))
			if len(matches) != 0 {
				t.Fatal(matches)
			}
		})
	}
}

func TestDiagnosticsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, readyDiagnostics)
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		cancel()
		<-r.Context().Done()
	}))
	defer srv.Close()
	dir := t.TempDir()
	args := append(apiArgs(t, srv.URL), "diagnostics", "capture", "--out", filepath.Join(dir, "profiles.tar"))
	var out, err bytes.Buffer
	code := runContext(ctx, args, &out, &err)
	if code != 4 || out.Len() != 0 {
		t.Fatalf("%d %s %s", code, out.String(), err.String())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}

type failingArchiveWriter struct{}

func (failingArchiveWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }
func TestDiagnosticsWriteFailure(t *testing.T) {
	good := archiveFixture(t, "goroutineleak.pprof", "goroutine.pprof")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Length", strconv.Itoa(len(good)))
		w.Write(good)
	}))
	defer srv.Close()
	c, err := newClient(options{endpoint: srv.URL, tokenFile: writeFile(t, "token", "test-secret"), timeout: time.Second}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.http.CloseIdleConnections()
	_, err = c.downloadDiagnostics(failingArchiveWriter{})
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != 1 {
		t.Fatalf("write failure: %v", err)
	}
}
