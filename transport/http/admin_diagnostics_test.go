// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/internal/diagnostics"
)

const diagnosticsURL = "http://guardian.test/admin/diagnostics/goroutines"

func diagnosticsAdmin(t *testing.T, enabled bool) (*AdminServer, *httptest.Server) {
	t.Helper()
	cfg := &core.Config{}
	cfg.Admin.DiagnosticsEnabled = enabled
	s := NewAdminServer(nil, cfg, nil, adminToken, "", "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return s, httptest.NewTestServer(t, s)
}

func diagnosticsRequest(t *testing.T, ts *httptest.Server, method, url, body, token, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func diagnosticsFixture(t *testing.T) *diagnostics.Archive {
	t.Helper()
	var data bytes.Buffer
	if err := diagnostics.WriteProfile("goroutine", &data); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "capture.tar"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	tw := tar.NewWriter(f)
	for _, name := range []string{"goroutineleak.pprof", "goroutine.pprof"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(data.Len())}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return &diagnostics.Archive{File: f, Name: "guardian-goroutines.tar", Size: size}
}

func TestAdminDiagnosticsAdmission(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		enabled                          bool
		method, url, body, token, origin string
		status                           int
	}{
		{"missing auth", true, "POST", diagnosticsURL, "", "", "", 401},
		{"wrong auth", true, "POST", diagnosticsURL, "", "incorrect", "", 401},
		{"disabled", false, "POST", diagnosticsURL, "", adminToken, "", 404},
		{"cross origin", true, "POST", diagnosticsURL, "", adminToken, "https://other.test", 403},
		{"body", true, "POST", diagnosticsURL, "{}", adminToken, "", 400},
		{"query", true, "POST", diagnosticsURL + "?debug=2", "", adminToken, "", 400},
		{"get auth", true, "GET", diagnosticsURL, "", "", "", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ts := diagnosticsAdmin(t, tc.enabled)
			var calls atomic.Int32
			s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) {
				calls.Add(1)
				return nil, errors.New("must not capture")
			}
			resp := diagnosticsRequest(t, ts, tc.method, tc.url, tc.body, tc.token, tc.origin)
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d want %d", resp.StatusCode, tc.status)
			}
			if calls.Load() != 0 {
				t.Fatal("rejected request triggered capture")
			}
		})
	}
	s, ts := diagnosticsAdmin(t, false)
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) {
		t.Error("GET triggered capture")
		return nil, errors.New("unexpected")
	}
	resp := diagnosticsRequest(t, ts, "GET", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	state := decodeJSON(t, resp)
	if state["enabled"] != false || state["capturing"] != false || state["retry_after_seconds"] != float64(0) {
		t.Fatalf("disabled state=%v", state)
	}
}

func TestAdminDiagnosticsDownloadAndCooldown(t *testing.T) {
	s, ts := diagnosticsAdmin(t, true)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	s.diagnosticsNow = func() time.Time { return now }
	archive := diagnosticsFixture(t)
	var calls atomic.Int32
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) { calls.Add(1); return archive, nil }
	resp := diagnosticsRequest(t, ts, "POST", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/x-tar" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers=%v", resp.Header)
	}
	kind, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || kind != "attachment" || params["filename"] != "guardian-goroutines.tar" {
		t.Fatalf("disposition=%q error=%v", resp.Header.Get("Content-Disposition"), err)
	}
	tr := tar.NewReader(resp.Body)
	for _, want := range []string{"goroutineleak.pprof", "goroutine.pprof"} {
		header, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != want {
			t.Fatalf("entry=%q want %q", header.Name, want)
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := profile.ParseData(raw); err != nil {
			t.Fatalf("%s invalid profile: %v", want, err)
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("unexpected archive tail: %v", err)
	}
	if _, err := archive.File.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("archive not closed: %v", err)
	}
	resp = diagnosticsRequest(t, ts, "POST", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("cooldown status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	state := decodeJSON(t, diagnosticsRequest(t, ts, "GET", diagnosticsURL, "", adminToken, ""))
	if state["enabled"] != true || state["capturing"] != false || state["retry_after_seconds"].(float64) <= 0 {
		t.Fatalf("state=%v", state)
	}
	if calls.Load() != 1 {
		t.Fatalf("captures=%d want 1", calls.Load())
	}
	now = now.Add(2 * time.Minute)
	nextArchive := diagnosticsFixture(t)
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) { calls.Add(1); return nextArchive, nil }
	resp = diagnosticsRequest(t, ts, "POST", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 200 || calls.Load() != 2 {
		t.Fatalf("post-cooldown status=%d captures=%d", resp.StatusCode, calls.Load())
	}
}

func TestAdminDiagnosticsConcurrentAndFailure(t *testing.T) {
	s, ts := diagnosticsAdmin(t, true)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) {
		calls.Add(1)
		close(entered)
		<-release
		return nil, errors.New("private diagnostic error /tmp/sensitive")
	}
	done := make(chan *http.Response, 1)
	req, _ := http.NewRequest("POST", diagnosticsURL, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	go func() {
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Error(err)
		}
		done <- resp
	}()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("capture not entered")
	}
	state := decodeJSON(t, diagnosticsRequest(t, ts, "GET", diagnosticsURL, "", adminToken, ""))
	if state["capturing"] != true {
		t.Fatalf("active state=%v", state)
	}
	resp := diagnosticsRequest(t, ts, "POST", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 409 || calls.Load() != 1 {
		t.Fatalf("concurrent status=%d captures=%d", resp.StatusCode, calls.Load())
	}
	close(release)
	select {
	case resp = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("failed capture did not finish")
	}
	if resp == nil {
		t.Fatal("capture returned no response")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 500 || bytes.Contains(body, []byte("sensitive")) || bytes.Contains(body, []byte("private diagnostic")) {
		t.Fatalf("failure status=%d body=%s", resp.StatusCode, body)
	}
	state = decodeJSON(t, diagnosticsRequest(t, ts, "GET", diagnosticsURL, "", adminToken, ""))
	if state["capturing"] != false {
		t.Fatalf("failed capture retained admission: %v", state)
	}
}

func TestAdminDiagnosticsCanceledCaptureCleanup(t *testing.T) {
	s, _ := diagnosticsAdmin(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	archive := diagnosticsFixture(t)
	s.diagnosticsPrepare = func(ctx context.Context) (*diagnostics.Archive, error) { cancel(); return archive, nil }
	req := httptest.NewRequest("POST", diagnosticsURL, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, req)
	if _, err := archive.File.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("canceled archive not closed: %v", err)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("canceled request received profile data: %d bytes", recorder.Body.Len())
	}
	s.diagnosticsMu.Lock()
	active := s.diagnosticsActive
	s.diagnosticsMu.Unlock()
	if active {
		t.Fatal("canceled capture retained admission")
	}
	var calls atomic.Int32
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) {
		calls.Add(1)
		return nil, errors.New("unexpected capture")
	}
	s.ServeHTTP(httptest.NewRecorder(), req)
	if calls.Load() != 0 {
		t.Fatal("already canceled request triggered capture")
	}
}

// A paused download keeps capture admission occupied even after the cooldown
// expires. A disconnected writer must release that admission and its archive.
type interruptedDiagnosticsWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w *interruptedDiagnosticsWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.release
	return 0, errors.New("client disconnected")
}

func TestAdminDiagnosticsInterruptedDownload(t *testing.T) {
	s, ts := diagnosticsAdmin(t, true)
	archive := diagnosticsFixture(t)
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) { return archive, nil }
	writer := &interruptedDiagnosticsWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	req := httptest.NewRequest("POST", diagnosticsURL, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	done := make(chan struct{})
	go func() { s.ServeHTTP(writer, req); close(done) }()
	t.Cleanup(func() {
		select {
		case <-writer.release:
		default:
			close(writer.release)
		}
	})
	select {
	case <-writer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not begin")
	}
	state := decodeJSON(t, diagnosticsRequest(t, ts, "GET", diagnosticsURL, "", adminToken, ""))
	if state["capturing"] != true {
		t.Fatalf("download released admission early: %v", state)
	}
	// Exercise the active gate rather than merely the cooldown gate.
	s.diagnosticsMu.Lock()
	s.diagnosticsNext = time.Time{}
	s.diagnosticsMu.Unlock()
	resp := diagnosticsRequest(t, ts, "POST", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 409 {
		t.Fatalf("active download status=%d want409", resp.StatusCode)
	}
	close(writer.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted download did not exit")
	}
	if _, err := archive.File.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("interrupted archive not closed: %v", err)
	}
	state = decodeJSON(t, diagnosticsRequest(t, ts, "GET", diagnosticsURL, "", adminToken, ""))
	if state["capturing"] != false {
		t.Fatalf("interrupted download retained admission: %v", state)
	}
	next := diagnosticsFixture(t)
	s.diagnosticsPrepare = func(context.Context) (*diagnostics.Archive, error) { return next, nil }
	resp = diagnosticsRequest(t, ts, "POST", diagnosticsURL, "", adminToken, "")
	if resp.StatusCode != 200 {
		t.Fatalf("after interrupted download status=%d want200", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
}
