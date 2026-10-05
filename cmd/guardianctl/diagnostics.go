// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"encoding/json/v2"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
)

const diagnosticsPath = "/admin/diagnostics/goroutines"
const maxDiagnosticsBytes int64 = 32 << 20

func (c *client) diagnostics(action string, o options, out io.Writer) error {
	if action == "status" {
		status, err := c.diagnosticsStatus()
		if err != nil {
			return err
		}
		return render(out, o.json, "diagnostics status", status)
	}
	destination, err := filepath.Abs(o.destination)
	if err != nil {
		return fail(2, "invalid output path")
	}
	if _, err := os.Lstat(destination); err == nil {
		return fail(2, "output already exists; choose another --out path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(2, "cannot inspect output destination")
	}
	// Create before requesting a capture: a missing/unwritable directory must
	// not consume the daemon's GC cycle or admission cooldown.
	f, err := os.CreateTemp(filepath.Dir(destination), ".guardianctl-profiles-*")
	if err != nil {
		return fail(2, "cannot create output file; check destination directory and permissions")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	status, err := c.diagnosticsStatus()
	if err != nil {
		return err
	}
	if status["enabled"] != true {
		return fail(1, "diagnostics disabled; set admin.diagnostics_enabled: true and restart Guardian")
	}
	if status["capturing"] == true {
		return fail(1, "a diagnostic capture or download is already active")
	}
	if seconds := status["retry_after_seconds"].(float64); seconds > 0 {
		return fail(1, "diagnostic capture is cooling down; retry in %.0f seconds", seconds)
	}
	size, err := c.downloadDiagnostics(f)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fail(1, "cannot flush downloaded archive to disk")
	}
	if err := validateDiagnosticsArchive(f, size); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return fail(1, "cannot close downloaded archive")
	}
	if err := c.ctx.Err(); err != nil {
		return fail(4, "diagnostic download canceled")
	}
	// A hard link within this directory publishes the complete file atomically
	// and fails if a competing process creates the destination (including links).
	if err := os.Link(f.Name(), destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(2, "output already exists; choose another --out path")
		}
		return fail(1, "cannot publish downloaded archive")
	}
	return render(out, o.json, "diagnostics capture", map[string]any{"path": destination, "bytes": size})
}

func (c *client) diagnosticsStatus() (map[string]any, error) {
	status, err := c.request("GET", diagnosticsPath, nil)
	if err != nil {
		return nil, err
	}
	_, enabledOK := status["enabled"].(bool)
	_, capturingOK := status["capturing"].(bool)
	retry, retryOK := status["retry_after_seconds"].(float64)
	if !enabledOK || !capturingOK || !retryOK || retry < 0 || retry != float64(int64(retry)) {
		return nil, fail(1, "invalid diagnostics status response")
	}
	return status, nil
}

func (c *client) downloadDiagnostics(dst io.Writer) (int64, error) {
	req, err := http.NewRequestWithContext(c.ctx, "POST", c.endpoint+diagnosticsPath, nil)
	if err != nil {
		return 0, fail(2, "invalid diagnostic request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fail(4, "cannot reach admin listener (connection, TLS or timeout failure)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return 0, fail(4, "cannot finish reading admin response")
		}
		result := map[string]any{}
		_ = json.Unmarshal(raw, &result)
		return 0, c.apiError(resp, diagnosticsPath, result)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-tar" {
		return 0, fail(1, "diagnostics API did not return a tar archive")
	}
	if resp.ContentLength <= 0 || resp.ContentLength > maxDiagnosticsBytes {
		return 0, fail(1, "invalid diagnostic archive length (maximum 32 MiB)")
	}
	// Separate read errors (connection/cancellation) from local write errors.
	n, err := io.Copy(dst, &diagnosticReader{reader: io.LimitReader(resp.Body, maxDiagnosticsBytes+1)})
	if err != nil {
		var readErr *diagnosticReadError
		if errors.As(err, &readErr) {
			return 0, fail(4, "diagnostic download interrupted or timed out")
		}
		return 0, fail(1, "cannot write downloaded archive")
	}
	if n != resp.ContentLength || n > maxDiagnosticsBytes {
		return 0, fail(1, "diagnostic archive is incomplete or exceeds its size limit")
	}
	return n, nil
}

type diagnosticReadError struct{ error }
type diagnosticReader struct{ reader io.Reader }

func (r *diagnosticReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		err = &diagnosticReadError{err}
	}
	return n, err
}

func validateDiagnosticsArchive(f *os.File, size int64) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(1, "cannot read downloaded archive")
	}
	tr := tar.NewReader(f)
	for _, name := range []string{"goroutineleak.pprof", "goroutine.pprof"} {
		h, err := tr.Next()
		if err != nil || h.Name != name || h.Typeflag != tar.TypeReg || h.Size <= 0 {
			return fail(1, "invalid diagnostic archive: expected two regular, nonempty goroutine profiles")
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return fail(1, "invalid or truncated diagnostic archive")
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		return fail(1, "invalid diagnostic archive: unexpected extra entry or damaged trailer")
	}
	position, err := f.Seek(0, io.SeekCurrent)
	if err != nil || position != size {
		return fail(1, "invalid diagnostic archive: unexpected trailing data")
	}
	// archive/tar treats physical EOF as a valid end. Require the two zero
	// records emitted by the server's tar writer, as well as complete padding.
	if size < 1024 || size%512 != 0 {
		return fail(1, "invalid or truncated diagnostic archive trailer")
	}
	tail := make([]byte, 1024)
	if _, err := f.ReadAt(tail, size-1024); err != nil {
		return fail(1, "cannot verify diagnostic archive trailer")
	}
	for _, b := range tail {
		if b != 0 {
			return fail(1, "invalid diagnostic archive trailer")
		}
	}
	return nil
}
