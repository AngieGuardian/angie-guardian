// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
)

const diagnosticsCooldown = time.Minute

func retrySeconds(next, now time.Time) int {
	if !next.After(now) {
		return 0
	}
	return int((next.Sub(now) + time.Second - 1) / time.Second)
}

func (s *AdminServer) handleGoroutineDiagnosticsStatus(w http.ResponseWriter, _ *http.Request) {
	s.diagnosticsMu.Lock()
	status := struct {
		Enabled    bool `json:"enabled"`
		Capturing  bool `json:"capturing"`
		RetryAfter int  `json:"retry_after_seconds"`
	}{s.diagnosticsEnabled, s.diagnosticsActive, retrySeconds(s.diagnosticsNext, s.diagnosticsNow())}
	s.diagnosticsMu.Unlock()
	writeJSON(w, http.StatusOK, status)
}

func (s *AdminServer) handleGoroutineDiagnosticsCapture(w http.ResponseWriter, r *http.Request) {
	if !s.diagnosticsEnabled {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "runtime diagnostics are disabled"})
		return
	}
	// Read at most one byte: every non-empty body (including chunked bodies)
	// is invalid. No caller-controlled options or output paths are accepted.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
	if err != nil || len(body) != 0 || r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "diagnostic capture requires an empty body and no query parameters"})
		return
	}
	if r.Context().Err() != nil {
		return
	}
	s.diagnosticsMu.Lock()
	now := s.diagnosticsNow()
	if s.diagnosticsActive {
		s.diagnosticsMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "a diagnostic capture or download is already active"})
		return
	}
	if retry := retrySeconds(s.diagnosticsNext, now); retry != 0 {
		s.diagnosticsMu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "diagnostic capture is cooling down"})
		return
	}
	s.diagnosticsActive = true
	s.diagnosticsNext = now.Add(diagnosticsCooldown)
	s.diagnosticsMu.Unlock()
	defer func() {
		s.diagnosticsMu.Lock()
		s.diagnosticsActive = false
		s.diagnosticsMu.Unlock()
	}()
	started := time.Now()
	archive, err := s.diagnosticsPrepare(r.Context())
	if err != nil {
		s.log.Error("goroutine diagnostic capture failed", "err", err, "duration", time.Since(started))
		if r.Context().Err() == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not prepare goroutine profiles"})
		}
		return
	}
	defer func() {
		if err := archive.Close(); err != nil {
			s.log.Error("clean up goroutine diagnostics", "err", err)
		}
	}()
	if r.Context().Err() != nil {
		return
	}
	securityHeaders(w, "", "")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": archive.Name}))
	w.Header().Set("Content-Length", strconv.FormatInt(archive.Size, 10))
	w.WriteHeader(http.StatusOK)
	n, err := io.Copy(w, archive.File)
	if err != nil {
		s.log.Warn("goroutine diagnostic download interrupted", "err", err, "bytes", n, "duration", time.Since(started))
		return
	}
	s.log.Info("goroutine diagnostic download completed", "bytes", n, "duration", time.Since(started))
}
