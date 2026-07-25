// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// BenchmarkChallengeIssue drives GET /challenge with a fresh client IP per
// iteration: the write-heavy path a flood of new clients exercises, and the one
// whose throughput the load test showed decaying as in-process counter state
// grows. Per request it pays the issuance rate-limit counter, the farming
// escalation counter, one store CAS for the challenge record, and the
// interstitial render.
//
// The IP never repeats, so the rate limiter never trips and escalation never
// fires; every iteration is the first sight of a new client. allocs/op is the
// number to gate on: it is stable across machines. ns/op depends on how far b.N
// has grown the counter caches, which is exactly what makes this benchmark able
// to reproduce the loaded-regime slowdown in-process (run with a large
// -benchtime to push both caches past their 131k-entry capacity).
func BenchmarkChallengeIssue(b *testing.B) {
	srv := newIssueBenchServer(b)
	var seq int64

	probe := httptest.NewRecorder()
	srv.ServeHTTP(probe, issueBenchRequest(0))
	if probe.Code != http.StatusOK {
		b.Fatalf("sanity: status = %d, body %s", probe.Code, probe.Body.String())
	}
	seq++

	b.ReportAllocs()
	b.ResetTimer()
	w := &issueBenchWriter{h: make(http.Header, 8)}
	for range b.N {
		clear(w.h)
		srv.ServeHTTP(w, issueBenchRequest(seq))
		if w.code != http.StatusOK {
			b.Fatalf("status = %d at seq %d", w.code, seq)
		}
		seq++
	}
}

// newIssueBenchServer builds a Server the way guardiand wires it, on the memory
// store, with the decision log discarded (a log write per request would swamp
// what this measures).
func newIssueBenchServer(b *testing.B) *Server {
	b.Helper()
	dir := b.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	cfgYAML := `
store: { backend: memory }
signing_key_file: ` + filepath.Join(dir, "ed25519.key") + `
domains:
  bench.test:
    pow: { enabled: true, base_difficulty: 4, max_difficulty: 6 }
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		b.Fatal(err)
	}
	st := store.NewMemory()
	b.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(cfg.SigningKeyFile)
	if err != nil {
		b.Fatal(err)
	}
	mgr := pow.NewManager(key, st)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine, err := core.NewEngine(cfg, st, mgr, log)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(engine.Close)
	return New(engine, mgr, st, nil, log)
}

// issueBenchRequest is the subrequest the Angie glue sends to /challenge, with
// the client IP derived from seq so it never repeats (mirroring the load
// test's rotation).
func issueBenchRequest(seq int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	r.Header.Set("X-Guardian-Host", "bench.test")
	r.Header.Set("X-Guardian-Uri", "/loadtest?x=1")
	r.Header.Set("X-Guardian-Ip", fmt.Sprintf("10.%d.%d.%d",
		(seq>>16)&0x3f|0x40, (seq>>8)&0xff, seq&0xff))
	r.Header.Set("X-Guardian-Ua", "Mozilla/5.0 (bench)")
	return r
}

// issueBenchWriter discards the response body while keeping one header map
// alive for the whole run, so the harness adds no allocations of its own.
// (Named issue-specifically so it cannot collide with other bench harnesses.)
type issueBenchWriter struct {
	h    http.Header
	code int
}

func (w *issueBenchWriter) Header() http.Header { return w.h }

// Write mirrors net/http's implicit 200: the interstitial path renders the
// template without an explicit WriteHeader.
func (w *issueBenchWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return len(b), nil
}

func (w *issueBenchWriter) WriteHeader(code int) { w.code = code }
