// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/web"
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

	// One request for the whole run, with only the client-IP header value
	// swapped per iteration (writing the backing slice element directly, which
	// allocates nothing). Building a fresh httptest request per iteration would
	// charge ~20 allocs of request-parsing harness to a gate that exists to
	// watch the HANDLER's allocations.
	r := issueBenchRequest(0)
	ipSlice := []string{""}
	r.Header["X-Guardian-Ip"] = ipSlice
	var ipBuf [16]byte

	b.ReportAllocs()
	b.ResetTimer()
	w := &issueBenchWriter{h: make(http.Header, 8)}
	for range b.N {
		clear(w.h)
		// The IP string itself is one deliberate allocation: handler-side
		// counter keys embed copies of it, so a reused buffer would be unsafe.
		// Built by append rather than Sprintf so the harness charges exactly
		// that one allocation, not fmt boxing on top.
		ip := append(ipBuf[:0], "10."...)
		ip = strconv.AppendInt(ip, (seq>>16)&0x3f|0x40, 10)
		ip = append(ip, '.')
		ip = strconv.AppendInt(ip, (seq>>8)&0xff, 10)
		ip = append(ip, '.')
		ip = strconv.AppendInt(ip, seq&0xff, 10)
		ipSlice[0] = string(ip)
		srv.ServeHTTP(w, r)
		if w.code != http.StatusOK {
			b.Fatalf("status = %d at seq %d", w.code, seq)
		}
		seq++
	}
}

// BenchmarkChallengeRenderTemplate isolates the reference html/template cost
// from counters, challenge generation and store writes, so the compiled
// production renderer has a stable before implementation to compare against.
func BenchmarkChallengeRenderTemplate(b *testing.B) {
	tmpl := template.Must(template.ParseFS(web.FS, "challenge.html.tmpl"))
	payload, err := json.Marshal(&challengePayload{
		ChallengeID: "0123456789abcdef0123456789abcdef",
		Challenge:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Difficulty:  16,
		PassURL:     PassPath,
	})
	if err != nil {
		b.Fatal(err)
	}
	for _, noScript := range []bool{false, true} {
		b.Run(fmt.Sprintf("nojs=%t", noScript), func(b *testing.B) {
			data := &challengeData{
				JSON:           template.JS(payload),
				NoScript:       noScript,
				RefreshSeconds: 6,
				NoJSURL:        PassPath + "?cid=0123456789abcdef0123456789abcdef&nojs=1",
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := tmpl.Execute(io.Discard, data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkChallengeRenderCompiled(b *testing.B) {
	renderer := newChallengeRenderer()
	payload := []byte(`{"challenge_id":"0123456789abcdef0123456789abcdef","challenge":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","difficulty_bits":16,"pass_url":"/__guardian/pass"}`)
	b.ReportAllocs()
	for b.Loop() {
		if err := renderer.Render(io.Discard, payload, false, "", "0123456789abcdef0123456789abcdef"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChallengeRenderCompiledNoJS(b *testing.B) {
	renderer := newChallengeRenderer()
	payload := []byte(`{"challenge_id":"0123456789abcdef0123456789abcdef","challenge":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","difficulty_bits":16,"pass_url":"/__guardian/pass"}`)
	b.ReportAllocs()
	for b.Loop() {
		if err := renderer.Render(io.Discard, payload, true, "6", "0123456789abcdef0123456789abcdef"); err != nil {
			b.Fatal(err)
		}
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
