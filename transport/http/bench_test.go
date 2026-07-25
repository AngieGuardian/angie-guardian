// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The core benchmarks measure Engine.Evaluate in isolation. What Angie actually
// drives is this handler: per subrequest it reads the X-Guardian-* headers,
// builds a RequestContext around them, evaluates, and writes a response. That
// wrapper runs on every request, so it belongs in the measured hot path rather
// than being assumed free.
//
// The harness deliberately keeps its own cost out of the number: the request is
// built once per goroutine (Angie reuses keepalive connections; net/http parsing
// is not what this measures) and the response goes to a reusable writer rather
// than a fresh httptest.NewRecorder per iteration, which allocates a Header map
// and a body buffer. cmd/guardian-loadtest measures the full socket-to-socket
// path end to end.

const benchAuthYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  allowlist:
    paths: [ "/robots.txt" ]
  denylist:
    ips: [ "203.0.113.0/24" ]
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, noscript_fallback: true }
`

const benchUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"

// authRequest builds the subrequest the Angie glue sends, header for header.
func authRequest(path, host, ip, ua, cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.Header.Set(hdrHost, host)
	r.Header.Set("X-Guardian-Method", http.MethodGet)
	r.Header.Set(hdrURI, path)
	r.Header.Set(hdrIP, ip)
	r.Header.Set(hdrUA, ua)
	if cookie != "" {
		r.Header.Set("X-Guardian-Cookie", cookie)
	}
	return r
}

// benchWriter is a minimal ResponseWriter that keeps one header map alive for
// the whole run, so the harness contributes no allocations of its own.
type benchWriter struct {
	h    http.Header
	code int
}

func newBenchWriter() *benchWriter { return &benchWriter{h: make(http.Header, 4)} }

func (w *benchWriter) Header() http.Header         { return w.h }
func (w *benchWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *benchWriter) WriteHeader(code int)        { w.code = code }

// benchServer builds a handler whose decision log is discarded: a non-allow
// decision writes a structured log line synchronously, and measuring the test
// binary's stderr is not the point.
func benchServer(b *testing.B, yaml string) *Server {
	b.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(prev) })
	_, srv := testServerAndHandler(b, yaml)
	return srv
}

func benchmarkAuth(b *testing.B, path, host, ip, ua, cookie string, wantStatus int) {
	b.Helper()
	srv := benchServer(b, benchAuthYAML)

	probe := httptest.NewRecorder()
	srv.ServeHTTP(probe, authRequest(path, host, ip, ua, cookie))
	if probe.Code != wantStatus {
		b.Fatalf("sanity: status = %d, want %d", probe.Code, wantStatus)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := authRequest(path, host, ip, ua, cookie)
		w := newBenchWriter()
		for pb.Next() {
			clear(w.h)
			srv.ServeHTTP(w, r)
		}
	})
}

// BenchmarkAuthAllow is an unvouched request to a PoW-free vhost: the full
// pipeline ending in the default allow.
func BenchmarkAuthAllow(b *testing.B) {
	benchmarkAuth(b, "/products/1234?page=2", "plain.test", "198.51.100.7", benchUA, "", http.StatusOK)
}

// BenchmarkAuthAllowlistPath is the cheapest terminal verdict, and the one a
// well-configured site serves for its static assets.
func BenchmarkAuthAllowlistPath(b *testing.B) {
	benchmarkAuth(b, "/robots.txt", "plain.test", "198.51.100.7", benchUA, "", http.StatusOK)
}

// BenchmarkAuthDeny is a denylisted client: the terminal path Angie turns into
// the denied page. It also pays the decision log line every non-allow verdict
// writes.
func BenchmarkAuthDeny(b *testing.B) {
	benchmarkAuth(b, "/products/1234", "plain.test", "203.0.113.9", benchUA, "", http.StatusForbidden)
}

// BenchmarkAuthChallengeDecision is an unvouched client on a PoW vhost: the 401
// that sends Angie to the interstitial.
func BenchmarkAuthChallengeDecision(b *testing.B) {
	benchmarkAuth(b, "/dashboard", "html.test", "198.51.100.7", benchUA, "", http.StatusUnauthorized)
}

// BenchmarkRequestContext isolates the per-request header plumbing from the
// decision: the X-Guardian-* reads plus the RequestContext built around them,
// paid on every request before any policy runs.
func BenchmarkRequestContext(b *testing.B) {
	s := &Server{}
	r := authRequest("/products/1234?page=2", "plain.test", "198.51.100.7", benchUA,
		"guardian_token="+strings.Repeat("x", 320))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if req := s.requestContext(r); req.Host == "" {
			b.Fatal("empty host")
		}
	}
}
