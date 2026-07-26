// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/store"
)

// The guard pages must carry their own security headers, not rely on the Angie
// glue adding them: Guardian is also reached directly (dev, probes, a vhost
// whose add_header lines were never copied), and the admin listener is never
// fronted by Angie at all.
func TestGuardPagesCarryOwnSecurityHeaders(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	for _, tc := range []struct {
		name, path, csp, frame string
	}{
		{"challenge", "/challenge", "worker-src blob:", "SAMEORIGIN"},
		{"denied", "/denied", "default-src 'none'", "SAMEORIGIN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Guardian-Host", "html.test")
			req.Header.Set("X-Guardian-IP", "198.51.100.9")
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			csp := resp.Header.Get("Content-Security-Policy")
			if !strings.Contains(csp, tc.csp) {
				t.Errorf("Content-Security-Policy = %q, want it to contain %q", csp, tc.csp)
			}
			if !strings.Contains(csp, "frame-ancestors 'self'") {
				t.Errorf("Content-Security-Policy = %q, want frame-ancestors 'self'", csp)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := resp.Header.Get("X-Frame-Options"); got != tc.frame {
				t.Errorf("X-Frame-Options = %q, want %q", got, tc.frame)
			}
			if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want no-referrer", got)
			}
		})
	}
}

// Neither guard page may gain an img-src, because the absence of one is what
// stops a browser from asking for a favicon.
//
// A document that declares no <link rel="icon"> falls back to requesting
// /favicon.ico from the origin root. On a pow.mode: always domain that request
// is itself challenged, so the interstitial would generate the traffic the
// interstitial exists to filter (#44). Measured against both engines: an
// otherwise identical page served with and without default-src 'none' emits
// /favicon.ico only without it, in Chrome 150 and in Firefox alike. The fetch
// is blocked before it reaches the wire.
//
// Only the daemon's own policy is asserted here, and that is sufficient: a
// browser enforces every CSP it receives, so a policy without img-src blocks
// images whatever the Angie glue's copy allows.
//
// Adding an icon to these pages therefore does not work the way it looks. It
// needs img-src, which re-enables the implicit fallback for anything that fails
// to use the declared icon, and it widens the two tightest policies in the
// product to buy a suppression that is already in place.
func TestGuardPagesAllowNoImagesSoNoFaviconIsFetched(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	for _, path := range []string{"/challenge", "/denied"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Guardian-Host", "html.test")
		req.Header.Set("X-Guardian-IP", "198.51.100.9")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("GET %s: Content-Security-Policy = %q, want default-src 'none'", path, csp)
		}
		if strings.Contains(csp, "img-src") {
			t.Errorf("GET %s: Content-Security-Policy = %q gained an img-src; "+
				"the guard pages must not load images, or every render provokes a challenged /favicon.ico", path, csp)
		}
	}
}

// TestChallengeRefusalsAreNotStored pins both refusals as no-store, and exists
// mostly to record why the obvious alternative was rejected on evidence rather
// than on taste.
//
// A short max-age looks right for the Accept-heuristic refusal: that client
// sends no cookie and never will, so the usual objection (a cached refusal
// outliving the client's token) does not apply to it, and letting the response
// be stored would stop it re-asking on every render. It was implemented, with
// Vary naming every header the decision read, and then measured. On the path it
// was aimed at it changed nothing: private, max-age=30, must-revalidate drew 38
// requests in 1.7 minutes against no-store's 40 in 2.1, while the same policy
// on a 200 took the identical repetition from 46 requests to 5, so the
// instrument could see storage working.
//
// That result is about Floorp 153's favicon path, not about error statuses in
// general; RFC 9111 makes a final status storable when it carries explicit
// freshness, whatever the status is. It was enough to drop the header, since a
// cache directive that changes nothing still has to be reasoned about forever.
//
// So both refusals stay no-store, and a Vary would be answering a question
// nothing asks. If someone re-adds a cache header here, this test should fail
// until they have re-measured and can say what changed.
func TestChallengeRefusalsAreNotStored(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	cases := []struct {
		name    string
		headers map[string]string
		why     string
	}{
		{
			name:    "accept heuristic",
			headers: map[string]string{"Accept": "*/*"},
			why:     "a cacheable 403 was measured and made no difference",
		},
		{
			name:    "subresource",
			headers: map[string]string{"Sec-Fetch-Dest": "image"},
			why:     "that client sends a cookie, so a cached refusal could outlive its token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/challenge", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Guardian-Host", "html.test")
			req.Header.Set("X-Guardian-IP", "198.51.100.10")
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store (%s)", got, tc.why)
			}
			if got := resp.Header.Get("Vary"); got != "" {
				t.Errorf("Vary = %q, want none: nothing here is storable, so nothing needs a cache key", got)
			}
		})
	}
}

// A JSON response is not a document, so it gets no page policy, but it must
// still be nosniff: without it a browser may render an admin body as HTML.
func TestJSONResponsesAreNosniffWithoutCSP(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/pass", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Guardian-Host", "html.test")
	req.Header.Set("X-Guardian-IP", "198.51.100.9")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy = %q, want none on a JSON response", got)
	}
}

// The dashboard is served from the admin listener, which Angie never fronts, so
// guardiand is the only thing that can give the page a CSP. It holds an
// operator's bearer token in sessionStorage, so framing is refused outright.
func TestDashboardCarriesFittedCSP(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
store: { backend: memory }
admin: { listen: "127.0.0.1:0", dashboard: true }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, "tok", "", "", nil, slog.Default()))
	defer ts.Close()

	for _, tc := range []struct{ path, want string }{
		{"/admin/dashboard", "script-src 'self' 'unsafe-inline'"},
		{"/admin/chart.umd.min.js", ""}, // an asset is not a document: no page policy
	} {
		resp, err := ts.Client().Get(ts.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", tc.path, resp.StatusCode)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if tc.want == "" {
			if csp != "" {
				t.Errorf("GET %s: Content-Security-Policy = %q, want none", tc.path, csp)
			}
		} else if !strings.Contains(csp, tc.want) || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s: Content-Security-Policy = %q, want %q and frame-ancestors 'none'", tc.path, csp, tc.want)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("GET %s: X-Content-Type-Options = %q, want nosniff", tc.path, got)
		}
	}
}
