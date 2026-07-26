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
