// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"testing"
)

func TestRefusalScenarios(t *testing.T) {
	tests := map[string]struct {
		path         string
		status       int
		throughAngie bool
		wantHost     string
		wantHeaders  map[string]string
	}{
		"refuse-auth": {
			path:     "/auth",
			status:   http.StatusUnauthorized,
			wantHost: "127.0.0.1:8071",
			wantHeaders: map[string]string{
				"Accept":              refusalAccept,
				guardianHostHeader:    "example.com",
				guardianMethodHeader:  http.MethodGet,
				guardianURIHeader:     loadtestRequestURI,
				guardianIPHeader:      "198.51.100.7",
				guardianUAHeader:      browserUA,
				guardianRefusalHeader: "",
			},
		},
		"refuse-challenge": {
			path:     "/challenge",
			status:   http.StatusForbidden,
			wantHost: "127.0.0.1:8071",
			wantHeaders: map[string]string{
				"Accept":              refusalAccept,
				guardianHostHeader:    "example.com",
				guardianMethodHeader:  http.MethodGet,
				guardianURIHeader:     loadtestRequestURI,
				guardianIPHeader:      "198.51.100.7",
				guardianUAHeader:      browserUA,
				guardianRefusalHeader: refusalOutcome,
			},
		},
		"refuse-angie": {
			path:         loadtestRequestURI,
			status:       http.StatusForbidden,
			throughAngie: true,
			wantHost:     "example.com",
			wantHeaders: map[string]string{
				"Accept":             refusalAccept,
				"User-Agent":         browserUA,
				guardianHostHeader:   "",
				guardianMethodHeader: "",
				guardianURIHeader:    "",
				guardianIPHeader:     "",
				guardianUAHeader:     "",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			spec, err := scenarioByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if spec.path != tc.path || spec.wantStatus != tc.status || spec.throughAngie != tc.throughAngie {
				t.Fatalf("scenario = path %q, status %d, throughAngie %t; want %q, %d, %t",
					spec.path, spec.wantStatus, spec.throughAngie, tc.path, tc.status, tc.throughAngie)
			}
			req, err := spec.newRequest("http://127.0.0.1:8071", "example.com", "198.51.100.7", 0)
			if err != nil {
				t.Fatal(err)
			}
			if req.URL.RequestURI() != tc.path {
				t.Errorf("request path = %q, want %q", req.URL.RequestURI(), tc.path)
			}
			if req.Host != tc.wantHost {
				t.Errorf("HTTP Host = %q, want %q", req.Host, tc.wantHost)
			}
			for k, want := range tc.wantHeaders {
				if got := req.Header.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestRefusalResponseContracts(t *testing.T) {
	for _, name := range []string{"refuse-auth", "refuse-challenge", "refuse-angie"} {
		t.Run(name, func(t *testing.T) {
			spec, err := scenarioByName(name)
			if err != nil {
				t.Fatal(err)
			}
			resp := &http.Response{StatusCode: spec.wantStatus, Header: make(http.Header)}
			if name == "refuse-auth" {
				resp.Header.Set(guardianActionHeader, "refuse")
				resp.Header.Set(guardianRefusalHeader, refusalOutcome)
			} else {
				resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
				resp.Header.Set("Cache-Control", "no-store")
			}
			if !spec.responseMatches(resp) {
				t.Fatal("valid refusal response did not satisfy its contract")
			}
			resp.Header = make(http.Header)
			if spec.responseMatches(resp) {
				t.Fatal("response missing identifying headers satisfied its contract")
			}
		})
	}
}

func TestUnknownScenario(t *testing.T) {
	if _, err := scenarioByName("refuse"); err == nil {
		t.Fatal("unknown scenario accepted")
	}
}

func TestRotatingChallengeIPUsesFullPrivateRange(t *testing.T) {
	tests := map[int64]string{
		0:             "10.0.0.0",
		255:           "10.0.0.255",
		256:           "10.0.1.0",
		1<<16 - 1:     "10.0.255.255",
		1 << 16:       "10.1.0.0",
		1 << 22:       "10.64.0.0",
		1<<24 - 1:     "10.255.255.255",
		1 << 24:       "10.0.0.0",
		1<<24 + 12345: "10.0.48.57",
	}
	for seq, want := range tests {
		if got := rotatingChallengeIP(seq); got != want {
			t.Errorf("rotatingChallengeIP(%d) = %q, want %q", seq, got, want)
		}
	}

	if rotatingChallengeIP(0) == rotatingChallengeIP(1<<22) {
		t.Fatal("challenge IP rotation still wraps at the former 10.64/10 boundary")
	}
}
