// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestAngieApplicationScenarios(t *testing.T) {
	for _, name := range []string{"allow-angie", "deny-angie"} {
		t.Run(name, func(t *testing.T) {
			spec, err := scenarioByName(name)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus := http.StatusOK
			if name == "deny-angie" {
				wantStatus = http.StatusForbidden
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "protected.test" || r.URL.RequestURI() != loadtestRequestURI || r.Header.Get("User-Agent") != browserUA {
					t.Errorf("original client request changed: host=%q uri=%q ua=%q", r.Host, r.URL.RequestURI(), r.Header.Get("User-Agent"))
				}
				for header := range r.Header {
					if strings.HasPrefix(header, "X-Guardian-") {
						t.Errorf("client request forged trusted header %q", header)
					}
				}
				w.WriteHeader(wantStatus)
			}))
			defer server.Close()
			result := runLoad(server.Client(), spec, loadConfig{
				baseURL: server.URL, host: "protected.test", ip: "203.0.113.99",
				concurrency: 2, warmup: 3, requests: 7,
			})
			if result.warmup.completed != 3 || result.measured.completed != 7 || result.measured.statuses[wantStatus] != 7 || result.measured.unexpectedStatus != 0 {
				t.Fatalf("unexpected request accounting: warmup=%+v measured=%+v", result.warmup, result.measured)
			}
		})
	}
}

func TestRunLoadSeparatesWarmupAndMeasuredOutcomes(t *testing.T) {
	// Rotation supplies a unique sequence to the server, so concurrent warmup
	// completions cannot accidentally determine which phase owns a response.
	spec, err := scenarioByName("challenge")
	if err != nil {
		t.Fatal(err)
	}
	spec.wantHeaderContains = map[string]string{"Cache-Control": "no-store"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.Header.Get(guardianIPHeader), ".")
		seq, _ := strconv.Atoi(parts[len(parts)-1])
		switch seq {
		case 0: // Warmup transport error: no HTTP response.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
		case 1, 2:
			w.WriteHeader(http.StatusForbidden)
		case 3: // Warmup response-contract mismatch.
			w.WriteHeader(http.StatusOK)
		case 4:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 5:
			w.WriteHeader(799) // Valid three-digit status outside the standard range.
		case 6: // Measured response-contract mismatch.
			w.WriteHeader(http.StatusOK)
		case 7: // Measured truncated body: status is visible, completion fails.
			w.Header().Set("Content-Length", "100")
			fmt.Fprint(w, "short")
		default:
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	result := runLoad(server.Client(), spec, loadConfig{
		baseURL: server.URL, host: "protected.test", ip: "198.51.100.7",
		concurrency: 4, warmup: 4, requests: 6,
	})
	if result.warmup.completed != 3 || result.warmup.errors != 1 || result.warmup.unexpectedStatus != 2 || result.warmup.unexpectedContract != 1 {
		t.Fatalf("warmup failures lost or attributed to measurement: %+v", result.warmup)
	}
	if result.measured.completed != 5 || result.measured.errors != 1 || result.measured.unexpectedStatus != 2 || result.measured.unexpectedContract != 1 {
		t.Fatalf("measured failures lost or attributed to warmup: %+v", result.measured)
	}
	if result.measured.statuses[200] != 4 || result.measured.statuses[503] != 1 || result.measured.statuses[799] != 1 || result.measured.statuses[403] != 0 {
		t.Fatalf("histogram mixes warmup or omits observed statuses: %+v", result.measured.statuses)
	}
	var completions int64
	for _, n := range result.perSecond {
		completions += n
	}
	if completions != 5 || result.elapsed <= 0 {
		t.Fatalf("measurement window/completions incorrect: elapsed=%s completions=%d", result.elapsed, completions)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestRunLoadAllErrorsHasMeasuredWindow(t *testing.T) {
	spec, _ := scenarioByName("allow")
	result := runLoad(&http.Client{Transport: failingTransport{}}, spec, loadConfig{
		baseURL: "http://example.test", concurrency: 2, warmup: 3, requests: 5,
	})
	if result.warmup.errors != 3 || result.measured.errors != 5 || result.measured.completed != 0 || result.elapsed <= 0 {
		t.Fatalf("all-error accounting/window incorrect: %+v", result)
	}
}

func TestRunLoadDurationMode(t *testing.T) {
	spec, _ := scenarioByName("allow")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	result := runLoad(server.Client(), spec, loadConfig{
		baseURL: server.URL, concurrency: 2, warmup: 3, duration: 20 * time.Millisecond,
	})
	if result.warmup.completed != 3 || result.measured.completed == 0 || result.elapsed <= 0 || result.measured.statuses[200] != result.measured.completed {
		t.Fatalf("duration mode lost measured work: warmup=%+v measured=%+v elapsed=%s", result.warmup, result.measured, result.elapsed)
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
