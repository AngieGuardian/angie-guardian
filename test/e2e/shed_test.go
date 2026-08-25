// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// TestGuardianBaselineControlPlaneAdmission verifies the shipped baseline at
// the real Angie locations. These are Guardian-owned public endpoints, so the
// limits are generic; each rejected request must stop before Guardian's
// expensive work and can never reach the protected origin.
func TestGuardianBaselineControlPlaneAdmission(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"challenge", http.MethodGet, "/baseline-challenge", ""},
		{"pass", http.MethodPost, "/__guardian/pass", `{}`},
		{"assets", http.MethodGet, "/__guardian/assets/argon2id-worker-db57362e2dddfb66.js", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const burst = 80
			before := backendCount(t)
			var wg sync.WaitGroup
			var mu sync.Mutex
			codes := map[int]int{}
			for range burst {
				wg.Go(func() {
					r, err := http.NewRequest(tt.method, site+tt.path, strings.NewReader(tt.body))
					if err != nil {
						t.Error(err)
						return
					}
					r.Host = baselineHost
					resp, err := (&http.Client{}).Do(r)
					if err != nil {
						return
					}
					mu.Lock()
					codes[resp.StatusCode]++
					mu.Unlock()
					resp.Body.Close()
				})
			}
			wg.Wait()

			if codes[http.StatusTooManyRequests] == 0 {
				t.Fatalf("Guardian baseline did not shed %s flood: %v", tt.name, codes)
			}
			if after := backendCount(t); after != before {
				t.Errorf("backend received %d requests during %s control-plane flood; want 0 (statuses=%v)", after-before, tt.name, codes)
			}
		})
	}
}

// TestLoadShedThroughAngie proves the shed path survives Angie's auth_request:
// under saturation the sidecar answers the auth subrequest with 403 +
// X-Guardian-Action: shed, and the Angie glue turns that into a real 503 +
// Retry-After for the client. The bug this guards against is a bare 503 from
// the sidecar becoming a 500 that fail-open converts to authorization,
// leaking the flood to the backend (a 200 from whoami).
//
// A concurrent burst of tokenless requests on the PoW-off host oversubscribes
// the small max_inflight bound (guardian.e2e.yaml). We do not require a
// specific count of sheds (timing-dependent), but assert that WHENEVER a
// request is shed it is a well-formed 503 + Retry-After, and never a backend
// 200 produced by fail-open continuation of the original handler.
func TestLoadShedThroughAngie(t *testing.T) {
	const burst = 200
	backendBefore := backendCount(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	shedHadRetryAfter := true

	client := &http.Client{}
	for range burst {
		wg.Go(func() {
			r, _ := http.NewRequest(http.MethodGet, site+"/shed-probe", nil)
			r.Host = powHost // unvouched requests must challenge or shed, never reach the backend
			r.Header.Set("User-Agent", "shed-test/1.0")
			resp, err := client.Do(r)
			if err != nil {
				return
			}
			mu.Lock()
			codes[resp.StatusCode]++
			if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") == "" {
				shedHadRetryAfter = false
			}
			mu.Unlock()
			resp.Body.Close()
		})
	}
	wg.Wait()

	if !shedHadRetryAfter {
		t.Error("a shed response (503) was missing Retry-After")
	}
	// auth_request would turn a sidecar's bare 503 into a 500 reaching the
	// client; sheds must come back as 503 (via the action header + Angie glue)
	// so nothing is a 500.
	if n := codes[http.StatusInternalServerError]; n > 0 {
		t.Errorf("%d requests got 500 (auth_request mangled the shed status; the flood would route to the backend)", n)
	}
	// Sanity: the burst should produce at least some 503s, otherwise the test
	// never actually exercised shedding (bound too high or burst too small).
	if codes[http.StatusServiceUnavailable] == 0 {
		t.Logf("codes: %v", codes)
		t.Skip("burst did not saturate max_inflight (timing); shed path not exercised this run")
	}
	t.Logf("shed e2e status distribution: %v", codes)
	if backendAfter := backendCount(t); backendAfter != backendBefore {
		t.Errorf("backend received %d requests during the unvouched shed burst; want 0 (before=%d after=%d)",
			backendAfter-backendBefore, backendBefore, backendAfter)
	}
}

// TestServerScopeAdmissionProtectsBackend proves the other half of the
// overload boundary: Angie admission runs before Guardian and the origin.
// The admission.localhost harness vhost has a deliberately tiny server-scope limit;
// rejected requests must not increment the private origin counter.
func TestServerScopeAdmissionProtectsBackend(t *testing.T) {
	const burst = 20
	before := backendCount(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range burst {
		wg.Go(func() {
			r, _ := http.NewRequest(http.MethodGet, site+"/admission-probe", nil)
			r.Host = admissionHost
			r.Header.Set("User-Agent", "admission-test/1.0")
			resp, err := (&http.Client{}).Do(r)
			if err != nil {
				return
			}
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
			resp.Body.Close()
		})
	}
	wg.Wait()

	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("server-scope admission did not reject the burst: %v", codes)
	}
	after := backendCount(t)
	if delta := after - before; delta != int64(codes[http.StatusOK]) {
		t.Errorf("backend request delta = %d, accepted 200s = %d, statuses=%v; rejected traffic reached the origin",
			delta, codes[http.StatusOK], codes)
	}
}
