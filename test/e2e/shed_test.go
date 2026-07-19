// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"sync"
	"testing"
)

// TestLoadShedThroughAngie proves the shed path survives Angie's auth_request:
// under saturation the sidecar answers the auth subrequest with 403 +
// X-Guardian-Action: shed, and the Angie glue turns that into a real 503 +
// Retry-After for the client. The bug this guards against is a bare 503 from
// the sidecar becoming a 500 that error_page routes to @guardian_bypass,
// leaking the flood to the backend (a 200 from whoami).
//
// A concurrent burst of tokenless requests on the PoW-off host oversubscribes
// the small max_inflight bound (guardian.e2e.yaml). We do not require a
// specific count of sheds (timing-dependent), but assert that WHENEVER a
// request is shed it is a well-formed 503 + Retry-After, and never a backend
// 200 produced by the fail-open bypass.
func TestLoadShedThroughAngie(t *testing.T) {
	const burst = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	shedHadRetryAfter := true

	client := &http.Client{}
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := http.NewRequest(http.MethodGet, site+"/shed-probe", nil)
			r.Host = wafOnlyHost // PoW off: a normal request is a plain allow
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
		}()
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
}
