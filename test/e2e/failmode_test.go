// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
)

// TestFailOpenWhenGuardianDown exercises Angie's fail mode. The harness ships
// the documented default (fail-OPEN) in deploy/angie-guardian.conf: when the
// guardiand sidecar is unreachable, the internal auth location maps its own
// upstream error to 204. auth_request treats that as allow and resumes the
// site's original handler, so a sidecar outage does not take the site down.
//
// This test stops guardiand, asserts the backend is still served, then restarts
// it and waits for health so the rest of the suite is unaffected. It is written
// to leave the stack exactly as it found it.
func TestFailOpenWhenGuardianDown(t *testing.T) {
	// Make sure we always bring guardiand back, even if an assertion fails.
	t.Cleanup(func() {
		startGuardiand(t)
		clearGatewayBlocks()
	})

	transport := &http.Transport{MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	fetch := func(uri string, wantReuse bool) *http.Response {
		r, err := http.NewRequest(http.MethodGet, site+uri, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = powHost
		r.Header.Set("User-Agent", browserUA)
		reused := false
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		if wantReuse && !reused {
			response.Body.Close()
			t.Fatal("failed-auth isolation request did not reuse the Angie connection")
		}
		return response
	}

	// Sanity: with guardiand up, an unvouched GET is challenged (proof the
	// sidecar is actually in the path before we stop it).
	if r := fetch(uniqueAuditURI("/pre-check"), false); r.StatusCode != http.StatusOK {
		t.Fatalf("pre-check (guardiand up): status %d, want 200 interstitial", r.StatusCode)
	} else {
		bodyOf(t, r)
	}

	stopGuardiand(t)

	// Fail-open applies only to Guardian's own upstream failure. Angie's
	// protocol admission remains in force while the sidecar is unavailable.
	// In particular, the body-size boundary must not leak through to origin.
	oversizedBefore := backendCount(t)
	oversized := req(t, http.MethodPost, site+"/too-large-with-guardian-down", map[string]string{
		"Host":       wafOnlyHost,
		"User-Agent": browserUA,
	}, strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	if oversized.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("fail-open oversized request: status %d, want 413", oversized.StatusCode)
	}
	if after := backendCount(t); after != oversizedBefore {
		t.Fatalf("fail-open oversized request reached origin: delta %d", after-oversizedBefore)
	}

	// With the sidecar down, the site must still serve the backend (fail-open).
	// Use a normal path to prove the original backend handler resumes.
	before := backendCount(t)
	failedURI := uniqueAuditURI("/still-up")
	resp := fetch(failedURI, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fail-open: status %d with guardiand down, want 200 (backend served)", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
		t.Fatalf("fail-open did not serve the backend; body:\n%s", body)
	}
	ctr, err := stack.ServiceContainer(t.Context(), "angie")
	if err != nil {
		t.Fatal(err)
	}
	failedRecord, _ := accessLogRecord(t, ctr, failedURI)
	// Docker may refuse the old peer connection or blackhole its address.
	// Assert the observed failure, never relabel a timeout as a refusal.
	if failedRecord.AuthUpstreamStatus != "502" && failedRecord.AuthUpstreamStatus != "504" {
		t.Fatalf("stopped sidecar upstream status = %q", failedRecord.AuthUpstreamStatus)
	}
	assertAccessDecision(t, ctr, failedURI, "", "", "204", failedRecord.AuthUpstreamStatus, 200, true)
	publicURI := uniqueAuditURI("/audit-public/after-failed-auth")
	public := fetch(publicURI, true)
	bodyOf(t, public)
	assertAccessDecision(t, ctr, publicURI, "", "", "", "", 200, true)
	if after := backendCount(t); after != before+2 {
		t.Errorf("fail-open backend delta = %d, want exactly 2", after-before)
	}
}

// NOTE on fail-CLOSED: the opposite behaviour (site returns 500 when guardiand
// is down) is produced by removing the fail-open 5xx error_page from the
// internal auth location. Reproducing it here would require a second Angie config +
// reload within one stack; the harness deliberately ships fail-open (the
// documented default), and deploy/docker/README.md documents the one-line
// toggle to reproduce fail-closed manually. The toggle itself is a pure Angie
// config concern, not guardian behaviour, so it is left out of the automated
// suite to keep it single-stack and deterministic.
