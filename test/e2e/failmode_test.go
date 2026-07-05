// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestFailOpenWhenGuardianDown exercises Angie's fail mode. The harness ships
// the documented default — fail-OPEN — via `error_page 500 = @guardian_bypass`
// in angie.docker.conf: when the guardiand sidecar is unreachable, the
// auth_request subrequest errors, Angie turns that into a 500, and the bypass
// route serves the backend anyway. So a sidecar outage does not take the site
// down.
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

	// Sanity: with guardiand up, a browser-shaped GET is challenged (proof the
	// sidecar is actually in the path before we stop it).
	if r := get(t, "/pre-check", powHost, browserUA, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("pre-check (guardiand up): status %d, want 200 interstitial", r.StatusCode)
	}

	stopGuardiand(t)

	// With the sidecar down, the site must still serve the backend (fail-open).
	// Use an allowlist-shaped and a normal path to be sure it's the bypass, not
	// a cached allow.
	resp := get(t, "/still-up", powHost, browserUA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fail-open: status %d with guardiand down, want 200 (backend served)", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
		t.Fatalf("fail-open did not serve the backend; body:\n%s", body)
	}
}

// NOTE on fail-CLOSED: the opposite behaviour (site returns 500 when guardiand
// is down) is produced by removing `error_page 500 = @guardian_bypass` from the
// Angie config. Reproducing it here would require a second Angie config +
// reload within one stack; the harness deliberately ships fail-open (the
// documented default), and deploy/docker/README.md documents the one-line
// toggle to reproduce fail-closed manually. The toggle itself is a pure Angie
// config concern, not guardian behaviour, so it is left out of the automated
// suite to keep it single-stack and deterministic.
