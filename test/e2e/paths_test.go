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

// The e2e config gives powHost a per-path overlay: paths "/api/" disables PoW
// while the WAF (inherited from defaults) stays on. These tests prove the
// split works end to end through a real Angie: same host, different paths,
// different PoW policy, one WAF.

// TestPathOverridePoWDisabled: a machine client under /api/ passes straight
// through to the backend, while the rest of the host still serves the
// interstitial.
func TestPathOverridePoWDisabled(t *testing.T) {
	// PoW disabled under /api/: no browser UA, no cookie, straight to whoami.
	resp := get(t, "/api/v1/items", powHost, "machine-client/1.0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/v1/items: status %d, want 200 passthrough", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
		t.Fatalf("/api/v1/items did not reach whoami backend; body:\n%s", body)
	}

	// The same client outside /api/ still gets the PoW interstitial.
	resp = get(t, "/app/page", powHost, browserUA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/app/page interstitial: status %d, want 200", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "guardian-data") {
		t.Fatalf("/app/page did not serve the PoW interstitial; body:\n%s", body)
	}

	// A percent-encoded path cannot dodge the overlay in either direction:
	// the config matches the decoded path.
	resp = get(t, "/api%2Fv1%2Fitems", powHost, "machine-client/1.0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("encoded /api path: status %d, want 200 passthrough", resp.StatusCode)
	}
}

// TestPathOverrideWAFStillActive: disabling PoW for /api/ must not soften the
// WAF there; a rule probe under the PoW-free prefix is still denied.
func TestPathOverrideWAFStillActive(t *testing.T) {
	// wp-cms-probe is a deny rule (no behavioural block), so this leaves no state.
	resp := get(t, "/api/wp-login.php", powHost, "machine-client/1.0", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/api/wp-login.php: status %d, want 403 (WAF must stay active on the PoW-free path)", resp.StatusCode)
	}
}
