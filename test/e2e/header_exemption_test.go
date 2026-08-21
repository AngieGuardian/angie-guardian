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

func TestHeaderPoWExemptionThroughAngie(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	// Without the configured marker, this PoW-enabled path serves the normal
	// interstitial. fetchChallenge supplies real navigation headers.
	_ = fetchChallenge(t, "/machine-api/items", powHost, browserUA)

	headers := map[string]string{"X-E2E-Machine-Proof": "Harness opaque-value"}
	resp := get(t, "/machine-api/items", powHost, "machine-client/1.0", headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("matching marker: status %d, want backend 200", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Hostname:") {
		t.Fatalf("matching marker did not reach backend; body:\n%s", body)
	}

	// The classification is not a WAF allow. A deny rule still wins.
	if resp := get(t, "/machine-api/wp-login.php", powHost, "machine-client/1.0", headers); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("WAF deny with marker: status %d, want 403", resp.StatusCode)
	}

	// A challenge-only WAF rule is a PoW outcome and is suppressed.
	resp = get(t, "/machine-api/search?q="+urlEscape("' or 1=1"), powHost, "machine-client/1.0", headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("WAF challenge with marker: status %d, want backend 200", resp.StatusCode)
	}

	// The WAF-denied request terminates before classification, so only the
	// backend pass and challenge-rule suppression increment this series.
	if got := metric(t, "guardian_pow_header_exemptions_total", `outcome="matched",verifier="none"`); got < 2 {
		t.Fatalf("matched classification metric = %v, want at least 2", got)
	}
}
