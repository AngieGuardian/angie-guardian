// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"os"
	"testing"
)

// Keep real-time outage/timeout qualification out of routine CI/CD. See
// AGENTS.md in this directory before changing the opt-in policy.
func requireExtendedE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("GUARDIAN_E2E_EXTENDED") != "1" {
		t.Skip("extended local qualification: run make e2e-extended")
	}
}
