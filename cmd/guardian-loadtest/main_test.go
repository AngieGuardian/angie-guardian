// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

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
