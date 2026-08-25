// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json/v2"
	"net/http"
	"testing"
)

// TestKeyRotationPreservesLiveTokens exercises the file-backed key lifecycle
// in the real Docker image. The harness mounts signing_key_file and
// previous_key_dir on its persistent key volume, so this proves the admin
// rotation can replace the live key without logging out visitors: a token
// minted before rotation and one minted afterwards must both vouch.
func TestKeyRotationPreservesLiveTokens(t *testing.T) {
	const (
		oldTokenIP = "203.0.113.241"
		newTokenIP = "203.0.113.242"
	)

	oldToken := solveThroughAuth(t, oldTokenIP)
	assertTokenVouches(t, oldTokenIP, oldToken, "before rotation")

	resp := adminReq(t, http.MethodPost, "/admin/rotate-key", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate key: status %d, want 200; body: %s", resp.StatusCode, bodyOf(t, resp))
	}
	var rotated struct {
		Rotated bool `json:"rotated"`
	}
	if err := json.UnmarshalRead(resp.Body, &rotated); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if !rotated.Rotated {
		t.Fatal("rotate response did not confirm rotation")
	}

	assertTokenVouches(t, oldTokenIP, oldToken, "after rotation")
	newToken := solveThroughAuth(t, newTokenIP)
	assertTokenVouches(t, newTokenIP, newToken, "new key")
}

func assertTokenVouches(t *testing.T, ip, token, stage string) {
	t.Helper()
	resp := req(t, http.MethodGet, auth+"/auth", map[string]string{
		"X-Guardian-Host":   powHost,
		"X-Guardian-IP":     ip,
		"X-Guardian-UA":     "Mozilla/5.0",
		"X-Guardian-URI":    "/page",
		"X-Guardian-Cookie": "guardian_token=" + token,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s token rejected: status %d, want 200", stage, resp.StatusCode)
	}
}
