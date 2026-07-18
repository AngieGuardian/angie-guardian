// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestBlockOffloadMirror proves the enforcement mirror through the real
// stack: once a behavioural block is placed, repeated requests from the
// blocked IP are denied by the in-process mirror with ZERO store reads, the
// admin offload endpoint reports the seeded mirror, and an admin unblock
// propagates write-through (no reconcile wait).
func TestBlockOffloadMirror(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks() // start clean

	// Place a behavioural block via the dotfile-probe `block` rule.
	if r := get(t, "/.env", wafOnlyHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("/.env: status %d, want 403", r.StatusCode)
	}
	if ip, _ := findBlockedGateway(t); ip == "" {
		t.Fatal("/.env did not place a behavioural block")
	}

	// One denied request to confirm enforcement, then snapshot the counters.
	if r := get(t, "/benign", wafOnlyHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked IP: status %d, want 403", r.StatusCode)
	}
	mirrorHits := metric(t, "guardian_block_lookups_total", `source="mirror"`, `outcome="hit"`)
	storeGets := metric(t, "guardian_store_ops_total", `op="get"`)

	// A burst from the blocked IP: every request denied, every denial a
	// mirror hit, and the store read count must not move at all. This is the
	// DDoS property the mirror exists for.
	const burst = 20
	for range burst {
		if r := get(t, "/benign", wafOnlyHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
			t.Fatalf("blocked IP during burst: status %d, want 403", r.StatusCode)
		}
	}
	if got := metric(t, "guardian_block_lookups_total", `source="mirror"`, `outcome="hit"`); got < mirrorHits+burst {
		t.Fatalf("mirror hits = %v, want >= %v (burst of %d not served from the mirror)", got, mirrorHits+burst, burst)
	}
	if got := metric(t, "guardian_store_ops_total", `op="get"`); got != storeGets {
		t.Fatalf("store gets moved %v -> %v during the burst; blocked traffic must not touch the store", storeGets, got)
	}

	// The admin surface reports the mirror.
	resp := adminReq(t, http.MethodGet, "/admin/offload", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/offload: status %d", resp.StatusCode)
	}
	var status struct {
		Mirror struct {
			Entries int    `json:"entries"`
			Mode    string `json:"mode"`
			Seeded  bool   `json:"seeded"`
		} `json:"mirror"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode offload status: %v", err)
	}
	if !status.Mirror.Seeded || status.Mirror.Entries < 1 || status.Mirror.Mode != "authoritative" {
		t.Fatalf("offload status = %+v, want seeded authoritative mirror with the block", status.Mirror)
	}
	if resp := adminReq(t, http.MethodPost, "/admin/offload/reconcile", nil); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("/admin/offload/reconcile: status %d, want 202", resp.StatusCode)
	}

	// Unblocking through the admin API restores access immediately: the
	// removal is written through to the mirror, not discovered by a scan.
	clearGatewayBlocks()
	if r := get(t, "/benign", wafOnlyHost, "curl/8.0", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("after unblock: status %d, want 200", r.StatusCode)
	}
}
