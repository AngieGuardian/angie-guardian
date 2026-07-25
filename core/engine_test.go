// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"testing"
	"time"
)

// BlockDetailFor adds expiry and the repeat-offender count to the single-IP
// lookup, which previously reported strictly less than the list endpoint.
func TestBlockDetailFor(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()

	// Not blocked, never blocked: no expiry, no offense count, no error.
	d, err := e.BlockDetailFor(ctx, "198.51.100.7")
	if err != nil {
		t.Fatalf("BlockDetailFor: %v", err)
	}
	if d.Blocked || d.ExpiresAt != nil || d.Offenses != nil {
		t.Fatalf("clean IP = %+v, want blocked=false with no enrichment", d)
	}

	if err := e.BlockIP(ctx, "198.51.100.7", "manual", time.Hour); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	d, err = e.BlockDetailFor(ctx, "198.51.100.7")
	if err != nil {
		t.Fatalf("BlockDetailFor: %v", err)
	}
	if !d.Blocked || d.Reason != "manual" {
		t.Fatalf("blocked IP = %+v, want blocked with reason manual", d)
	}
	if d.ExpiresAt == nil {
		t.Fatal("blocked IP reported no expiry; the list endpoint would have one")
	}
	if got := time.Until(*d.ExpiresAt); got < 50*time.Minute || got > time.Hour+time.Minute {
		t.Fatalf("expiry in %v, want about an hour", got)
	}
}

// A prefix scan for block:10.0.0.1 also matches block:10.0.0.10 and
// block:10.0.0.100, so the expiry lookup must compare the whole key.
//
// The target is blocked permanently (no expiry) while its neighbours expire,
// which is what makes this test able to fail: the target sorts first among its
// own prefix-neighbours, so a first-row-wins bug would still stumble onto the
// right row if every row had an expiry. Here the only expiry in range belongs
// to a neighbour, so reporting one at all means the wrong key was read.
func TestBlockDetailExpiryIgnoresPrefixNeighbours(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()

	if err := e.BlockIP(ctx, "10.0.0.1", "target", 0); err != nil { // 0 = no expiry
		t.Fatal(err)
	}
	if err := e.BlockIP(ctx, "10.0.0.10", "neighbour", 100*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := e.BlockIP(ctx, "10.0.0.100", "neighbour", 200*time.Hour); err != nil {
		t.Fatal(err)
	}

	d, err := e.BlockDetailFor(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("BlockDetailFor: %v", err)
	}
	if d.Reason != "target" {
		t.Fatalf("reason = %q, want target", d.Reason)
	}
	if d.ExpiresAt != nil {
		t.Fatalf("expiry %v reported for a permanent block: a prefix neighbour's expiry leaked through", *d.ExpiresAt)
	}

	// And the neighbour itself still reports its own expiry correctly.
	n, err := e.BlockDetailFor(ctx, "10.0.0.10")
	if err != nil {
		t.Fatalf("BlockDetailFor neighbour: %v", err)
	}
	if n.ExpiresAt == nil {
		t.Fatal("neighbour lost its expiry")
	}
	if got := time.Until(*n.ExpiresAt); got < 99*time.Hour || got > 101*time.Hour {
		t.Fatalf("neighbour expiry in %v, want about 100h", got)
	}
}

// The backoff counter is reported even when the IP is not currently blocked:
// "blocked 3 times today, currently clear" is the state worth seeing.
func TestBlockDetailReportsOffenses(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	const ip = "203.0.113.9"

	for range 3 {
		if err := e.board.Block(ctx, ip, "threshold:pow_fail", time.Minute, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.UnblockIP(ctx, ip); err != nil {
		t.Fatal(err)
	}

	d, err := e.BlockDetailFor(ctx, ip)
	if err != nil {
		t.Fatalf("BlockDetailFor: %v", err)
	}
	if d.Blocked {
		t.Fatal("IP should be unblocked")
	}
	if d.Offenses == nil {
		t.Fatal("no offense count after three blocks")
	}
	if *d.Offenses != 3 {
		t.Fatalf("offenses = %d, want 3", *d.Offenses)
	}
}
