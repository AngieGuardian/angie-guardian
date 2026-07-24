// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitter

import (
	"context"
	"testing"
	"time"
)

func TestFracStaysInBounds(t *testing.T) {
	const base = time.Second
	lo, hi := time.Duration(float64(base)*0.9), time.Duration(float64(base)*1.1)
	sawBelow, sawAbove := false, false
	for range 1000 {
		got := Frac(base, 0.10)
		if got < lo || got > hi {
			t.Fatalf("Frac out of ±10%% bounds: %v (want [%v,%v])", got, lo, hi)
		}
		if got < base {
			sawBelow = true
		}
		if got > base {
			sawAbove = true
		}
	}
	if !sawBelow || !sawAbove {
		t.Errorf("Frac never varied in both directions (below=%v above=%v)", sawBelow, sawAbove)
	}
}

func TestFracAndPhaseDegenerate(t *testing.T) {
	if Frac(0, 0.1) != 0 || Frac(time.Second, 0) != time.Second {
		t.Error("Frac must return d unchanged for non-positive d or frac")
	}
	if Phase(0) != 0 {
		t.Error("Phase(0) must be 0")
	}
	if p := Phase(time.Second); p < 0 || p >= time.Second {
		t.Errorf("Phase out of [0,d): %v", p)
	}
}

func TestSleepHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if Sleep(ctx, time.Hour) {
		t.Error("Sleep must return false when the context is already cancelled")
	}
	if !Sleep(context.Background(), time.Millisecond) {
		t.Error("Sleep must return true after a normal wait")
	}
}
