// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jitter spreads periodic background work so a fleet restarted
// together does not fire the same store, DNS or feed-origin traffic in
// lockstep on every tick.
package jitter

import (
	"context"
	"math/rand/v2"
	"time"
)

// Fraction is the default relative jitter (±10%) applied to an interval.
const Fraction = 0.10

// Frac returns d perturbed by a uniform ±frac (e.g. frac 0.1 gives [0.9d,
// 1.1d]). A non-positive d or frac returns d unchanged. math/rand/v2 is
// goroutine-safe and needs no seeding.
func Frac(d time.Duration, frac float64) time.Duration {
	if d <= 0 || frac <= 0 {
		return d
	}
	// (rand-0.5)*2 ∈ [-1,1], scaled by frac.
	delta := float64(d) * frac * (rand.Float64()*2 - 1)
	return d + time.Duration(delta)
}

// Phase returns a random startup offset in [0, d) so instances that begin a
// loop at the same instant do not stay aligned. Non-positive d returns 0.
func Phase(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)))
}

// Sleep waits for d or until ctx is done, reporting false if the context was
// cancelled first (the caller should stop).
func Sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
