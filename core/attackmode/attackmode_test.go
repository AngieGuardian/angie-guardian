// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package attackmode

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Enabled:             true,
		Window:              30 * time.Second, // 6 buckets
		MinDwell:            30 * time.Second,
		ChallengeRate:       200,
		AttackChallengeRate: 1000,
		MinSolveRatio:       0.2,
		StoreErrorRatio:     0.05,
		StoreSlowRatio:      0.25,
		ElevatedBits:        2,
		AttackBits:          4,
		CapBits:             28,
		ForceAlways:         true,
		Stateless:           true,
	}
}

// clock is a manually-advanced clock for deterministic dwell tests.
type clock struct{ t atomic.Int64 }

func (c *clock) now() time.Time      { return time.Unix(0, c.t.Load()) }
func (c *clock) add(d time.Duration) { c.t.Add(int64(d)) }

func newTestDetector(t *testing.T, cfg Config) (*Detector, *clock) {
	t.Helper()
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, nil, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)
	return d, c
}

// feed issues n challenges and advances one tick.
func issueAndTick(d *Detector, c *clock, issued, redeemed int) {
	for range issued {
		d.ChallengeIssued()
	}
	for range redeemed {
		d.ChallengeRedeemed()
	}
	c.add(bucketWidth)
	d.TickForTest()
}

func TestDetectorNilReceiver(t *testing.T) {
	var d *Detector
	d.Evaluated()
	d.ChallengeIssued()
	d.StoreOp("get", 0, nil)
	d.Pin(Attack, time.Minute)
	if d.State().Level != Normal {
		t.Fatal("nil detector not normal")
	}
	d.Close()
}

// TestInitialStateHasSince guards the admin API's "normal since ..." field. A
// detector that never leaves Normal never calls publish(), so an unstamped
// initial state would report the zero time for the daemon's whole life, which
// a local-time formatter renders as a plausible-looking year-1 clock reading.
func TestInitialStateHasSince(t *testing.T) {
	before := time.Now()
	d := New(testConfig(), nil, slog.New(slog.DiscardHandler))
	t.Cleanup(d.Close)

	since := d.State().Since
	if since.IsZero() {
		t.Fatal("initial state Since is the zero time; the admin API would report 0001-01-01T00:00:00Z")
	}
	if since.Before(before) || since.After(time.Now()) {
		t.Fatalf("initial state Since = %v, want a stamp taken during New()", since)
	}
}

func TestEntersElevatedOnChallengeRate(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	// 6 buckets * 5s = 30s window. 300 issued/tick over 5s = 60/s per bucket
	// summed: need > 200/s window average. Push 1500/tick = 300/s.
	for range 3 {
		issueAndTick(d, c, 1500, 1500)
	}
	if got := d.State().Level; got != Elevated {
		t.Fatalf("level = %s, want elevated (challenge_rate)", got)
	}
	if got := d.State().Reason; got != "challenge_rate" {
		t.Fatalf("reason = %q", got)
	}
	if got := d.State().ExtraBits; got != 2 {
		t.Fatalf("elevated extra bits = %d, want 2", got)
	}
}

func TestAttackNeedsLowSolveRatio(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	// Above the attack issuance rate but ALL solved: a flash crowd, not an
	// attack. Must stay at most elevated, never attack.
	for range 3 {
		issueAndTick(d, c, 6000, 6000) // 1200/s, solve ratio 1.0
	}
	if d.State().Level == Attack {
		t.Fatal("high solve ratio must not trip attack (flash crowd)")
	}

	// Same volume, almost none solved: a bot flood.
	d2, c2 := newTestDetector(t, testConfig())
	for range 3 {
		issueAndTick(d2, c2, 6000, 10) // 1200/s, solve ratio ~0
	}
	if d2.State().Level != Attack {
		t.Fatalf("bot flood level = %s, want attack", d2.State().Level)
	}
	if d2.State().ExtraBits != 4 || !d2.State().Stateless || !d2.State().ForceAlways {
		t.Fatalf("attack effects = %+v", d2.State())
	}
}

func TestStoreDegradationTriggers(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	// 100 ops/tick, 10 errors/tick = 10% error ratio > 5% elevated threshold.
	for range 2 {
		for i := range 100 {
			var err error
			if i < 10 {
				err = errBoom
			}
			d.StoreOp("get", 0, err)
		}
		c.add(bucketWidth)
		d.TickForTest()
	}
	if d.State().Level != Elevated || d.State().Reason != "store_errors" {
		t.Fatalf("store errors: level=%s reason=%q", d.State().Level, d.State().Reason)
	}

	// 3x the threshold enters attack.
	d2, c2 := newTestDetector(t, testConfig())
	for range 2 {
		for i := range 100 {
			var err error
			if i < 20 { // 20% > 3*5%
				err = errBoom
			}
			d2.StoreOp("get", 0, err)
		}
		c2.add(bucketWidth)
		d2.TickForTest()
	}
	if d2.State().Level != Attack {
		t.Fatalf("heavy store errors level = %s, want attack", d2.State().Level)
	}
}

func TestHysteresisAndDwell(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	for range 3 {
		issueAndTick(d, c, 1500, 1500) // 300/s -> elevated
	}
	if d.State().Level != Elevated {
		t.Fatalf("setup: level = %s", d.State().Level)
	}
	// Stop the flood. Within min_dwell the level must NOT decay yet.
	issueAndTick(d, c, 0, 0)
	if d.State().Level != Elevated {
		t.Fatal("decayed before min_dwell elapsed")
	}
	// Advance past min_dwell (window flushes to zero, then dwell passes).
	for range 10 {
		issueAndTick(d, c, 0, 0)
	}
	if d.State().Level != Normal {
		t.Fatalf("did not decay to normal after dwell, level = %s", d.State().Level)
	}
}

// TestHalfThresholdExitHolds: load sustained between 50% and 100% of the entry
// threshold must HOLD the level (not decay), per the documented "stay below
// half for min_dwell" hysteresis.
func TestHalfThresholdExitHolds(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	// challenge_rate threshold is 200/s. Trip elevated at 300/s.
	for range 3 {
		issueAndTick(d, c, 1500, 1500) // 300/s
	}
	if d.State().Level != Elevated {
		t.Fatalf("setup: level = %s", d.State().Level)
	}
	// Settle at 75% of threshold: 150/s (750 issued/tick). Above half (100/s),
	// below full (200/s). This must HOLD elevated indefinitely.
	for range 20 {
		issueAndTick(d, c, 750, 750) // 150/s, all solved
		if d.State().Level != Elevated {
			t.Fatalf("level decayed under sustained 75%% load: %s (must hold above half)", d.State().Level)
		}
	}
	// Drop below half (25/s = 125 issued/tick) and it eventually decays.
	decayed := false
	for range 20 {
		issueAndTick(d, c, 125, 125) // 25/s, below half
		if d.State().Level == Normal {
			decayed = true
			break
		}
	}
	if !decayed {
		t.Fatal("level never decayed after signals dropped below half")
	}
}

func TestOneStepDecay(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	for range 3 {
		issueAndTick(d, c, 6000, 10) // attack
	}
	if d.State().Level != Attack {
		t.Fatalf("setup: level = %s", d.State().Level)
	}
	// One quiet dwell period drops exactly one step (attack -> elevated),
	// not straight to normal.
	seen := map[Level]bool{}
	for range 20 {
		issueAndTick(d, c, 0, 0)
		seen[d.State().Level] = true
		if d.State().Level == Normal {
			break
		}
	}
	if !seen[Elevated] {
		t.Fatal("decay skipped the elevated step")
	}
}

func TestPinOverridesDetection(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	d.Pin(Attack, time.Minute)
	if d.State().Level != Attack {
		t.Fatal("pin attack did not take")
	}
	if lvl, ok := d.Pinned(); !ok || lvl != Attack {
		t.Fatalf("Pinned = %s, %v", lvl, ok)
	}
	// Even with zero traffic the pin holds.
	issueAndTick(d, c, 0, 0)
	if d.State().Level != Attack {
		t.Fatal("pin did not hold through a tick")
	}
	// Pin normal is a kill switch: heavy flood cannot raise it.
	d.Pin(Normal, 0)
	for range 3 {
		issueAndTick(d, c, 6000, 10)
	}
	if d.State().Level != Normal {
		t.Fatalf("pinned-normal kill switch failed, level = %s", d.State().Level)
	}
	d.Unpin()
	if _, ok := d.Pinned(); ok {
		t.Fatal("unpin did not clear")
	}
}

func TestPinTTLExpires(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	d.Pin(Attack, 3*bucketWidth)
	issueAndTick(d, c, 0, 0)
	if d.State().Level != Attack {
		t.Fatal("pin expired too early")
	}
	for range 3 {
		issueAndTick(d, c, 0, 0)
	}
	if _, ok := d.Pinned(); ok {
		t.Fatal("pin TTL did not expire")
	}
	if d.State().Level != Normal {
		t.Fatalf("post-expiry level = %s, want normal", d.State().Level)
	}
}

func TestOnTransitionFires(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	var mu sync.Mutex
	var transitions []string
	d.OnTransition(func(from, to Level, reason string) {
		mu.Lock()
		transitions = append(transitions, from.String()+"->"+to.String())
		mu.Unlock()
	})
	// Ramp gently: first a challenge_rate above elevated but below attack, so
	// the first transition is normal->elevated, then escalate to attack. Run
	// the attack burst for a full window so the earlier solved buckets flush
	// out and the window solve ratio clears MinSolveRatio.
	for range 2 {
		issueAndTick(d, c, 1500, 1500) // 300/s, solved: elevated
	}
	for range 7 {
		issueAndTick(d, c, 12000, 5) // 2400/s, unsolved: attack
	}
	mu.Lock()
	defer mu.Unlock()
	if len(transitions) < 2 || transitions[0] != "normal->elevated" || transitions[len(transitions)-1] != "elevated->attack" {
		t.Fatalf("transitions = %v, want normal->elevated ... elevated->attack", transitions)
	}
}

// TestConcurrentPinAndTick exercises the evalMu serialization: an admin Pin
// racing the ticker must not trip the race detector or revert the pin.
func TestConcurrentPinAndTick(t *testing.T) {
	d, c := newTestDetector(t, testConfig())
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				c.add(bucketWidth)
				d.TickForTest()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				d.Pin(Attack, time.Minute)
			} else {
				d.Unpin()
			}
		}
		close(stop)
	}()
	wg.Wait()
	// After a final pin, the level must reflect it (serialized, not reverted).
	d.Pin(Attack, time.Minute)
	if d.State().Level != Attack {
		t.Fatalf("final pin not honored: level = %s", d.State().Level)
	}
}

func TestDisabledStaysNormal(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	d, c := newTestDetector(t, cfg)
	for range 3 {
		issueAndTick(d, c, 6000, 10)
	}
	if d.State().Level != Normal {
		t.Fatalf("disabled detector rose to %s", d.State().Level)
	}
}

func TestEffectiveBits(t *testing.T) {
	// No raise: window unchanged.
	if b, m := EffectiveBits(&State{ExtraBits: 0}, 20, 24, 28); b != 20 || m != 24 {
		t.Fatalf("no-raise = %d/%d", b, m)
	}
	// +4 shifts both floor and ceiling.
	if b, m := EffectiveBits(&State{ExtraBits: 4}, 20, 24, 28); b != 24 || m != 28 {
		t.Fatalf("+4 = %d/%d, want 24/28", b, m)
	}
	// Cap clamps; effMax never below effBase.
	if b, m := EffectiveBits(&State{ExtraBits: 4}, 26, 27, 28); b != 28 || m != 28 {
		t.Fatalf("clamp = %d/%d, want 28/28", b, m)
	}
	// A cap BELOW the domain base must never lower difficulty: the raise can
	// only raise. base 30, cap 28 -> effBase stays >= 30, effMax >= domain max.
	if b, m := EffectiveBits(&State{ExtraBits: 4, CapBits: 28}, 30, 30, 28); b < 30 || m < 30 {
		t.Fatalf("cap-below-base = %d/%d, want both >= 30 (raise must not lower difficulty)", b, m)
	}
	// Nil state is safe.
	if b, m := EffectiveBits(nil, 20, 24, 28); b != 20 || m != 24 {
		t.Fatalf("nil = %d/%d", b, m)
	}
}

var errBoom = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }
