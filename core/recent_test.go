// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/metrics"
)

func TestRecentRing(t *testing.T) {
	var r recentRing

	// Empty ring.
	if got := r.list(0); len(got) != 0 {
		t.Fatalf("empty ring list = %d entries, want 0", len(got))
	}

	// Under capacity: newest first, limit respected.
	for i := 0; i < 5; i++ {
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	got := r.list(0)
	if len(got) != 5 || got[0].URI != "/4" || got[4].URI != "/0" {
		t.Fatalf("list = %+v, want /4../0 newest-first", got)
	}
	if got := r.list(2); len(got) != 2 || got[0].URI != "/4" || got[1].URI != "/3" {
		t.Fatalf("list(2) = %+v, want [/4 /3]", got)
	}

	// Overfill past capacity: oldest entries overwritten, order kept.
	for i := 5; i < defaultRecentDecisionsCapacity+10; i++ {
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	got = r.list(0)
	if len(got) != defaultRecentDecisionsCapacity {
		t.Fatalf("wrapped ring holds %d, want %d", len(got), defaultRecentDecisionsCapacity)
	}
	if got[0].URI != "/"+strconv.Itoa(defaultRecentDecisionsCapacity+9) {
		t.Errorf("newest = %s, want /%d", got[0].URI, defaultRecentDecisionsCapacity+9)
	}
	if got[defaultRecentDecisionsCapacity-1].URI != "/10" {
		t.Errorf("oldest = %s, want /10 (0..9 overwritten)", got[defaultRecentDecisionsCapacity-1].URI)
	}
}

func TestRecentRingCustomSizeAndSnapshot(t *testing.T) {
	r := newRecentRing(3)
	if snap := r.snapshot(0); len(snap.Decisions) != 0 || snap.Capacity != 3 || snap.Full || snap.StartedAt.IsZero() {
		t.Fatalf("empty snapshot = %+v, want initialized capacity 3", snap)
	}
	for i := 0; i < 4; i++ {
		if i == 3 {
			snap := r.snapshot(0)
			if snap.Full || len(snap.Decisions) != 3 {
				t.Fatalf("exact-capacity snapshot = %+v, want complete but not overwritten", snap)
			}
		}
		r.add(RecentDecision{URI: "/" + strconv.Itoa(i)})
	}
	snap := r.snapshot(0)
	if snap.Capacity != 3 || !snap.Full || len(snap.Decisions) != 3 {
		t.Fatalf("wrapped snapshot = %+v, want capacity 3 full with 3 entries", snap)
	}
	if snap.Decisions[0].URI != "/3" || snap.Decisions[2].URI != "/1" {
		t.Fatalf("wrapped decisions = %+v, want /3../1", snap.Decisions)
	}
}

func TestRecentRingConcurrentSnapshot(t *testing.T) {
	r := newRecentRing(64)
	var wg sync.WaitGroup
	for writer := 0; writer < 4; writer++ {
		wg.Go(func() {
			for i := 0; i < 1000; i++ {
				r.add(RecentDecision{Time: time.Now(), URI: "/" + strconv.Itoa(writer) + "/" + strconv.Itoa(i)})
				_ = r.snapshot(16)
			}
		})
	}
	wg.Wait()
	if snap := r.snapshot(0); len(snap.Decisions) != 64 || !snap.Full {
		t.Fatalf("final snapshot = %+v, want full 64-entry ring", snap)
	}
}

func BenchmarkRecentRingSnapshot(b *testing.B) {
	for _, size := range []int{512, 4096, 16384, 65536} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			r := newRecentRing(size)
			for i := 0; i < size; i++ {
				r.add(RecentDecision{
					Time: time.Now(), Host: "protected.example", IP: "203.0.113.10",
					Method: "GET", URI: "/wp-login.php?source=distributed-scan",
					UA:     "Mozilla/5.0 (compatible; GuardianBenchmarkBot/1.0)",
					Action: "deny", Reason: "denylist:ip",
					// Solve rows are the widest entry the ring holds, so the
					// snapshot cost is measured against a fully populated one.
					SolveMS: 1900, RoundTripMS: 2400, Bits: 20,
				})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = r.snapshot(0)
			}
		})
	}
}

// Every attacker-supplied field in a ring entry is capped, so a flood of
// oversized headers cannot pin capacity * header-budget bytes in a diagnostics
// buffer. Host and Method are as client-controlled as URI and UA: Angie passes
// through $host and $request_method verbatim, bounded only by its header buffer.
func TestRecentRingCapsEveryClientField(t *testing.T) {
	r := newRecentRing(4)
	r.add(RecentDecision{
		Host:   strings.Repeat("h", 4096),
		Method: strings.Repeat("M", 4096),
		URI:    strings.Repeat("u", 16384),
		UA:     strings.Repeat("a", 16384),
	})
	got := r.list(1)
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	for _, f := range []struct {
		name  string
		value string
		cap   int
	}{
		{"Host", got[0].Host, maxRecentHostLen},
		{"Method", got[0].Method, maxRecentMethodLen},
		{"URI", got[0].URI, maxRecentURILen},
		{"UA", got[0].UA, maxRecentUALen},
	} {
		// The cap plus the multi-byte ellipsis that marks the cut.
		if want := f.cap + len("…"); len(f.value) != want {
			t.Errorf("%s length = %d, want %d", f.name, len(f.value), want)
		}
		if !strings.HasSuffix(f.value, "…") {
			t.Errorf("%s is not marked as truncated: %q", f.name, f.value)
		}
	}
}

// A redeemed challenge lands in the same ring as the decisions, carrying what
// the client paid and what it was asked for. Same-path attribution is the whole
// point: without it a slow solve is only a number in a process-wide histogram.
func TestRecordSolve(t *testing.T) {
	e := &Engine{recent: newRecentRing(8)}
	e.RecordSolve(SolveRecord{
		Host: "shop.test", IP: "198.51.100.7", URI: "/checkout",
		UA: "Mozilla/5.0", SolveMS: 1900, RoundTripMS: 2400,
		Algorithm: "sha256", Bits: 20,
	})
	got := e.recent.list(0)
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	d := got[0]
	if d.Action != ActionSolve || d.Reason != ReasonSolved {
		t.Errorf("action/reason = %s/%s, want %s/%s", d.Action, d.Reason, ActionSolve, ReasonSolved)
	}
	if d.SolveMS != 1900 || d.RoundTripMS != 2400 || d.Bits != 20 {
		t.Errorf("solve = %dms / round trip %dms / %d bits, want 1900/2400/20",
			d.SolveMS, d.RoundTripMS, d.Bits)
	}
	if d.PoWAlgorithm != "sha256" || d.Argon2MemoryKiB != 0 || d.Argon2Iterations != 0 {
		t.Errorf("proof = %q/%d/%d, want sha256/0/0", d.PoWAlgorithm, d.Argon2MemoryKiB, d.Argon2Iterations)
	}
	if d.Host != "shop.test" || d.IP != "198.51.100.7" || d.URI != "/checkout" {
		t.Errorf("attribution = %s %s %s, want shop.test 198.51.100.7 /checkout", d.Host, d.IP, d.URI)
	}
	// The redemption is a POST to the pass endpoint; naming that as the request
	// method would describe the wrong hop.
	if d.Method != "" {
		t.Errorf("method = %q, want empty on a solve row", d.Method)
	}
	if d.Time.IsZero() {
		t.Error("solve row has no timestamp")
	}
}

func TestRecordArgon2IDSolve(t *testing.T) {
	e := &Engine{recent: newRecentRing(8)}
	e.RecordSolve(SolveRecord{
		Host: "shop.test", IP: "198.51.100.8", URI: "/checkout",
		Algorithm: "argon2id", MemoryKiB: 8192, Iterations: 2,
		SolveMS: 120, RoundTripMS: 300,
	})
	d := e.recent.list(1)[0]
	if d.PoWAlgorithm != "argon2id" || d.Argon2MemoryKiB != 8192 || d.Argon2Iterations != 2 || d.Bits != 0 {
		t.Errorf("proof = %q/%d/%d/%d bits, want argon2id/8192/2/0",
			d.PoWAlgorithm, d.Argon2MemoryKiB, d.Argon2Iterations, d.Bits)
	}
}

// A failed redemption lands in the same ring, carrying who failed and why:
// the funnel metric counts these without a reason, and the ring row is what
// lets an operator tell a garbage-nonce bot from a visitor whose VPN moved
// them to a new exit IP mid-challenge.
func TestRecordRedeemFailure(t *testing.T) {
	e := &Engine{recent: newRecentRing(8)}
	e.RecordRedeemFailure("shop.test", "198.51.100.7", "Mozilla/5.0", ReasonBindingMismatch)
	got := e.recent.list(0)
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	d := got[0]
	if d.Action != ActionRedeemFail || d.Reason != ReasonBindingMismatch {
		t.Errorf("action/reason = %s/%s, want %s/%s", d.Action, d.Reason, ActionRedeemFail, ReasonBindingMismatch)
	}
	if d.Host != "shop.test" || d.IP != "198.51.100.7" || d.UA != "Mozilla/5.0" {
		t.Errorf("attribution = %s %s %s, want shop.test 198.51.100.7 Mozilla/5.0", d.Host, d.IP, d.UA)
	}
	// No verified challenge record exists on the failure path, so the solve
	// fields must read as "unknown", never as an instant solve at difficulty 0.
	if d.SolveMS != 0 || d.RoundTripMS != 0 || d.Bits != 0 || d.PoWAlgorithm != "" || d.Argon2MemoryKiB != 0 || d.Argon2Iterations != 0 {
		t.Errorf("solve fields = %d/%d/%q/%d/%d/%d, want all zero on a failure row",
			d.SolveMS, d.RoundTripMS, d.PoWAlgorithm, d.Bits, d.Argon2MemoryKiB, d.Argon2Iterations)
	}
	if d.URI != "" || d.Method != "" {
		t.Errorf("uri/method = %q/%q, want empty on a failure row", d.URI, d.Method)
	}
	if d.Time.IsZero() {
		t.Error("failure row has no timestamp")
	}
}

// A no-JS redemption waited out the meta refresh instead of computing, so it has
// no solve time to report and must not be recorded as an instant solve.
func TestRecordSolveNoJS(t *testing.T) {
	e := &Engine{recent: newRecentRing(8)}
	e.RecordSolve(SolveRecord{Host: "shop.test", IP: "198.51.100.7", RoundTripMS: 5000, Bits: 18, NoJS: true})
	d := e.recent.list(1)[0]
	if d.Reason != ReasonNoJS {
		t.Errorf("reason = %s, want %s", d.Reason, ReasonNoJS)
	}
	if d.SolveMS != 0 {
		t.Errorf("solve_ms = %d, want 0 (no proof was computed)", d.SolveMS)
	}
	if d.RoundTripMS != 5000 {
		t.Errorf("round_trip_ms = %d, want 5000", d.RoundTripMS)
	}
}

// Durations and difficulty cross a package boundary as int64/int. Saturating
// keeps an absurd value obviously absurd; wrapping would turn it into a small
// or negative number that reads as a real, fast solve.
func TestSolveFieldsSaturate(t *testing.T) {
	if got := clampMS(math.MaxInt64); got != math.MaxInt32 {
		t.Errorf("clampMS(maxint64) = %d, want %d", got, math.MaxInt32)
	}
	if got := clampMS(-5); got != 0 {
		t.Errorf("clampMS(-5) = %d, want 0", got)
	}
	if got := clampBits(9000); got != math.MaxUint8 {
		t.Errorf("clampBits(9000) = %d, want %d", got, math.MaxUint8)
	}
	if got := clampBits(-1); got != 0 {
		t.Errorf("clampBits(-1) = %d, want 0", got)
	}
}

// Solve rows carry the same attacker-supplied strings as decision rows, so they
// go through the same caps: RecordSolve must not be a way around them.
func TestRecordSolveCapsClientFields(t *testing.T) {
	e := &Engine{recent: newRecentRing(4)}
	e.RecordSolve(SolveRecord{
		Host: strings.Repeat("h", 4096),
		URI:  strings.Repeat("u", 16384),
		UA:   strings.Repeat("a", 16384),
	})
	d := e.recent.list(1)[0]
	for _, f := range []struct {
		name  string
		value string
		cap   int
	}{
		{"Host", d.Host, maxRecentHostLen},
		{"URI", d.URI, maxRecentURILen},
		{"UA", d.UA, maxRecentUALen},
	} {
		if want := f.cap + len("…"); len(f.value) != want {
			t.Errorf("%s length = %d, want %d", f.name, len(f.value), want)
		}
	}
}

// A redemption is not a pipeline decision and must never be counted as one.
// RecordSolve deliberately bypasses Evaluate, and this pins the consequence:
// guardian_decisions_total stays untouched. If a future tidy-up routes solves
// through Evaluate, every reason rate and per-domain decision total silently
// inflates by the solve volume, which on a healthy proof-of-work site is a
// large share of traffic, and the original challenge row has already counted
// that same client journey once.
func TestRecordSolveIsNotADecision(t *testing.T) {
	m := metrics.New("memory")
	e := &Engine{recent: newRecentRing(64), metrics: m}
	for range 25 {
		e.RecordSolve(SolveRecord{
			Host: "shop.test", IP: "198.51.100.7", URI: "/", UA: "Mozilla/5.0",
			SolveMS: 900, RoundTripMS: 1200, Bits: 18,
		})
	}
	if got := len(e.recent.list(0)); got != 25 {
		t.Fatalf("recorded %d rows, want 25", got)
	}

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		switch mf.GetName() {
		case "guardian_decisions_total":
			t.Errorf("a solve was counted as a decision: %v", mf.GetMetric())
		case "guardian_evaluate_seconds":
			// Evaluate's own latency histogram: a solve never ran the pipeline,
			// so timing it here would report work that did not happen.
			for _, series := range mf.GetMetric() {
				if n := series.GetHistogram().GetSampleCount(); n > 0 {
					t.Errorf("a solve was timed as an evaluation: %d samples", n)
				}
			}
		}
	}
}
