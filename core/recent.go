// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"math"
	"sync"
	"time"
)

// RecentDecision is one entry in a small in-process ring buffer so the admin
// API (and the dashboard built on it) can answer "what did the guardian just
// act on, and what did it cost the client?" without a store write on either
// path. Three kinds of entry share the ring:
//
//   - every terminal non-allow decision. Allows are deliberately not recorded:
//     they are the overwhelming common case and carry no report value.
//   - every redeemed proof-of-work challenge (ActionSolve). A solve arrives on
//     a later, separate request, so it is a second row rather than an update of
//     the challenge row: the two carry no shared identifier. Recording it here
//     is what makes a slow solve attributable to a host, path, IP and UA
//     instead of vanishing into one process-wide histogram.
//   - every failed redemption attempt (ActionRedeemFail). The funnel metric
//     counts these without a reason; this row is what tells an operator
//     whether "failed 3" was a bot posting garbage nonces or a real visitor
//     whose VPN moved them to a new exit IP mid-challenge.
//
// The last two are outcome rows: they describe what later happened to a
// challenge whose decision row already exists. Aggregates that count verdicts
// (offender rankings, decision totals, the decision charts) must skip both,
// keyed on the action; anything less re-counts a client journey the challenge
// row already recorded.
//
// The buffer is per-instance and cleared on restart: a live operator view,
// not an audit log (that role belongs to the structured decision log).
type RecentDecision struct {
	Time   time.Time `json:"time"`
	Host   string    `json:"host"`
	IP     string    `json:"ip"`
	Method string    `json:"method"`
	URI    string    `json:"uri"`
	UA     string    `json:"ua"`
	Action string    `json:"action"`
	Reason string    `json:"reason"`

	// The fields below are set only on ActionSolve rows and omitted everywhere
	// else, so a deny row is byte-identical on the wire to what it was before
	// solves shared this ring, and absent reads as "unknown" rather than zero.

	// SolveMS is what the client said its solver spent computing (a
	// performance.now() delta around the workers). UNAUTHENTICATED telemetry,
	// kept because it is the only measurement of pure client work used to tune
	// SHA-256 difficulty or Argon2id parameters. 0 means "not reported": a
	// no-JS redemption, or a value rejected as physically impossible. It never
	// means "instant".
	SolveMS int32 `json:"solve_ms,omitzero"`
	// RoundTripMS is issue to redeem, measured here from the challenge's own
	// issued-at. Not forgeable, but not solve time either: it includes page
	// load, both network legs and any time the tab spent backgrounded. On one
	// instance it bounds SolveMS from above; across instances it does so only
	// within pow.ClockSkewAllowance, since the challenge may carry a peer's
	// clock. Never a substitute for SolveMS.
	RoundTripMS int32 `json:"round_trip_ms,omitzero"`
	// PoWAlgorithm identifies how the solve was produced. RecordSolve maps an
	// omitted value from older/internal callers to SHA-256.
	PoWAlgorithm string `json:"pow_algorithm,omitempty"`
	// Bits is set for SHA-256 and is the leading-zero-bit difficulty this
	// challenge actually required after any escalation.
	Bits uint8 `json:"bits,omitzero"`
	// Argon2MemoryKiB and Argon2Iterations are the authenticated fixed-result
	// work parameters for an Argon2id solve. They are zero for SHA-256.
	Argon2MemoryKiB  uint32 `json:"argon2_memory_kib,omitzero"`
	Argon2Iterations uint32 `json:"argon2_iterations,omitzero"`
}

// The vocabulary for outcome rows. ActionSolve and ActionRedeemFail are
// deliberately not stateless.Actions: no rule or stage can produce them and
// Evaluate never returns them, so the decision vocabulary stays exactly the
// verdicts the pipeline can reach. Everything that must exclude outcomes keys
// on the action, never on the reason string, which would need the same special
// case in three places and would rot the first time a new reason appears.
const (
	ActionSolve      = "solve"
	ActionRedeemFail = "redeem_fail"

	ReasonSolved = "pow:solved" // a real proof of work was verified
	ReasonNoJS   = "pow:nojs"   // the meta-refresh wait was accepted; nothing was hashed

	// Failure reasons, mirroring the pow package's redeem errors one-to-one.
	// All "pow:" like the token-stage reasons in pipeline.go, and collapsed to
	// the same "pow" category by reasonCategory, which is one of the reasons
	// outcome rows stay out of by-reason rollups.
	ReasonBadSolution     = "pow:bad_solution"      // nonce does not meet the difficulty
	ReasonBindingMismatch = "pow:binding_mismatch"  // challenge was issued to a different host or IP
	ReasonChallengeGone   = "pow:unknown_challenge" // unknown, expired or already spent
	ReasonTooFast         = "pow:too_fast"          // no-JS redemption before the minimum delay
	ReasonNoJSDisabled    = "pow:nojs_disabled"     // no-JS redemption on a JS-only challenge
	// ReasonRedeemInternal is Guardian failing, not the client: a store or
	// key-refresh error. Recorded because the funnel's "failed" count includes
	// these, and a burst of them is a store-trouble signal in its own right.
	ReasonRedeemInternal = "pow:internal_error"
)

// The recent-decision ring is deliberately a bounded, per-instance live view,
// not a historical store. The default and cap are validated by Config.finalize;
// keep the zero-value fallback here so recentRing remains useful in tests and
// embedded code that constructs one directly.
const (
	defaultRecentDecisionsCapacity = 4096
	maxRecentDecisionsCapacity     = 16384
)

// Per-entry field caps. URI, UA, Host and Method are all attacker-supplied and
// can each run to the proxy's full header budget (~8 KiB); uncapped, a hostile
// flood could pin capacity*several-KiB (hundreds of MiB at
// maxRecentDecisionsCapacity) in a diagnostics buffer. Truncation keeps the ring's worst case
// attacker-independent while leaving entries plenty descriptive for a live
// operator view. Host and Method are capped far tighter because a legitimate
// value is short: a Host is bounded by DNS name length and a method by the
// registered verbs.
const (
	maxRecentURILen    = 2048
	maxRecentUALen     = 512
	maxRecentHostLen   = 253
	maxRecentMethodLen = 32
)

// truncateRecent caps s at n bytes, marking the cut so an operator can tell a
// truncated value from a naturally short one.
func truncateRecent(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// clampMS narrows a millisecond duration to the ring's int32, saturating rather
// than wrapping: the values cross a package boundary as int64, and a wrapped
// negative would render as a nonsensical solve time rather than an obvious
// ceiling. int32 milliseconds covers 24 days; a challenge lifetime is minutes.
func clampMS(v int64) int32 {
	if v <= 0 {
		return 0
	}
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v)
}

// clampBits narrows difficulty to the ring's uint8. pow.max_difficulty is
// capped at 8 hex digits (32 bits), so this saturates only on a value that
// could not have been issued.
func clampBits(v int) uint8 {
	if v <= 0 {
		return 0
	}
	if v > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(v)
}

// RecentDecisionSnapshot is one consistent copy of the live ring plus the
// retention state needed to describe its coverage honestly.
type RecentDecisionSnapshot struct {
	Decisions []RecentDecision
	Capacity  int
	Full      bool
	StartedAt time.Time
}

// recentRing is a fixed-size overwrite-oldest buffer. Only challenged/denied
// requests pass through it, so the mutex sees a tiny fraction of traffic and
// never the allow fast path. Per-instance by design: replicas each report
// their own recent feed (cross-instance aggregation is a metrics concern).
type recentRing struct {
	mu    sync.Mutex
	buf   []RecentDecision
	next  int  // index the next entry is written at
	count int  // initialized entries, up to len(buf)
	full  bool // at least one older entry has been overwritten
	// startedAt is when this ring began observing decisions. It distinguishes
	// an empty covered interval from time before this process existed.
	startedAt time.Time
}

func newRecentRing(size int) *recentRing {
	if size <= 0 {
		size = defaultRecentDecisionsCapacity
	}
	return &recentRing{buf: make([]RecentDecision, size), startedAt: time.Now()}
}

func (r *recentRing) add(d RecentDecision) {
	d.URI = truncateRecent(d.URI, maxRecentURILen)
	d.UA = truncateRecent(d.UA, maxRecentUALen)
	d.Host = truncateRecent(d.Host, maxRecentHostLen)
	d.Method = truncateRecent(d.Method, maxRecentMethodLen)
	r.mu.Lock()
	if len(r.buf) == 0 {
		r.buf = make([]RecentDecision, defaultRecentDecisionsCapacity)
		r.startedAt = time.Now()
	}
	if r.count == len(r.buf) {
		r.full = true
	} else {
		r.count++
	}
	r.buf[r.next] = d
	r.next++
	if r.next == len(r.buf) {
		r.next = 0
	}
	r.mu.Unlock()
}

// snapshot returns up to limit entries, newest first, together with retention
// metadata captured under the same lock. limit <= 0 means all.
func (r *recentRing) snapshot(limit int) RecentDecisionSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	capacity := len(r.buf)
	if capacity == 0 {
		capacity = defaultRecentDecisionsCapacity
	}
	n := r.count
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]RecentDecision, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, r.buf[(r.next-i+len(r.buf))%len(r.buf)])
	}
	return RecentDecisionSnapshot{
		Decisions: out,
		Capacity:  capacity,
		Full:      r.full,
		StartedAt: r.startedAt,
	}
}

// list returns up to limit entries, newest first. limit <= 0 means all.
func (r *recentRing) list(limit int) []RecentDecision { return r.snapshot(limit).Decisions }
