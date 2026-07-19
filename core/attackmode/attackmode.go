// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attackmode is the global attack posture: an in-process signal
// aggregator plus a normal/elevated/attack state machine. The hot path only
// ever touches it through single atomic operations (a counter Add, a state
// pointer Load); a background ticker aggregates the counters over a sliding
// window and publishes an immutable *State. When the posture rises, PoW
// difficulty is raised fleet-wide, challenges can be forced, and challenge
// issuance can switch to a store-free path, so a flood of new clients stops
// saturating the store.
//
// The detector is transport-agnostic (no core/store/pow imports beyond the
// store interface for optional posture sharing), so core owns one and the
// HTTP transport reads its published state. The WASM guest is unaffected.
package attackmode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// Level is the posture. Higher is more hostile.
type Level int32

const (
	Normal Level = iota
	Elevated
	Attack
)

func (l Level) String() string {
	switch l {
	case Elevated:
		return "elevated"
	case Attack:
		return "attack"
	default:
		return "normal"
	}
}

// ParseLevel maps an admin string to a Level, plus an "auto" sentinel.
func ParseLevel(s string) (level Level, auto, ok bool) {
	switch s {
	case "auto":
		return Normal, true, true
	case "normal":
		return Normal, false, true
	case "elevated":
		return Elevated, false, true
	case "attack":
		return Attack, false, true
	}
	return Normal, false, false
}

// bucketWidth is the aggregation granularity; the window holds
// window/bucketWidth buckets.
const bucketWidth = 5 * time.Second

// slowOpThreshold is the store-op latency above which an op counts as "slow"
// for the store-degradation signal. Compile-time: no operator story justifies
// tuning it.
const slowOpThreshold = 25 * time.Millisecond

// minStoreOps / minSolveSamples are floors below which the store-degradation
// and solve-ratio signals are treated as too noisy to act on.
const (
	minStoreOps     = 20
	minSolveSamples = 50
)

// Config is the resolved attack-mode configuration (core.Config translates
// the YAML into this so the package stays free of the core import).
type Config struct {
	Enabled      bool
	Window       time.Duration
	MinDwell     time.Duration
	SharePosture bool

	// The rate/ratio signals below disable when 0 (see elevatedSignal/
	// attackSignal, which each guard on `> 0`). At the YAML layer that maps to
	// omitting the field: a Rate cannot be written "0/s" (the parser rejects a
	// zero count), so an omitted signal reaches here as 0 = disabled.
	ChallengeRate       float64 // issued/s entering elevated; 0 disables
	AttackChallengeRate float64 // issued/s entering attack; 0 disables
	MinSolveRatio       float64 // attack issuance qualifier (always set)
	RequestRate         float64 // Evaluate/s entering elevated; 0 disables
	StoreErrorRatio     float64 // store error fraction; 0 disables
	StoreSlowRatio      float64 // store slow-op fraction; 0 disables

	ElevatedBits int // fleet raise in bits at elevated
	AttackBits   int // fleet raise in bits at attack
	CapBits      int
	ForceAlways  bool
	Stateless    bool
}

// State is the immutable posture snapshot read once per request.
type State struct {
	Level       Level
	ExtraBits   int  // fleet difficulty raise in bits
	CapBits     int  // ceiling for the shifted difficulty window
	ForceAlways bool // suspicion behaves as always
	Stateless   bool // issue store-free challenges
	Since       time.Time
	Reason      string // bounded: challenge_rate|request_rate|store_errors|store_slow|forced|peer|""
}

// Cap returns the effective difficulty ceiling: the configured attack-mode cap
// when a raise is active, else the caller's own maxBits (so a Normal posture
// never shrinks a domain's window). Safe on a nil State.
func (s *State) Cap(maxBits int) int {
	if s == nil || s.ExtraBits == 0 || s.CapBits == 0 {
		return maxBits
	}
	return s.CapBits
}

// counters are the raw atomics the hot path bumps; the ticker snapshots deltas.
type counters struct {
	evals     atomic.Int64
	issued    atomic.Int64
	redeemed  atomic.Int64
	storeOps  atomic.Int64
	storeErrs atomic.Int64
	storeSlow atomic.Int64
}

type bucket struct {
	evals, issued, redeemed, storeOps, storeErrs, storeSlow int64
}

// Detector aggregates signals and publishes the posture.
type Detector struct {
	cfg        atomic.Pointer[Config]
	log        *slog.Logger
	store      store.Store // for posture sharing; may be nil
	instanceID string      // per-process id for this instance's posture-share key
	voteLive   atomic.Bool // this process may currently have a shared vote key
	// unsupportedShareWarn emits once when a third-party store silently loses
	// fleet posture sharing. Built-in stores all implement PostureVotes.
	unsupportedShareWarn sync.Once

	c        counters
	prev     counters // last-tick totals, for deltas (ticker-only, no lock)
	ring     []bucket
	ringPos  int
	ringFull bool

	state atomic.Pointer[State]
	// shareMu serializes publishing and clearing this instance's store vote.
	// Pin/SetConfig can otherwise delete just before an already-started tick
	// republishes the stale level.
	shareMu sync.Mutex

	// evalMu serializes the whole evaluate/publish path, which runs on both
	// the ticker goroutine and the admin goroutine (Pin/Unpin). It guards
	// lastAbove and the load-then-store of state so the two goroutines cannot
	// race or revert each other's decision.
	evalMu sync.Mutex
	// lastAbove[level] is the last tick (unix nano) at which any entry signal
	// for that level was at or above threshold; drives dwell + hysteresis.
	// Guarded by evalMu.
	lastAbove [3]int64
	// localLvl is this instance's own detected level (before adopting any
	// peer level); it is what we publish to peers. Guarded by evalMu.
	localLvl Level

	pinned   atomic.Bool
	pinLevel atomic.Int32
	pinUntil atomic.Int64 // unix nano; 0 = no expiry

	onTransition atomic.Pointer[func(from, to Level, reason string)]
	onTick       atomic.Pointer[func(level Level, extraBits int, sig Signals)]

	// current window rates, for the admin API / metrics (ticker-written).
	mu       sync.Mutex
	sig      Signals
	now      func() time.Time
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	tickHook func() // test hook, called at the end of each tick
}

// Signals is the current window measurement, for observability.
type Signals struct {
	ChallengeRate   float64 `json:"challenge_rate"`
	RequestRate     float64 `json:"request_rate"`
	SolveRatio      float64 `json:"solve_ratio"`
	StoreErrorRatio float64 `json:"store_error_ratio"`
	StoreSlowRatio  float64 `json:"store_slow_ratio"`
}

// New builds a detector in the Normal state. A nil *Detector is safe to call
// every method on (feature-off no-op), so callers never nil-check.
func New(cfg Config, st store.Store, log *slog.Logger) *Detector {
	d := &Detector{log: log, store: st, now: time.Now, instanceID: newInstanceID()}
	d.applyConfig(cfg)
	d.state.Store(&State{Level: Normal})
	return d
}

// newInstanceID returns a random per-process id for this instance's
// posture-share key, so replicas never collide on the shared store.
func newInstanceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func (d *Detector) applyConfig(cfg Config) {
	n := max(int(cfg.Window/bucketWidth), 1)
	d.ring = make([]bucket, n)
	d.ringPos, d.ringFull = 0, false
	d.cfg.Store(&cfg)
}

// SetConfig swaps the config on a hot reload. The ring is rebuilt, so a window
// change takes a full new window to fill; the published state is untouched.
func (d *Detector) SetConfig(cfg Config) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.applyConfig(cfg)
	d.mu.Unlock()
	if !cfg.Enabled || !cfg.SharePosture {
		d.clearSharedVote()
	}
}

// OnTransition registers a callback fired on every level change (logging,
// metrics, and the enforcement offload can subscribe). One callback; last wins.
func (d *Detector) OnTransition(fn func(from, to Level, reason string)) {
	if d == nil {
		return
	}
	d.onTransition.Store(&fn)
}

// OnTick registers a callback fired at the end of every aggregation tick with
// the current level and window signals, for publishing gauges. One callback.
func (d *Detector) OnTick(fn func(level Level, extraBits int, sig Signals)) {
	if d == nil {
		return
	}
	d.onTick.Store(&fn)
}

// --- hot-path feeds (single atomic add each) --------------------------------

func (d *Detector) Evaluated() {
	if d != nil {
		d.c.evals.Add(1)
	}
}
func (d *Detector) ChallengeIssued() {
	if d != nil {
		d.c.issued.Add(1)
	}
}
func (d *Detector) ChallengeRedeemed() {
	if d != nil {
		d.c.redeemed.Add(1)
	}
}

// StoreOp implements store.OpRecorder so the detector can observe every store
// op's latency and error without a second call site.
func (d *Detector) StoreOp(_ string, seconds float64, err error) {
	if d == nil {
		return
	}
	d.c.storeOps.Add(1)
	if err != nil {
		d.c.storeErrs.Add(1)
	}
	if seconds >= slowOpThreshold.Seconds() {
		d.c.storeSlow.Add(1)
	}
}

// State returns the current posture (one atomic load). Never nil.
func (d *Detector) State() *State {
	if d == nil {
		return normalState
	}
	return d.state.Load()
}

var normalState = &State{Level: Normal}

// CurrentSignals returns the last-tick window rates for the admin API.
func (d *Detector) CurrentSignals() Signals {
	if d == nil {
		return Signals{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sig
}

// Pinned reports whether an operator has pinned the level (and to what).
func (d *Detector) Pinned() (Level, bool) {
	if d == nil || !d.pinned.Load() {
		return Normal, false
	}
	return Level(d.pinLevel.Load()), true
}

// Pin forces a level until ttl elapses (0 = until unpinned). Pin wins in both
// directions, so Pin(Normal) is a kill switch.
func (d *Detector) Pin(level Level, ttl time.Duration) {
	if d == nil {
		return
	}
	d.pinLevel.Store(int32(level))
	if ttl > 0 {
		d.pinUntil.Store(d.now().Add(ttl).UnixNano())
	} else {
		d.pinUntil.Store(0)
	}
	d.pinned.Store(true)
	d.recompute()
	// Pins are deliberately local hard overrides. Remove any previously
	// published automatic vote immediately, otherwise peers keep adopting the
	// stale value until its window TTL expires (defeating Pin(Normal)).
	d.clearSharedVote()
}

// Unpin returns to automatic detection.
func (d *Detector) Unpin() {
	if d == nil {
		return
	}
	d.pinned.Store(false)
	d.recompute()
}

// Start begins the aggregation ticker. Call once; Close stops it.
func (d *Detector) Start(ctx context.Context) {
	if d == nil {
		return
	}
	ctx, d.cancel = context.WithCancel(ctx)
	d.wg.Add(1)
	go d.run(ctx)
}

// Close stops the ticker.
func (d *Detector) Close() {
	if d == nil {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
	d.clearSharedVote()
}

func (d *Detector) run(ctx context.Context) {
	defer d.wg.Done()
	t := time.NewTicker(bucketWidth)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.tick()
		}
	}
}

// tick snapshots one bucket of deltas, recomputes window rates and re-evaluates
// the state machine. Exported-for-test via TickForTest.
func (d *Detector) tick() {
	cfg := d.cfg.Load()
	b := bucket{
		evals:     delta(&d.c.evals, &d.prev.evals),
		issued:    delta(&d.c.issued, &d.prev.issued),
		redeemed:  delta(&d.c.redeemed, &d.prev.redeemed),
		storeOps:  delta(&d.c.storeOps, &d.prev.storeOps),
		storeErrs: delta(&d.c.storeErrs, &d.prev.storeErrs),
		storeSlow: delta(&d.c.storeSlow, &d.prev.storeSlow),
	}
	d.mu.Lock()
	d.ring[d.ringPos] = b
	d.ringPos = (d.ringPos + 1) % len(d.ring)
	if d.ringPos == 0 {
		d.ringFull = true
	}
	sig := d.windowSignals(cfg)
	d.sig = sig
	d.mu.Unlock()

	// Posture sharing runs OUTSIDE evalMu (it does blocking store I/O) but is
	// fed into evaluate as the peer level, so the whole decision (local +
	// pin + peer) is made in one serialized place. This publishes the local
	// level to peers only when we are the ones detecting elevation, so a
	// replica that merely adopted a peer's level never writes it back (which
	// would let a decayed replica clobber the true source).
	peer := Normal
	if cfg.Enabled && cfg.SharePosture && d.store != nil && !d.pinned.Load() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		peer = d.sharePosture(ctx, cfg, d.localLevel())
		cancel()
	} else {
		d.clearSharedVote()
	}
	d.evaluate(cfg, sig, peer)
	if fn := d.onTick.Load(); fn != nil {
		st := d.state.Load()
		(*fn)(st.Level, st.ExtraBits, sig)
	}
	if d.tickHook != nil {
		d.tickHook()
	}
}

// TickForTest runs one aggregation tick synchronously, for tests that drive
// the detector without the real ticker. Not for production use.
func (d *Detector) TickForTest() { d.tick() }

// SetClockForTest overrides the detector's clock so tests can advance dwell
// windows deterministically.
func (d *Detector) SetClockForTest(now func() time.Time) { d.now = now }

func delta(cur, prev *atomic.Int64) int64 {
	c := cur.Load()
	d := c - prev.Load()
	prev.Store(c)
	if d < 0 {
		return 0
	}
	return d
}

// windowSignals sums the ring into per-second rates and ratios. Caller holds mu.
func (d *Detector) windowSignals(cfg *Config) Signals {
	var sum bucket
	n := len(d.ring)
	if !d.ringFull {
		n = d.ringPos
	}
	for i := 0; i < len(d.ring); i++ {
		b := d.ring[i]
		sum.evals += b.evals
		sum.issued += b.issued
		sum.redeemed += b.redeemed
		sum.storeOps += b.storeOps
		sum.storeErrs += b.storeErrs
		sum.storeSlow += b.storeSlow
	}
	secs := float64(max(n, 1)) * bucketWidth.Seconds()
	sig := Signals{
		ChallengeRate: float64(sum.issued) / secs,
		RequestRate:   float64(sum.evals) / secs,
	}
	if sum.issued >= minSolveSamples {
		sig.SolveRatio = float64(sum.redeemed) / float64(sum.issued)
	} else {
		sig.SolveRatio = 1 // too few samples to distrust
	}
	if sum.storeOps >= minStoreOps {
		sig.StoreErrorRatio = float64(sum.storeErrs) / float64(sum.storeOps)
		sig.StoreSlowRatio = float64(sum.storeSlow) / float64(sum.storeOps)
	}
	return sig
}

// localLevel returns this instance's own detected level (ignoring any
// peer-adopted level), which is what it publishes to peers. Guarded by evalMu.
func (d *Detector) localLevel() Level {
	d.evalMu.Lock()
	defer d.evalMu.Unlock()
	return d.localLvl
}

// evaluate runs the state machine against the current window and publishes a
// new State. peer is the level adopted from other replicas via the shared
// store (Normal when sharing is off or we are pinned); the published level is
// max(local, peer), but a pin overrides everything. The whole body runs under
// evalMu so the ticker and an admin Pin cannot race or revert each other.
func (d *Detector) evaluate(cfg *Config, sig Signals, peer Level) {
	d.evalMu.Lock()
	defer d.evalMu.Unlock()
	now := d.now()
	// Shared posture values cross a trust boundary. Keep the state machine
	// defensive even if a future store implementation bypasses sharePosture's
	// parser: lastAbove is indexed only by the three valid enum values.
	if peer < Normal || peer > Attack {
		peer = Normal
	}

	// Manual pin overrides detection in both directions (kill switch).
	if lvl, pinned := d.resolvePin(now); pinned {
		d.localLvl = lvl
		d.publish(cfg, lvl, "forced", now)
		return
	}
	if !cfg.Enabled {
		d.localLvl = Normal
		d.publish(cfg, Normal, "", now)
		return
	}

	elevatedHit, elevatedReason := d.elevatedSignal(cfg, sig)
	attackHit, attackReason := d.attackSignal(cfg, sig)
	// lastAbove tracks the last time any entry signal for a level was at or
	// above HALF its threshold, which is the documented exit condition:
	// a level decays only after every signal has stayed below half for
	// min_dwell. Tracking the half-crossing (not the full entry threshold) is
	// what makes sustained load between 50% and 100% hold the level instead of
	// decaying.
	if elevatedHit || d.elevatedHalf(cfg, sig) {
		d.lastAbove[Elevated] = now.UnixNano()
	}
	if attackHit || d.attackHalf(cfg, sig) {
		d.lastAbove[Attack] = now.UnixNano()
	}

	// The local decision drives what we detect (and publish to peers).
	cur := d.localLvl
	local, reason := cur, ""
	switch {
	case attackHit:
		local, reason = Attack, attackReason
	case elevatedHit && cur < Attack:
		local, reason = Elevated, elevatedReason
	default:
		local, reason = d.decayFrom(cfg, cur, now)
	}
	d.localLvl = local

	// The published posture is the fleet max, with its own decay state. Keep
	// localLvl separate because only local detection is published as this
	// replica's vote; an adopted level must never be written back. While a peer
	// vote is present, refresh its dwell timestamp. After it disappears, decay
	// from the currently published fleet level rather than jumping straight to
	// localLvl (usually Normal on a quiet replica).
	desired, treason := local, reason
	if peer > desired {
		desired, treason = peer, "peer"
	}
	if peer > Normal {
		d.lastAbove[peer] = now.UnixNano()
	}
	target := desired
	currentState := d.state.Load()
	published := currentState.Level
	if desired < published && currentState.Reason != "forced" {
		decayed, _ := d.decayFrom(cfg, published, now)
		target = max(decayed, desired)
		if target < published && target > Normal {
			// A downward transition starts a fresh dwell at the intermediate
			// posture; otherwise a peer-adopted Attack can fall through Elevated
			// to Normal on consecutive ticks because Elevated was never observed.
			d.lastAbove[target] = now.UnixNano()
		}
		if target == published {
			treason = ""
		}
	}
	d.publish(cfg, target, treason, now)
}

// resolvePin returns the pinned level, expiring the pin if its TTL passed.
func (d *Detector) resolvePin(now time.Time) (Level, bool) {
	if !d.pinned.Load() {
		return Normal, false
	}
	if until := d.pinUntil.Load(); until != 0 && now.UnixNano() >= until {
		d.pinned.Store(false)
		return Normal, false
	}
	return Level(d.pinLevel.Load()), true
}

func (d *Detector) elevatedSignal(cfg *Config, sig Signals) (bool, string) {
	if cfg.ChallengeRate > 0 && sig.ChallengeRate > cfg.ChallengeRate {
		return true, "challenge_rate"
	}
	if cfg.RequestRate > 0 && sig.RequestRate > cfg.RequestRate {
		return true, "request_rate"
	}
	if cfg.StoreErrorRatio > 0 && sig.StoreErrorRatio > cfg.StoreErrorRatio {
		return true, "store_errors"
	}
	if cfg.StoreSlowRatio > 0 && sig.StoreSlowRatio > cfg.StoreSlowRatio {
		return true, "store_slow"
	}
	return false, ""
}

func (d *Detector) attackSignal(cfg *Config, sig Signals) (bool, string) {
	if cfg.AttackChallengeRate > 0 && sig.ChallengeRate > cfg.AttackChallengeRate && sig.SolveRatio < cfg.MinSolveRatio {
		return true, "challenge_rate"
	}
	if cfg.StoreErrorRatio > 0 && sig.StoreErrorRatio > 3*cfg.StoreErrorRatio {
		return true, "store_errors"
	}
	return false, ""
}

// elevatedHalf reports whether any elevated entry signal is at or above HALF
// its threshold. The exit hysteresis holds the level until every signal has
// stayed strictly below half for min_dwell, so this is the "not yet safe to
// decay" test (the solve-ratio qualifier is intentionally NOT halved: it is a
// direction flag, not a magnitude).
func (d *Detector) elevatedHalf(cfg *Config, sig Signals) bool {
	return (cfg.ChallengeRate > 0 && sig.ChallengeRate >= cfg.ChallengeRate/2) ||
		(cfg.RequestRate > 0 && sig.RequestRate >= cfg.RequestRate/2) ||
		(cfg.StoreErrorRatio > 0 && sig.StoreErrorRatio >= cfg.StoreErrorRatio/2) ||
		(cfg.StoreSlowRatio > 0 && sig.StoreSlowRatio >= cfg.StoreSlowRatio/2)
}

// attackHalf reports whether any attack entry signal is at or above HALF its
// threshold. The issuance rate keeps its solve-ratio qualifier (a low ratio is
// what makes issuance an attack rather than a crowd), so a fully-solved flood
// does not hold the attack level.
func (d *Detector) attackHalf(cfg *Config, sig Signals) bool {
	return (cfg.AttackChallengeRate > 0 && sig.ChallengeRate >= cfg.AttackChallengeRate/2 && sig.SolveRatio < cfg.MinSolveRatio) ||
		(cfg.StoreErrorRatio > 0 && sig.StoreErrorRatio >= 3*cfg.StoreErrorRatio/2)
}

// decayFrom lowers a level one step only after every entry signal has stayed
// below HALF its threshold for MinDwell; otherwise it holds. lastAbove[cur] is
// refreshed each tick a signal is at or above half (see evaluate), so this
// time check implements the documented half-threshold exit hysteresis: load
// sustained between 50% and 100% keeps refreshing lastAbove and holds the
// level. Caller holds evalMu.
func (d *Detector) decayFrom(cfg *Config, cur Level, now time.Time) (Level, string) {
	if cur == Normal {
		return Normal, ""
	}
	last := d.lastAbove[cur]
	if last != 0 && now.Sub(time.Unix(0, last)) < cfg.MinDwell {
		return cur, "" // still dwelling; reason recomputed by publish's short-circuit
	}
	return cur - 1, ""
}

// publish swaps in a new State. Caller holds evalMu. It republishes when the
// level, the reason, or any config-derived effect field changes, so a hot
// reload of the raise/cap/stateless/force settings takes effect even while a
// level is held (not only at the next transition). An empty reason while the
// level is unchanged preserves the current reason (a dwell "hold").
func (d *Detector) publish(cfg *Config, level Level, reason string, now time.Time) {
	cur := d.state.Load()
	if reason == "" && level == cur.Level {
		reason = cur.Reason // holding at the same level keeps its reason
	}
	next := &State{
		Level:       level,
		ExtraBits:   d.bitsFor(cfg, level),
		CapBits:     cfg.CapBits,
		ForceAlways: level == Attack && cfg.ForceAlways,
		Stateless:   level == Attack && cfg.Stateless,
		Since:       now,
		Reason:      reason,
	}
	// No-op unless something actually changed (level, reason, or an effect).
	if cur.Level == next.Level && cur.Reason == next.Reason &&
		cur.ExtraBits == next.ExtraBits && cur.CapBits == next.CapBits &&
		cur.ForceAlways == next.ForceAlways && cur.Stateless == next.Stateless {
		return
	}
	if cur.Level == level {
		next.Since = cur.Since // effect/reason-only change keeps the start time
	}
	d.state.Store(next)
	if cur.Level != level {
		d.log.Warn("attack mode transition",
			"from", cur.Level.String(), "to", level.String(), "reason", reason,
			"extra_bits", next.ExtraBits)
		if fn := d.onTransition.Load(); fn != nil {
			(*fn)(cur.Level, level, reason)
		}
	}
}

func (d *Detector) bitsFor(cfg *Config, level Level) int {
	switch level {
	case Elevated:
		return cfg.ElevatedBits
	case Attack:
		return cfg.AttackBits
	default:
		return 0
	}
}

// recompute forces a state re-evaluation off the current window (used by
// Pin/Unpin so an operator action takes effect immediately, not next tick).
// Peer level is not re-read here: a pin overrides it anyway, and an unpin
// picks the fleet level up on the next tick.
func (d *Detector) recompute() {
	d.mu.Lock()
	sig := d.sig
	d.mu.Unlock()
	d.evaluate(d.cfg.Load(), sig, Normal)
}

// EffectiveBits shifts a domain's difficulty window up by the fleet raise,
// clamped to the attack-mode cap. Both floor and ceiling move so per-IP
// escalation and anomaly scaling keep their headroom above the new floor.
//
// The raise can only ever RAISE difficulty: the effective base never drops
// below the domain's own base, and the ceiling never below the domain's own
// max, even when difficulty_cap is misconfigured below them. That guarantee
// is load-bearing, because the pow_token stage verifies against the unshifted
// base (core/pipeline.go): if a challenge were issued below that floor, the
// solved token would be rejected and the visitor trapped in a solve loop.
func EffectiveBits(st *State, baseBits, maxBits, capBits int) (effBase, effMax int) {
	if st == nil || st.ExtraBits == 0 {
		return baseBits, maxBits
	}
	cap := max(capBits, maxBits) // the cap can never shrink the domain window
	effBase = max(min(baseBits+st.ExtraBits, cap), baseBits)
	effMax = max(min(maxBits+st.ExtraBits, cap), effBase)
	return effBase, effMax
}

// --- posture sharing (store, tick-only, off the hot path) -------------------

// sharePosture publishes this instance's own level as an expiring vote and
// returns the maximum level any OTHER live instance is reporting. Per-instance
// votes avoid the last-writer-wins clobber a single shared value suffers: a
// decayed replica writing "1" can never overwrite an attacking replica's "2".
// Each vote self-expires after the window, so a crashed instance stops voting.
// Backend-native vote indexes keep the tick independent of the general store
// keyspace; a failing or unsupported store degrades to local-only.
func (d *Detector) sharePosture(ctx context.Context, cfg *Config, local Level) Level {
	if d.store == nil || !cfg.SharePosture {
		return Normal
	}
	votes, ok := d.store.(store.PostureVotes)
	if !ok {
		d.warnUnsupportedPostureSharing()
		return Normal
	}
	d.shareMu.Lock()
	defer d.shareMu.Unlock()
	// Re-check live state after taking the serialization lock: a pin or reload
	// may have raced the tick's earlier eligibility check.
	cfg = d.cfg.Load()
	if d.pinned.Load() || !cfg.Enabled || !cfg.SharePosture {
		d.clearSharedVoteLocked(ctx)
		return Normal
	}
	// Publish our own level (or clear our vote when back to Normal).
	if local > Normal {
		// SET may have reached a remote store even when the client reports a
		// timeout. Record that the vote may exist before attempting the write,
		// so pin/disable/shutdown will always issue the compensating DELETE.
		d.voteLive.Store(true)
		if err := votes.SetPostureVote(ctx, d.instanceID, int(local), cfg.Window); errors.Is(err, store.ErrCapabilityUnsupported) {
			// Unlike a transport failure, unsupported guarantees no ambiguous
			// remote write, so do not retry a compensating delete every tick.
			d.voteLive.Store(false)
			d.warnUnsupportedPostureSharing()
		}
	} else {
		if err := votes.DeletePostureVote(ctx, d.instanceID); err == nil {
			d.voteLive.Store(false)
		} else if errors.Is(err, store.ErrCapabilityUnsupported) {
			d.voteLive.Store(false)
			d.warnUnsupportedPostureSharing()
		}
	}
	// Adopt the max over every OTHER instance's vote. Excluding our own vote is
	// essential: feeding yesterday's local level back into the detector would
	// prevent hysteresis from ever decaying.
	level, err := votes.MaxPostureVote(ctx, d.instanceID)
	if err != nil {
		if errors.Is(err, store.ErrCapabilityUnsupported) {
			d.warnUnsupportedPostureSharing()
		}
		return Normal
	}
	if level < int(Elevated) || level > int(Attack) {
		return Normal
	}
	return Level(level)
}

func (d *Detector) warnUnsupportedPostureSharing() {
	d.unsupportedShareWarn.Do(func() {
		d.log.Warn("store does not support fleet posture votes; attack detection is local to this replica")
	})
}

// clearSharedVote best-effort deletes this process's posture key. It is used
// when sharing becomes inactive (pin, hot-disable, shutdown) so peers never
// keep acting on a stale automatic vote. The atomic flag avoids a store call
// every tick for instances that never published a non-Normal level.
func (d *Detector) clearSharedVote() {
	if d == nil || d.store == nil {
		return
	}
	d.shareMu.Lock()
	defer d.shareMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	d.clearSharedVoteLocked(ctx)
	cancel()
}

func (d *Detector) clearSharedVoteLocked(ctx context.Context) {
	if !d.voteLive.Load() {
		return
	}
	votes, ok := d.store.(store.PostureVotes)
	if !ok {
		return
	}
	if err := votes.DeletePostureVote(ctx, d.instanceID); err == nil {
		d.voteLive.Store(false)
	}
}
