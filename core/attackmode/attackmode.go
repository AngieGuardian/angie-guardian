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
	"log/slog"
	"strconv"
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

	ChallengeRate       float64 // issued/s entering elevated
	AttackChallengeRate float64 // issued/s entering attack
	MinSolveRatio       float64
	RequestRate         float64 // Evaluate/s; 0 disables
	StoreErrorRatio     float64
	StoreSlowRatio      float64

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
	ForceAlways bool // suspicion behaves as always
	Stateless   bool // issue store-free challenges
	Since       time.Time
	Reason      string // bounded: challenge_rate|request_rate|store_errors|store_slow|forced|peer|""
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
	cfg   atomic.Pointer[Config]
	log   *slog.Logger
	store store.Store // for posture sharing; may be nil

	c        counters
	prev     counters // last-tick totals, for deltas (ticker-only, no lock)
	ring     []bucket
	ringPos  int
	ringFull bool

	state atomic.Pointer[State]

	// lastAbove[level] is the last tick (unix nano) at which any entry signal
	// for that level was at or above threshold; drives dwell + hysteresis.
	lastAbove [3]int64

	pinned   atomic.Bool
	pinLevel atomic.Int32
	pinUntil atomic.Int64 // unix nano; 0 = no expiry

	onTransition atomic.Pointer[func(from, to Level, reason string)]

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
	d := &Detector{log: log, store: st, now: time.Now}
	d.applyConfig(cfg)
	d.state.Store(&State{Level: Normal})
	return d
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
}

// OnTransition registers a callback fired on every level change (logging,
// metrics, and the enforcement offload can subscribe). One callback; last wins.
func (d *Detector) OnTransition(fn func(from, to Level, reason string)) {
	if d == nil {
		return
	}
	d.onTransition.Store(&fn)
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
	d.recompute("forced")
}

// Unpin returns to automatic detection.
func (d *Detector) Unpin() {
	if d == nil {
		return
	}
	d.pinned.Store(false)
	d.recompute("")
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

	d.evaluate(cfg, sig)
	// After the local decision, reconcile with peers: adopt the fleet max so
	// replicas move together. Off the hot path (one tick), store errors
	// degrade to local-only.
	if cfg.Enabled && cfg.SharePosture && d.store != nil {
		local := d.state.Load().Level
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		adopted := d.sharePosture(ctx, cfg, local)
		cancel()
		if adopted > local {
			d.publish(cfg, adopted, "peer", d.now())
		}
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

// evaluate runs the state machine against the current window and publishes a
// new State when the level or reason changes.
func (d *Detector) evaluate(cfg *Config, sig Signals) {
	now := d.now()
	elevatedHit, elevatedReason := d.elevatedSignal(cfg, sig)
	attackHit, attackReason := d.attackSignal(cfg, sig)
	if elevatedHit {
		d.lastAbove[Elevated] = now.UnixNano()
	}
	if attackHit {
		d.lastAbove[Attack] = now.UnixNano()
	}

	cur := d.state.Load()
	target, reason := cur.Level, cur.Reason

	// Manual pin overrides detection in both directions.
	if lvl, pinned := d.resolvePin(now); pinned {
		d.publish(cfg, lvl, "forced", now)
		return
	}

	if !cfg.Enabled {
		d.publish(cfg, Normal, "", now)
		return
	}

	switch {
	case attackHit:
		target, reason = Attack, attackReason
	case elevatedHit && cur.Level < Attack:
		target, reason = Elevated, elevatedReason
	default:
		// No entry signal active: decay one step if we have dwelled long
		// enough below every signal for the current level.
		target, reason = d.decay(cfg, cur, now)
	}
	d.publish(cfg, target, reason, now)
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

// decay lowers the level one step when every entry signal for the current
// level has stayed below 50% of its threshold for MinDwell.
func (d *Detector) decay(cfg *Config, cur *State, now time.Time) (Level, string) {
	if cur.Level == Normal {
		return Normal, ""
	}
	last := d.lastAbove[cur.Level]
	if last != 0 && now.Sub(time.Unix(0, last)) < cfg.MinDwell {
		return cur.Level, cur.Reason // still dwelling
	}
	return cur.Level - 1, cur.Reason
}

// publish swaps in a new State when the effective level or reason changed, and
// fires the transition callback.
func (d *Detector) publish(cfg *Config, level Level, reason string, now time.Time) {
	cur := d.state.Load()
	if cur.Level == level && cur.Reason == reason {
		return
	}
	next := &State{
		Level:       level,
		ExtraBits:   d.bitsFor(cfg, level),
		ForceAlways: level == Attack && cfg.ForceAlways,
		Stateless:   level == Attack && cfg.Stateless,
		Since:       now,
		Reason:      reason,
	}
	if cur.Level == level {
		next.Since = cur.Since // reason-only change keeps the start time
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
func (d *Detector) recompute(_ string) {
	d.mu.Lock()
	sig := d.sig
	d.mu.Unlock()
	d.evaluate(d.cfg.Load(), sig)
}

// EffectiveBits shifts a domain's difficulty window up by the fleet raise,
// clamped to the attack-mode cap. Both floor and ceiling move so per-IP
// escalation and anomaly scaling keep their headroom above the new floor.
func EffectiveBits(st *State, baseBits, maxBits, capBits int) (effBase, effMax int) {
	if st == nil || st.ExtraBits == 0 {
		return baseBits, maxBits
	}
	effBase = min(baseBits+st.ExtraBits, capBits)
	effMax = max(min(maxBits+st.ExtraBits, capBits), effBase)
	return effBase, effMax
}

// --- posture sharing (store, tick-only, off the hot path) -------------------

const posturePrefix = "attack:posture"

// sharePosture publishes this instance's level (if above Normal) and adopts
// the max of local and any peer level. One store op each per tick; a failing
// store degrades to local-only (and is itself a trigger signal).
func (d *Detector) sharePosture(ctx context.Context, cfg *Config, local Level) Level {
	if d.store == nil || !cfg.SharePosture {
		return local
	}
	window := cfg.Window
	if local > Normal {
		_ = d.store.Set(ctx, posturePrefix, []byte(strconv.Itoa(int(local))), window)
	}
	v, ok, err := d.store.Get(ctx, posturePrefix)
	if err != nil || !ok {
		return local
	}
	peer, perr := strconv.Atoi(string(v))
	if perr != nil {
		return local
	}
	if Level(peer) > local {
		return Level(peer)
	}
	return local
}
