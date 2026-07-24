// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package health probes the store in the background so an operator can tell
// "up" from "up but failing open". Guardian degrades quietly when the store is
// unreachable — stages abstain, challenges fall back to stateless minting and
// every request sails through — while the process, both listeners and
// systemd all still look healthy. This package is what makes that state
// visible to /readyz, the guardian_store_up gauge and the dashboard.
package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/internal/jitter"
)

// Probe cadence. Compile-time constants on purpose: no operator story
// justifies tuning them, and every extra YAML knob is a support surface.
// staleFactor is how many intervals may pass without a completed probe before
// the last snapshot stops counting as current.
const (
	probeInterval = 10 * time.Second
	probeTimeout  = 2 * time.Second
	probeTTL      = time.Minute
	staleFactor   = 3
)

// clockSkewWarn is the store clock offset above which the probe warns. The
// deadline-based counter scripts compare app-computed deadlines against the
// server's clock, so a server running ahead by more than a counter window
// (60s challenge rate buckets) silently discards every flush; 10s leaves
// margin while staying far above what an NTP-synced fleet ever shows.
const clockSkewWarn = 10 * time.Second

// probeKeyPrefix namespaces the single key this package writes. The
// per-process suffix keeps replicas sharing one Redis from reading each
// other's nonce; reusing one key per process bounds storage, and its TTL
// cleans up after a stopped process.
const probeKeyPrefix = "guardian:health:probe:"

// Status is the published result of the most recent probe. It is a value type
// so readers get a consistent snapshot without holding a lock.
type Status struct {
	Probed    bool      `json:"probed"`
	Up        bool      `json:"up"`
	Stale     bool      `json:"stale,omitempty"`
	Backend   string    `json:"backend"`
	LatencyMS float64   `json:"latency_ms"`
	CheckedAt time.Time `json:"checked_at"`

	// Err is the raw probe error. It is deliberately not serialized: the
	// unauthenticated /readyz reports a coarse reason only, and the detail goes
	// to the log and the token-guarded /admin/stats.
	Err string `json:"-"`

	// gen is the publish generation this snapshot was stored under. It lets a
	// staleness timer tell "nothing has probed since I was armed" from "a newer
	// probe already superseded me".
	gen uint64
}

// Recorder receives probe outcomes; *metrics.Metrics satisfies it. Kept as an
// interface here for the same reason as store.OpRecorder: the package must not
// force a Prometheus dependency on its callers.
type Recorder interface {
	// StoreProbe reports one completed probe: gauge plus ok/error counter.
	StoreProbe(backend string, up bool)
	// StoreProbeStale drives the gauge to 0 when no probe completed in time.
	// No probe finished, so no probe counter moves.
	StoreProbeStale(backend string)
	// StoreClockSkew reports the store server clock minus the local clock,
	// measured on a successful probe of a ServerClock-capable backend.
	StoreClockSkew(backend string, seconds float64)
}

// Checker owns the probe loop and publishes its result as a lock-free
// snapshot. Every method is safe on a nil receiver (feature-off no-op),
// matching the enforce/attackmode discipline, so callers never nil-check.
type Checker struct {
	st      store.Store
	backend string
	rec     Recorder
	log     *slog.Logger
	key     string

	// Overridable by tests only; production always uses the constants above.
	interval time.Duration
	timeout  time.Duration
	ttl      time.Duration

	snap atomic.Pointer[Status] // read by Status(), never under a lock

	mu     sync.Mutex // serializes publishing with arming the staleness timer
	gen    uint64
	timer  *time.Timer
	closed bool

	// inflight is the probe attempt currently running, or nil when none is. It
	// bounds probeOnce to one goroutine even when a shipping embedded backend
	// (pebble/buntdb) ignores context cancellation and a probe stays wedged: a
	// tick that finds an attempt still running reports down immediately instead
	// of starting another or consuming that attempt's (already-void) late
	// result. See boundedProbe.
	inflightMu sync.Mutex
	inflight   *probeAttempt

	// skewWarned tracks whether the last clock-skew observation was over the
	// warn threshold, so transitions log once instead of every tick. Only the
	// probe loop touches it.
	skewWarned bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New builds a checker against st. Pass the raw store, not the instrumented
// wrapper: synthetic probe traffic must not change the meaning of
// guardian_store_ops_total or feed the attack detector's store-degradation
// ratios. Probe outcomes have their own metrics instead.
func New(st store.Store, backend string, rec Recorder, log *slog.Logger) *Checker {
	if log == nil {
		log = slog.Default()
	}
	return &Checker{
		st:       st,
		backend:  backend,
		rec:      rec,
		log:      log,
		key:      probeKeyPrefix + processSuffix(),
		interval: probeInterval,
		timeout:  probeTimeout,
		ttl:      probeTTL,
	}
}

// processSuffix returns a random per-process suffix for the probe key.
func processSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// Start runs the first probe synchronously, then keeps probing on a ticker.
// Probing before returning means the listeners and the first Prometheus scrape
// never observe an uninitialized store_up series. A failed first probe is not
// fatal (Guardian fails open by design); readiness simply reports 503 until a
// probe succeeds.
func (c *Checker) Start(ctx context.Context) {
	if c == nil {
		return
	}
	ctx, c.cancel = context.WithCancel(ctx)
	c.probe(ctx)
	c.wg.Add(1)
	go c.loop(ctx)
}

func (c *Checker) loop(ctx context.Context) {
	defer c.wg.Done()
	// Jittered interval: a fleet whose replicas start probing at the same
	// instant must not hit the shared store in lockstep on every tick.
	t := time.NewTimer(jitter.Frac(c.interval, jitter.Fraction))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.probe(ctx)
			t.Reset(jitter.Frac(c.interval, jitter.Fraction))
		}
	}
}

// Close stops the checker and is idempotent. Ownership of the store stays with
// the caller: this never closes it.
func (c *Checker) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	cancel := c.cancel
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	c.wg.Wait()
	return nil
}

// Status returns the latest snapshot. A nil Checker (or one that has not
// probed yet) reports the zero Status, which is "not probed" and therefore
// never ready.
func (c *Checker) Status() Status {
	if c == nil {
		return Status{}
	}
	if s := c.snap.Load(); s != nil {
		return *s
	}
	return Status{}
}

// probe runs one round trip and publishes the outcome. Latency is recorded for
// failures too: a probe that times out is exactly the case where knowing how
// long the store took matters.
func (c *Checker) probe(ctx context.Context) {
	start := time.Now()
	err := c.boundedProbe(ctx)
	took := time.Since(start)

	s := Status{
		Probed:    true,
		Up:        err == nil,
		Backend:   c.backend,
		LatencyMS: float64(took.Microseconds()) / 1000,
		CheckedAt: time.Now().UTC(),
	}
	if err != nil {
		s.Err = err.Error()
	}

	prev := c.snap.Load()
	c.publish(s)
	if c.rec != nil {
		c.rec.StoreProbe(c.backend, s.Up)
	}

	// Log transitions only. A store that stays down for an hour must not write
	// 360 identical lines.
	first, wasUp := prev == nil, prev != nil && prev.Up && !prev.Stale
	switch {
	case !s.Up && (first || wasUp):
		c.log.Warn("store probe failed, Guardian is failing open",
			"backend", c.backend, "err", s.Err)
	case s.Up && !first && !wasUp:
		c.log.Info("store probe recovered", "backend", c.backend,
			"latency_ms", s.LatencyMS)
	}

	if s.Up {
		c.observeClockSkew(ctx)
	}
}

// observeClockSkew compares a remote store's clock against the local one.
// The deadline counter scripts enforce app-computed deadlines against the
// server's TIME, so a server clock running ahead by more than a counter
// window makes every CounterCache flush return applied=false and the deltas
// are silently discarded: rate-limit convergence stops with zero errors.
// Skew behind the app silently extends windows instead. Half the round-trip
// is subtracted as the best available estimate of when the server read its
// clock. Embedded backends share the process clock and skip this entirely.
func (c *Checker) observeClockSkew(ctx context.Context) {
	sc, ok := c.st.(store.ServerClock)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	t0 := time.Now()
	remote, err := sc.ServerTime(ctx)
	rtt := time.Since(t0)
	if err != nil {
		return // reachability is the probe's own department
	}
	skew := remote.Sub(t0.Add(rtt / 2))
	if c.rec != nil {
		c.rec.StoreClockSkew(c.backend, skew.Seconds())
	}
	over := skew.Abs() > clockSkewWarn
	switch {
	case over && !c.skewWarned:
		c.log.Warn("store clock skew detected: deadline-based counter windows are shifted; a store clock more than one window ahead silently discards counter flushes",
			"backend", c.backend, "skew", skew.Round(time.Millisecond).String(),
			"rtt_ms", float64(rtt.Microseconds())/1000)
	case !over && c.skewWarned:
		c.log.Info("store clock skew back under threshold",
			"backend", c.backend, "skew", skew.Round(time.Millisecond).String())
	}
	c.skewWarned = over
}

// probeAttempt is one run of probeOnce. Its result is only ever consumed by the
// boundedProbe call that started it, and only before that call's deadline: an
// attempt that ran out of time is void, so a value arriving on done afterwards
// is left unread and discarded with the attempt.
type probeAttempt struct {
	done chan error // buffered, so an abandoned attempt never blocks on send
}

// boundedProbe runs probeOnce under a hard wall-clock deadline that does not
// depend on the store honoring context cancellation. probeOnce sets a
// context.WithTimeout, but the shipping embedded backends (pebble, buntdb) run
// their I/O without consulting ctx, so a stalled operation would otherwise blow
// straight past the timeout and still be recorded as a success — and an
// indefinitely hung *first* probe would block the synchronous Start (delaying
// both listeners) or a Close waiting on the probe loop goroutine.
//
// A probe that misses its deadline is down, permanently: the store failed to
// answer inside the window that defines "responsive", and the fact that the
// operation later completes does not retroactively make it healthy. So the
// abandoned attempt's result is never read back — the next tick starts a fresh
// probe instead. Reporting that late success would publish Up=true without any
// probe having actually met its deadline.
//
// While an abandoned attempt is still running, a tick reports down without
// starting another one, so a wedged store leaves exactly one probe goroutine
// alive rather than one per tick. The attempt clears itself when it finally
// returns, and the tick after that starts fresh, which is how recovery is
// observed.
func (c *Checker) boundedProbe(ctx context.Context) error {
	c.inflightMu.Lock()
	if c.inflight != nil {
		c.inflightMu.Unlock()
		return fmt.Errorf("store probe exceeded its %s deadline (previous probe still running)", c.timeout)
	}
	att := &probeAttempt{done: make(chan error, 1)}
	c.inflight = att
	c.inflightMu.Unlock()

	go func() {
		att.done <- c.probeOnce(ctx)
		c.inflightMu.Lock()
		if c.inflight == att {
			c.inflight = nil
		}
		c.inflightMu.Unlock()
	}()

	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	select {
	case err := <-att.done:
		return err
	case <-timer.C:
		return fmt.Errorf("store probe exceeded its %s deadline (store not responding)", c.timeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// probeOnce is one write + read-back round trip under a single deadline for
// the whole thing. Reading the exact nonce back is the point: a read-only
// replica, a full disk or a silently lossy backend all accept a Set, and
// ok=true alone would pass them as healthy.
func (c *Checker) probeOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("probe nonce: %w", err)
	}
	if err := c.st.Set(ctx, c.key, nonce[:], c.ttl); err != nil {
		return fmt.Errorf("probe write: %w", err)
	}
	got, ok, err := c.st.Get(ctx, c.key)
	if err != nil {
		return fmt.Errorf("probe read: %w", err)
	}
	if !ok {
		return errors.New("probe read: key absent immediately after a successful write")
	}
	if !bytes.Equal(got, nonce[:]) {
		return errors.New("probe read: value does not match the nonce just written")
	}
	return nil
}

// publish stores a snapshot and re-arms the staleness timer under one lock, so
// the generation a timer is armed for always matches the snapshot it guards.
func (c *Checker) publish(s Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	s.gen = c.gen
	c.snap.Store(&s)
	if c.closed {
		return
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	gen := c.gen
	c.timer = time.AfterFunc(c.interval*staleFactor, func() { c.markStale(gen) })
}

// markStale fires when no probe completed for staleFactor intervals, i.e. the
// probe loop wedged. Publishing Stale keeps /readyz and Prometheus agreeing
// instead of serving an indefinitely old "up". It is a no-op once a newer
// probe has published, so a superseded timer can never overwrite fresher
// state. No timer is re-armed: the next completed probe does that, which also
// keeps the warning to one line per wedge.
func (c *Checker) markStale(gen uint64) {
	c.mu.Lock()
	prev := c.snap.Load()
	if c.closed || c.gen != gen || prev == nil {
		c.mu.Unlock()
		return
	}
	s := *prev
	s.Stale = true
	s.Up = false
	c.gen++
	s.gen = c.gen
	c.snap.Store(&s)
	c.mu.Unlock()

	if c.rec != nil {
		c.rec.StoreProbeStale(c.backend)
	}
	c.log.Warn("store probe is stale, treating the store as down",
		"backend", c.backend, "last_checked", prev.CheckedAt)
}

// ProbeForTest runs one probe synchronously, for tests in other packages that
// need a definite readiness state without waiting on the ticker.
func (c *Checker) ProbeForTest(ctx context.Context) { c.probe(ctx) }

// MarkStaleForTest publishes the outcome the freshness timer would, for tests
// that need the stale readiness state without wedging the probe loop.
func (c *Checker) MarkStaleForTest() {
	c.mu.Lock()
	gen := c.gen
	c.mu.Unlock()
	c.markStale(gen)
}
