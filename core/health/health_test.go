// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// fakeStore wraps a real store so a test only overrides the one operation it
// wants to break; everything else keeps working, which is what makes "Set
// succeeds but Get lies" expressible at all.
type fakeStore struct {
	store.Store
	setErr   error
	getErr   error
	getMiss  bool          // Get reports ok=false
	getWrong bool          // Get returns a value that is not the nonce
	setBlock time.Duration // Set stalls but honors ctx, like redis
	setHang  chan struct{} // Set blocks until closed, ignoring ctx (pebble/buntdb)
	setCalls atomic.Int64
	// setSleep (nanoseconds) makes Set slow but eventually successful, ignoring
	// ctx. Atomic because a test flips it mid-run to model a store recovering
	// while an abandoned probe goroutine may still be reading it.
	setSleep atomic.Int64
}

func (f *fakeStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	f.setCalls.Add(1)
	if f.setHang != nil {
		// Deliberately ignores ctx: the shipping embedded backends run their
		// I/O without consulting it, so this is the case boundedProbe must
		// still bound on wall-clock time.
		<-f.setHang
	}
	if d := f.setSleep.Load(); d > 0 {
		time.Sleep(time.Duration(d)) // also ignores ctx, on purpose
	}
	if f.setBlock > 0 {
		select {
		case <-time.After(f.setBlock):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.setErr != nil {
		return f.setErr
	}
	return f.Store.Set(ctx, key, value, ttl)
}

func (f *fakeStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	if f.getMiss {
		return nil, false, nil
	}
	if f.getWrong {
		return []byte("not-the-nonce"), true, nil
	}
	return f.Store.Get(ctx, key)
}

// recorder captures what the Checker reported, in order.
type recorder struct {
	mu       sync.Mutex
	probes   []bool
	backends []string
	stale    int
	skews    []float64
}

func (r *recorder) StoreClockSkew(_ string, seconds float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skews = append(r.skews, seconds)
}

func (r *recorder) lastSkew() (float64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.skews) == 0 {
		return 0, false
	}
	return r.skews[len(r.skews)-1], true
}

func (r *recorder) StoreProbe(backend string, up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probes = append(r.probes, up)
	r.backends = append(r.backends, backend)
}

func (r *recorder) StoreProbeStale(backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stale++
	r.backends = append(r.backends, backend)
}

func (r *recorder) snapshot() ([]bool, []string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.probes...), append([]string(nil), r.backends...), r.stale
}

// logBuffer is a slog handler target that a test can read back. Guarded because
// the probe loop may write from its own goroutine.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newChecker(t *testing.T, st store.Store, rec Recorder, log *slog.Logger) *Checker {
	t.Helper()
	if log == nil {
		log = slog.New(slog.NewTextHandler(&logBuffer{}, nil))
	}
	c := New(st, "memory", rec, log)
	t.Cleanup(func() { c.Close() })
	return c
}

// clockStore adds a controllable ServerClock capability on top of a Store.
type clockStore struct {
	store.Store
	offset time.Duration
	err    error
}

func (c *clockStore) ServerTime(context.Context) (time.Time, error) {
	if c.err != nil {
		return time.Time{}, c.err
	}
	return time.Now().Add(c.offset), nil
}

// TestProbeObservesClockSkew: a ServerClock-capable backend gets its clock
// compared on every successful probe; crossing the warn threshold logs once,
// and returning under it logs the recovery once.
func TestProbeObservesClockSkew(t *testing.T) {
	mem := store.NewMemory()
	t.Cleanup(func() { mem.Close() })
	cs := &clockStore{Store: mem, offset: 90 * time.Second}
	rec := &recorder{}
	buf := &logBuffer{}
	c := newChecker(t, cs, rec, slog.New(slog.NewTextHandler(buf, nil)))

	c.probe(context.Background())
	skew, ok := rec.lastSkew()
	if !ok || skew < 85 || skew > 95 {
		t.Fatalf("skew = %v (reported=%v), want ~90s", skew, ok)
	}
	if !strings.Contains(buf.String(), "store clock skew detected") {
		t.Error("expected a skew warning above the threshold")
	}

	// Back under the threshold: gauge follows, transition logged once.
	cs.offset = 0
	c.probe(context.Background())
	if skew, _ := rec.lastSkew(); skew > 1 || skew < -1 {
		t.Errorf("skew after recovery = %v, want ~0", skew)
	}
	if !strings.Contains(buf.String(), "store clock skew back under threshold") {
		t.Error("expected a skew recovery line")
	}

	// A failing TIME call must not clear or update the gauge, only skip.
	before := len(rec.skews)
	cs.err = errors.New("no TIME for you")
	c.probe(context.Background())
	if len(rec.skews) != before {
		t.Errorf("skew reported despite ServerTime error")
	}
}

// TestProbeSkipsSkewWithoutCapability: embedded backends share the process
// clock; no ServerClock capability means no gauge and no warning.
func TestProbeSkipsSkewWithoutCapability(t *testing.T) {
	mem := store.NewMemory()
	t.Cleanup(func() { mem.Close() })
	rec := &recorder{}
	c := newChecker(t, mem, rec, nil)
	c.probe(context.Background())
	if _, ok := rec.lastSkew(); ok {
		t.Error("skew reported for a backend without ServerClock")
	}
}

// TestProbeHealthyStore: a working store round trips the nonce, so the first
// synchronous probe publishes Up before Start returns and the gauge is set.
func TestProbeHealthyStore(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	rec := &recorder{}
	c := newChecker(t, st, rec, nil)

	c.Start(context.Background())

	got := c.Status()
	if !got.Probed || !got.Up || got.Stale {
		t.Fatalf("status = %+v, want probed and up", got)
	}
	if got.Backend != "memory" {
		t.Errorf("backend = %q, want memory", got.Backend)
	}
	if got.Err != "" {
		t.Errorf("err = %q, want empty", got.Err)
	}
	if got.CheckedAt.IsZero() {
		t.Error("checked_at is zero after a completed probe")
	}
	probes, backends, stale := rec.snapshot()
	if len(probes) == 0 || !probes[0] {
		t.Fatalf("recorder probes = %v, want a leading true", probes)
	}
	if backends[0] != "memory" {
		t.Errorf("recorder backend = %q, want memory", backends[0])
	}
	if stale != 0 {
		t.Errorf("stale reported %d times on a healthy store", stale)
	}
}

// TestProbeFailureModes: every way a store can fail to complete the round trip
// counts as down. A backend that accepts the write and then cannot return the
// exact bytes is the whole reason the probe reads back rather than trusting a
// successful Set: a read-only replica or a full disk looks fine on write alone.
func TestProbeFailureModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   func(inner store.Store) store.Store
		want string
	}{
		{"set errors", func(in store.Store) store.Store {
			return &fakeStore{Store: in, setErr: errors.New("disk full")}
		}, "probe write"},
		{"get errors", func(in store.Store) store.Store {
			return &fakeStore{Store: in, getErr: errors.New("connection refused")}
		}, "probe read"},
		{"get reports missing", func(in store.Store) store.Store {
			return &fakeStore{Store: in, getMiss: true}
		}, "absent immediately after"},
		{"get returns another value", func(in store.Store) store.Store {
			return &fakeStore{Store: in, getWrong: true}
		}, "does not match the nonce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := store.NewMemory()
			t.Cleanup(func() { inner.Close() })
			rec := &recorder{}
			c := newChecker(t, tc.st(inner), rec, nil)

			c.probe(context.Background())

			got := c.Status()
			if !got.Probed {
				t.Fatal("probed = false after a completed probe attempt")
			}
			if got.Up {
				t.Fatalf("up = true, want down: %+v", got)
			}
			if !strings.Contains(got.Err, tc.want) {
				t.Errorf("err = %q, want it to mention %q", got.Err, tc.want)
			}
			// A failed probe still has a latency: how long the store took to
			// fail is exactly what an operator wants during an incident.
			if got.LatencyMS < 0 {
				t.Errorf("latency_ms = %v, want a recorded duration", got.LatencyMS)
			}
			if probes, _, _ := rec.snapshot(); len(probes) != 1 || probes[0] {
				t.Errorf("recorder probes = %v, want exactly one false", probes)
			}
		})
	}
}

// TestProbeTimeout: a store that never answers must fail the probe rather than
// wedge the loop, so the whole write/read round trip runs under one deadline.
func TestProbeTimeout(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	c := newChecker(t, &fakeStore{Store: inner, setBlock: time.Minute}, nil, nil)
	c.timeout = 20 * time.Millisecond

	start := time.Now()
	err := c.probeOnce(context.Background())
	if err == nil {
		t.Fatal("probeOnce returned nil against a store that never answers")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("probeOnce took %v, want the configured timeout to cut it short", elapsed)
	}
}

// TestProbeWallClockBoundIgnoresContext: a store that never returns and ignores
// ctx (the pebble/buntdb reality) must not let a probe hang past the deadline,
// or a slow op would publish Up=true and a hung first probe would block Start
// (and both listeners) or a Close waiting on the loop. The bound is enforced
// independently of the store honoring cancellation.
func TestProbeWallClockBoundIgnoresContext(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	hang := make(chan struct{})
	fs := &fakeStore{Store: inner, setHang: hang}
	c := newChecker(t, fs, nil, nil)
	c.timeout = 30 * time.Millisecond
	t.Cleanup(func() { close(hang) }) // release the leaked probe goroutine

	start := time.Now()
	c.probe(context.Background())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe took %v against a ctx-ignoring hung store; the deadline is not enforced independently", elapsed)
	}
	got := c.Status()
	if got.Up {
		t.Errorf("status = %+v, want down: a stalled store must not publish up", got)
	}
	if !strings.Contains(got.Err, "deadline") {
		t.Errorf("err = %q, want it to mention the deadline", got.Err)
	}

	// A second tick against the still-wedged store must not spawn a second
	// probe goroutine: the in-flight one is reused.
	c.probe(context.Background())
	if n := fs.setCalls.Load(); n != 1 {
		t.Errorf("Set called %d times across two ticks on a wedged store, want 1 (one in-flight probe)", n)
	}
}

// TestLateSuccessAfterTimeoutIsDiscarded is the regression for the bug where an
// abandoned probe's result was consumed by the next tick. The store here ignores
// ctx and takes longer than the deadline but does eventually succeed, so every
// attempt times out while producing a late "success". Publishing one of those
// would report Up=true although no probe ever met its deadline — a store too
// slow to answer inside the window is down, and completing afterwards does not
// retroactively make it healthy.
func TestLateSuccessAfterTimeoutIsDiscarded(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	fs := &fakeStore{Store: inner}
	fs.setSleep.Store(int64(40 * time.Millisecond))
	rec := &recorder{}
	c := newChecker(t, fs, rec, nil)
	c.timeout = 20 * time.Millisecond

	c.probe(context.Background())
	if got := c.Status(); got.Up {
		t.Fatalf("first probe = %+v, want down: it exceeded the deadline", got)
	}

	// Let the abandoned attempt finish its late, successful write and release
	// the in-flight slot. Its result must be dropped, not queued for the next
	// tick to pick up.
	time.Sleep(120 * time.Millisecond)

	c.probe(context.Background())
	if got := c.Status(); got.Up {
		t.Fatalf("second probe = %+v, want down: it must run a fresh probe, "+
			"not publish the late success of the attempt that already timed out", got)
	}
	// Both ticks ran a real probe against the (still too slow) store.
	if n := fs.setCalls.Load(); n != 2 {
		t.Errorf("Set called %d times, want 2: the second tick must probe afresh", n)
	}
	if probes, _, _ := rec.snapshot(); len(probes) != 2 || probes[0] || probes[1] {
		t.Errorf("recorder probes = %v, want two downs", probes)
	}
}

// TestRecoveryAfterDeadlineMisses: the flip side of discarding late results —
// once the store answers inside the deadline again, readiness must recover.
func TestRecoveryAfterDeadlineMisses(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	fs := &fakeStore{Store: inner}
	fs.setSleep.Store(int64(40 * time.Millisecond))
	c := newChecker(t, fs, nil, nil)
	c.timeout = 20 * time.Millisecond

	c.probe(context.Background())
	if c.Status().Up {
		t.Fatal("precondition: the slow store should have failed the deadline")
	}
	time.Sleep(120 * time.Millisecond) // let the abandoned attempt drain

	fs.setSleep.Store(0) // the store gets healthy again
	c.probe(context.Background())
	if got := c.Status(); !got.Up {
		t.Fatalf("status = %+v, want up once the store answers within the deadline", got)
	}
}

// TestStartAndCloseSurviveAHungStore: the two lifecycle hazards the wall-clock
// bound exists to prevent. Start must return even if the first probe is wedged,
// and Close must then return even though the probe goroutine is still stuck.
func TestStartAndCloseSurviveAHungStore(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	hang := make(chan struct{})
	defer close(hang)
	c := New(inner, "memory", nil, slog.New(slog.NewTextHandler(&logBuffer{}, nil)))
	c.timeout = 30 * time.Millisecond
	// Swap in the hanging store after construction so New's key setup is normal.
	c.st = &fakeStore{Store: inner, setHang: hang}

	done := make(chan struct{})
	go func() {
		c.Start(context.Background())
		c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Start+Close did not return against a hung store; the probe blocked the lifecycle")
	}
}

// TestStaleSnapshot: if the probe loop wedges, the last snapshot stops counting
// as current. The gauge is driven to 0 through StoreProbeStale rather than
// through a probe counter, since no probe actually completed.
func TestStaleSnapshot(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	rec := &recorder{}
	c := newChecker(t, st, rec, nil)
	c.interval = 20 * time.Millisecond

	c.probe(context.Background()) // publishes Up and arms the freshness timer
	if got := c.Status(); !got.Up || got.Stale {
		t.Fatalf("status = %+v, want a fresh up snapshot", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := c.Status()
		if got.Stale {
			if got.Up {
				t.Errorf("stale snapshot still reports up: %+v", got)
			}
			if !got.Probed {
				t.Error("stale snapshot lost the probed flag")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot never went stale: %+v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}

	probes, _, stale := rec.snapshot()
	if stale != 1 {
		t.Errorf("StoreProbeStale called %d times, want 1", stale)
	}
	if len(probes) != 1 {
		t.Errorf("recorder saw %d completed probes, want 1 (staleness is not a probe)", len(probes))
	}
}

// TestStaleTimerSuperseded: a freshness timer armed for an older snapshot must
// not overwrite a newer successful probe. Without the generation guard a timer
// that fires just after a fresh probe would report a live store as stale.
func TestStaleTimerSuperseded(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	c := newChecker(t, st, nil, nil)

	c.probe(context.Background()) // generation 1
	c.probe(context.Background()) // generation 2 supersedes it

	c.markStale(1) // the generation-1 timer, firing late

	if got := c.Status(); got.Stale || !got.Up {
		t.Fatalf("status = %+v, want the newer up snapshot to survive", got)
	}
}

// TestTransitionLogging: an unreachable store must not fill the log with one
// line per tick. Exactly one warning on the way down and one line on recovery.
func TestTransitionLogging(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	broken := &fakeStore{Store: inner, getErr: errors.New("connection refused")}
	logs := &logBuffer{}
	c := newChecker(t, broken, nil, slog.New(slog.NewTextHandler(logs, nil)))

	ctx := context.Background()
	for range 4 {
		c.probe(ctx)
	}
	if n := strings.Count(logs.String(), "failing open"); n != 1 {
		t.Errorf("logged the down transition %d times over 4 failing probes, want 1", n)
	}

	broken.getErr = nil
	for range 3 {
		c.probe(ctx)
	}
	if !c.Status().Up {
		t.Fatal("store did not recover after the fault was cleared")
	}
	if n := strings.Count(logs.String(), "recovered"); n != 1 {
		t.Errorf("logged recovery %d times over 3 healthy probes, want 1", n)
	}
	// The down transition must not be re-logged by the recovery run.
	if n := strings.Count(logs.String(), "failing open"); n != 1 {
		t.Errorf("down transition logged %d times in total, want 1", n)
	}
}

// TestFirstProbeFailureLogs: starting against a dead store is the case an
// operator most needs in the log, so the very first failure is a transition.
func TestFirstProbeFailureLogs(t *testing.T) {
	inner := store.NewMemory()
	t.Cleanup(func() { inner.Close() })
	logs := &logBuffer{}
	c := newChecker(t, &fakeStore{Store: inner, setErr: errors.New("read-only file system")},
		nil, slog.New(slog.NewTextHandler(logs, nil)))

	c.probe(context.Background())

	if !strings.Contains(logs.String(), "failing open") {
		t.Errorf("first failing probe was not logged: %q", logs.String())
	}
	if strings.Contains(logs.String(), "recovered") {
		t.Error("a first failing probe must not log a recovery")
	}
}

// TestFirstProbeSuccessIsQuiet: a normal startup logs nothing; there was no
// outage to recover from.
func TestFirstProbeSuccessIsQuiet(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	logs := &logBuffer{}
	c := newChecker(t, st, nil, slog.New(slog.NewTextHandler(logs, nil)))

	c.probe(context.Background())

	if s := logs.String(); s != "" {
		t.Errorf("healthy startup logged %q, want silence", s)
	}
}

// TestStartProbesBeforeReturning: the gauge and /readyz must never observe an
// uninitialized series, so Start completes the first probe synchronously.
func TestStartProbesBeforeReturning(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	rec := &recorder{}
	c := newChecker(t, st, rec, nil)

	c.Start(context.Background())

	if probes, _, _ := rec.snapshot(); len(probes) == 0 {
		t.Fatal("Start returned before any probe was recorded")
	}
	if !c.Status().Probed {
		t.Fatal("Start returned with an unprobed status")
	}
}

// TestCloseIsIdempotent: Close is wired as a defer next to other subsystems and
// may also run on an explicit shutdown path.
func TestCloseIsIdempotent(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	c := New(st, "memory", nil, slog.New(slog.NewTextHandler(&logBuffer{}, nil)))
	c.Start(context.Background())

	for range 3 {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	// The store outlives the checker: ownership stays with the caller.
	if err := st.Set(context.Background(), "still", []byte("open"), time.Minute); err != nil {
		t.Errorf("Close closed the store it does not own: %v", err)
	}
}

// TestCloseWithoutStart: Close must be safe on a checker that never ran, which
// is what happens when startup fails between New and Start.
func TestCloseWithoutStart(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	if err := New(st, "memory", nil, nil).Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
}

// TestNilChecker: a nil *Checker is safe to call, and its zero status is
// "never probed", which readiness must never read as ready.
func TestNilChecker(t *testing.T) {
	var c *Checker
	c.Start(context.Background())
	if err := c.Close(); err != nil {
		t.Fatalf("Close on nil checker: %v", err)
	}
	got := c.Status()
	if got.Probed || got.Up {
		t.Fatalf("nil checker status = %+v, want the zero (never ready) status", got)
	}
}

// TestProbeKeyIsPerProcess: replicas sharing one Redis must not read each
// other's nonce, so the key carries a per-process suffix.
func TestProbeKeyIsPerProcess(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	a := New(st, "memory", nil, nil)
	b := New(st, "memory", nil, nil)

	if !strings.HasPrefix(a.key, probeKeyPrefix) {
		t.Errorf("probe key %q does not use the reserved prefix", a.key)
	}
	if a.key == b.key {
		t.Errorf("two checkers share the probe key %q", a.key)
	}
}

// TestLoopKeepsProbing: after Start the ticker keeps the snapshot fresh
// without any request touching the store.
func TestLoopKeepsProbing(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	rec := &recorder{}
	c := newChecker(t, st, rec, nil)
	c.interval = 10 * time.Millisecond

	c.Start(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for {
		if probes, _, _ := rec.snapshot(); len(probes) >= 3 {
			return
		}
		if time.Now().After(deadline) {
			probes, _, _ := rec.snapshot()
			t.Fatalf("probe loop recorded %d probes, want at least 3", len(probes))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
