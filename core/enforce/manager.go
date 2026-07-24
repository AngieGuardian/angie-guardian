// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package enforce

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/internal/jitter"
)

// sinkQueueCap bounds each sink's event queue. A wedged sink (hung netlink)
// can therefore never block Notify or the request path; overflow drops the
// event with a metric and the next reconcile repairs the sink.
const sinkQueueCap = 4096

// reconcileTimeout caps one indexed reconcile so a dead store cannot wedge
// the reconcile loop; the mirror keeps its last state until the next tick.
const reconcileTimeout = 30 * time.Second

// errLogInterval rate-limits repeated per-sink error logging (one line per
// interval, with a counter of suppressed occurrences).
const errLogInterval = time.Minute

type sinkRunner struct {
	sink       Sink
	ch         chan BlockEvent
	mu         sync.Mutex // serializes Apply with destructive replace-all Reconcile
	lastErrLog atomic.Int64
	suppressed atomic.Uint64
}

// Manager owns the mirror plus optional external sinks and the reconcile
// loop. All methods are safe on a nil receiver (feature-off no-ops), matching
// the metrics discipline, so callers never nil-check.
type Manager struct {
	cfg     Config
	st      store.Store
	log     *slog.Logger
	metrics *metrics.Metrics
	mir     *mirror
	sinks   []*sinkRunner

	// seeded flips after the first successful scan. Until then the mirror
	// may be missing blocks persisted before this process started (pebble/buntdb),
	// so lookups fall back to the store even in authoritative mode.
	seeded atomic.Bool
	// mirrorState packs a monotonic drop generation in the upper bits and the
	// completeness flag in bit zero. A reconcile may only publish its result
	// while the generation it scanned under is unchanged. This prevents a
	// concurrent capacity drop from being overwritten by a stale "complete"
	// result after the scan took its store snapshot.
	mirrorState    atomic.Uint64
	sinkGeneration atomic.Uint64
	lastReconcile  atomic.Int64
	reconcileErrs  atomic.Uint64

	now    func() time.Time
	kick   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New builds a manager. Sink construction failures are logged and reported
// through Status, never returned as fatal: enforcement always degrades to
// the in-daemon paths.
func New(cfg Config, st store.Store, m *metrics.Metrics, log *slog.Logger) *Manager {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "block:"
	}
	if cfg.ReconcileInterval < time.Second {
		cfg.ReconcileInterval = 10 * time.Second
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1 << 20
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeAuthoritative
	}
	mgr := &Manager{
		cfg:     cfg,
		st:      st,
		log:     log,
		metrics: m,
		mir:     newMirror(cfg.MaxEntries),
		now:     time.Now,
		kick:    make(chan struct{}, 1),
	}
	if cfg.NFTables.Enabled {
		sink, err := newNFTSink(cfg.NFTables, log)
		if err != nil {
			// Init retries happen on every reconcile tick via Sink.Reconcile,
			// so a daemon started before its capability grant self-heals.
			log.Error("nftables sink unavailable, enforcement stays in-daemon", "err", err)
			mgr.metrics.OffloadHealthy("nftables", false)
		}
		if sink != nil {
			mgr.addSink(sink)
		}
	}
	return mgr
}

func (m *Manager) addSink(s Sink) {
	m.sinks = append(m.sinks, &sinkRunner{sink: s, ch: make(chan BlockEvent, sinkQueueCap)})
}

// Start seeds the mirror from the store and begins the reconcile loop and
// sink workers. Call once; Close stops everything.
func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	ctx, m.cancel = context.WithCancel(ctx)
	for _, sr := range m.sinks {
		m.wg.Add(1)
		go m.runSink(ctx, sr)
	}
	m.wg.Add(1)
	go m.runReconcile(ctx)
}

// Close stops background work and releases sink resources (kernel state is
// left in place on purpose: nft elements expire by their own timeouts).
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	for _, sr := range m.sinks {
		if err := sr.sink.Close(); err != nil {
			m.log.Warn("sink close failed", "sink", sr.sink.Name(), "err", err)
		}
	}
	return nil
}

// Lookup is the hot path: one shard read, no store I/O, no allocation.
func (m *Manager) Lookup(ip string) (reason string, ok bool) {
	if m == nil {
		return "", false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	return m.mir.get(a.Unmap(), m.now().UnixNano())
}

// ReadThrough reports whether a mirror miss must still consult the store:
// always before the seed scan completes (the mirror may not know blocks
// persisted by a previous run), and permanently when the store is shared and
// another replica may place blocks this process never saw.
func (m *Manager) ReadThrough() bool {
	if m == nil {
		return true
	}
	return m.cfg.Mode == ModeReadThrough || !m.seeded.Load() || !m.mirrorComplete()
}

func (m *Manager) mirrorComplete() bool { return m.mirrorState.Load()&1 != 0 }

// markMirrorIncomplete advances the generation as well as clearing complete.
// The generation is what makes the clear linearizable with a reconcile that
// is concurrently preparing to publish a successful scan.
func (m *Manager) markMirrorIncomplete() {
	for {
		old := m.mirrorState.Load()
		next := ((old >> 1) + 1) << 1
		if m.mirrorState.CompareAndSwap(old, next) {
			return
		}
	}
}

// publishMirrorReconcile publishes only if no capacity drop happened since
// the scan started. A later drop always advances the generation and clears
// complete, regardless of whether it races before or after this CAS.
func (m *Manager) publishMirrorReconcile(generation uint64, complete bool) {
	for {
		old := m.mirrorState.Load()
		if old>>1 != generation {
			return
		}
		next := old &^ uint64(1)
		if complete {
			next |= 1
		}
		if m.mirrorState.CompareAndSwap(old, next) {
			return
		}
	}
}

// Notify applies one block change: mirror synchronously (nanoseconds), sinks
// via their bounded queues. Never blocks, never errors.
func (m *Manager) Notify(ev BlockEvent) {
	if m == nil || !ev.IP.IsValid() {
		return
	}
	ev.IP = ev.IP.Unmap()
	now := m.now()
	if ev.Remove {
		m.mir.remove(ev.IP, now.UnixNano())
	} else {
		var exp int64
		if ev.TTL > 0 {
			exp = now.Add(ev.TTL).UnixNano()
		}
		if !m.mir.set(ev.IP, entry{reason: ev.Reason, expiresAt: exp, insertedAt: now.UnixNano()}) {
			m.markMirrorIncomplete()
			m.metrics.OffloadOp("mirror", "add", "dropped")
			m.log.Warn("block mirror full, entry falls back to store enforcement", "ip", ev.IP.String())
		}
	}
	m.metrics.OffloadEntries("mirror", m.mir.count())
	// Publish a generation before queueing. Reconcile uses it together with the
	// runner mutex to ensure a replace-all snapshot can never land after an
	// event newer than that snapshot.
	m.sinkGeneration.Add(1)
	for _, sr := range m.sinks {
		select {
		case sr.ch <- ev:
		default:
			m.metrics.OffloadOp(sr.sink.Name(), opOf(ev), "dropped")
		}
	}
}

// Learn caches a block discovered through the store read-through path, so a
// flood's second request onward is denied without store I/O. The retention is
// provisional (two reconcile intervals); the next scan installs the real
// expiry, and an unblock on another replica is picked up within one interval.
func (m *Manager) Learn(ip, reason string) {
	if m == nil {
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	now := m.now()
	if !m.mir.set(a.Unmap(), entry{
		reason:     reason,
		expiresAt:  now.Add(2 * m.cfg.ReconcileInterval).UnixNano(),
		insertedAt: now.UnixNano(),
	}) {
		m.markMirrorIncomplete()
	}
}

// ForceReconcile schedules an immediate scan (admin drift repair). Non-blocking.
func (m *Manager) ForceReconcile() {
	if m == nil {
		return
	}
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Status snapshots the manager for GET /admin/offload.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	st := Status{Mirror: MirrorStatus{
		Entries:         m.mir.count(),
		Mode:            m.cfg.Mode,
		Seeded:          m.seeded.Load(),
		Complete:        m.mirrorComplete(),
		ReconcileErrors: m.reconcileErrs.Load(),
		Dropped:         m.mir.dropped.Load(),
	}}
	if ns := m.lastReconcile.Load(); ns > 0 {
		st.Mirror.LastReconcile = time.Unix(0, ns)
	}
	for _, sr := range m.sinks {
		st.Sinks = append(st.Sinks, sr.sink.Status())
	}
	return st
}

func (m *Manager) runReconcile(ctx context.Context) {
	defer m.wg.Done()
	m.reconcileOnce(ctx)
	// Jittered interval so a fleet restarted together does not scan the shared
	// block index in lockstep every tick. A manual kick still runs immediately.
	t := time.NewTimer(jitter.Frac(m.cfg.ReconcileInterval, jitter.Fraction))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.reconcileOnce(ctx)
			t.Reset(jitter.Frac(m.cfg.ReconcileInterval, jitter.Fraction))
		case <-m.kick:
			m.reconcileOnce(ctx)
		}
	}
}

func (m *Manager) reconcileOnce(ctx context.Context) {
	scanStart := m.now()
	scanGeneration := m.mirrorState.Load() >> 1
	sinkScanGeneration := m.sinkGeneration.Load()
	sctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	var (
		kvs        []store.KV
		scannedAll = true
		err        error
	)
	_, indexed := m.st.(store.ActiveBlockScanner)
	if scanner, ok := m.st.(store.ActiveBlockScanner); ok {
		kvs, scannedAll, err = scanner.ScanActiveBlocks(sctx, m.cfg.KeyPrefix, m.cfg.MaxEntries)
		if errors.Is(err, store.ErrCapabilityUnsupported) {
			indexed = false
			err = nil
		}
	}
	if !indexed {
		// Compatibility path for third-party stores. Built-in stores all expose
		// the dedicated index and never reach this broad scan on a tick.
		kvs, scannedAll, err = m.scanBlocksFallback(sctx)
	}
	cancel()
	if err != nil {
		m.reconcileErrs.Add(1)
		m.metrics.OffloadReconcile(false)
		// Mirror hits keep denying while the store is down; entries expire by
		// their own TTLs, so stale state is bounded even during a long outage.
		m.log.Warn("block index reconcile failed, keeping last mirror state", "err", err)
		return
	}
	active := make(map[netip.Addr]entry, len(kvs))
	list := make([]ActiveBlock, 0, len(kvs))
	for _, kv := range kvs {
		a, err := netip.ParseAddr(strings.TrimPrefix(kv.Key, m.cfg.KeyPrefix))
		if err != nil {
			continue
		}
		a = a.Unmap()
		var exp int64
		if !kv.ExpiresAt.IsZero() {
			exp = kv.ExpiresAt.UnixNano()
		}
		active[a] = entry{reason: string(kv.Value), expiresAt: exp, insertedAt: scanStart.UnixNano()}
		list = append(list, ActiveBlock{Addr: a, Reason: string(kv.Value), ExpiresAt: kv.ExpiresAt})
	}
	m.publishMirrorReconcile(scanGeneration, m.mir.reconcile(active, scanStart.UnixNano(), scannedAll))
	m.seeded.Store(true)
	m.lastReconcile.Store(scanStart.UnixNano())
	m.metrics.OffloadReconcile(true)
	m.metrics.OffloadEntries("mirror", m.mir.count())
	// Reconcile is a replace-all operation for external sinks. Never feed it a
	// capped or concurrently changing snapshot: doing so would remove valid
	// kernel blocks that were outside the partial result.
	if !scannedAll {
		if len(m.sinks) > 0 {
			m.metrics.OffloadReconcileSkipped("incomplete_snapshot")
		}
		return
	}
	skippedStale := false
	for _, sr := range m.sinks {
		sr.mu.Lock()
		// A newer Notify is either already applied or waiting on this same mutex.
		// In the former case this snapshot is stale; in the latter case it will
		// apply immediately after a safe reconcile.
		if m.sinkGeneration.Load() != sinkScanGeneration {
			skippedStale = true
			sr.mu.Unlock()
			continue
		}
		err := sr.sink.Reconcile(list)
		sr.mu.Unlock()
		if err != nil {
			m.logSinkErr(sr, "reconcile", err)
		}
		st := sr.sink.Status()
		m.metrics.OffloadHealthy(st.Name, st.Healthy)
		m.metrics.OffloadEntries(st.Name, st.Elements)
	}
	if skippedStale {
		m.metrics.OffloadReconcileSkipped("concurrent_event")
	}
}

// scanBlocksFallback is the bounded compatibility path for stores without the
// backend-native active-block index (including wrappers that explicitly
// report ErrCapabilityUnsupported).
func (m *Manager) scanBlocksFallback(ctx context.Context) ([]store.KV, bool, error) {
	if scanner, ok := m.st.(store.LimitedScanner); ok {
		return scanner.ScanLimit(ctx, m.cfg.KeyPrefix, m.cfg.MaxEntries)
	}
	kvs, err := m.st.Scan(ctx, m.cfg.KeyPrefix)
	if err != nil || len(kvs) <= m.cfg.MaxEntries {
		return kvs, true, err
	}
	return kvs[:m.cfg.MaxEntries], false, nil
}

func (m *Manager) runSink(ctx context.Context, sr *sinkRunner) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-sr.ch:
			sr.mu.Lock()
			err := sr.sink.Apply(ev)
			sr.mu.Unlock()
			if err != nil {
				m.metrics.OffloadOp(sr.sink.Name(), opOf(ev), "error")
				m.logSinkErr(sr, opOf(ev), err)
			} else {
				m.metrics.OffloadOp(sr.sink.Name(), opOf(ev), "ok")
			}
		}
	}
}

// logSinkErr logs at most one line per sink per errLogInterval, so a sink
// failing on every event during an attack cannot flood the log.
func (m *Manager) logSinkErr(sr *sinkRunner, op string, err error) {
	now := m.now().UnixNano()
	last := sr.lastErrLog.Load()
	if now-last < int64(errLogInterval) || !sr.lastErrLog.CompareAndSwap(last, now) {
		sr.suppressed.Add(1)
		return
	}
	m.log.Warn("enforcement sink error",
		"sink", sr.sink.Name(), "op", op, "err", err,
		"suppressed_since_last", sr.suppressed.Swap(0))
}

func opOf(ev BlockEvent) string {
	if ev.Remove {
		return "remove"
	}
	return "add"
}
