// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package enforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	guardianmetrics "github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/store"
)

type fakeSink struct {
	mu         sync.Mutex
	applied    []BlockEvent
	reconciled [][]ActiveBlock
	err        error
}

func (f *fakeSink) Name() string { return "fake" }

func (f *fakeSink) Apply(ev BlockEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.applied = append(f.applied, ev)
	return nil
}

func (f *fakeSink) Reconcile(active []ActiveBlock) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.reconciled = append(f.reconciled, active)
	return nil
}

func (f *fakeSink) Status() SinkStatus { return SinkStatus{Name: "fake", Healthy: f.err == nil} }
func (f *fakeSink) Close() error       { return nil }

func newTestManager(t *testing.T, st store.Store, mode string) *Manager {
	t.Helper()
	m := New(Config{ReconcileInterval: time.Second, MaxEntries: 1024, Mode: mode},
		st, nil, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func metricCounter(t *testing.T, m *guardianmetrics.Metrics, name, labelName, labelValue string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == labelName && label.GetValue() == labelValue {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestManagerNilReceiver(t *testing.T) {
	var m *Manager
	m.Notify(BlockEvent{})
	m.Learn("203.0.113.9", "x")
	m.Start(context.Background())
	m.ForceReconcile()
	if _, ok := m.Lookup("203.0.113.9"); ok {
		t.Fatal("nil manager reported a hit")
	}
	if !m.ReadThrough() {
		t.Fatal("nil manager must be read-through (store fallback)")
	}
	_ = m.Status()
	_ = m.Close()
}

func TestManagerNotifyAndLookup(t *testing.T) {
	m := newTestManager(t, store.NewMemory(), ModeAuthoritative)
	m.Notify(BlockEvent{IP: addr(t, "203.0.113.9"), Reason: "threshold:tamper", TTL: time.Minute})

	if reason, ok := m.Lookup("203.0.113.9"); !ok || reason != "threshold:tamper" {
		t.Fatalf("Lookup = %q, %v; want threshold:tamper, true", reason, ok)
	}
	// IPv4-mapped IPv6 form of the same address hits the same entry.
	if _, ok := m.Lookup("::ffff:203.0.113.9"); !ok {
		t.Fatal("mapped-form lookup missed")
	}
	m.Notify(BlockEvent{IP: addr(t, "203.0.113.9"), Remove: true})
	if _, ok := m.Lookup("203.0.113.9"); ok {
		t.Fatal("removed block still hit")
	}
	if _, ok := m.Lookup("not-an-ip"); ok {
		t.Fatal("garbage input reported a hit")
	}
}

func TestManagerSinkFanOutAndErrorIsolation(t *testing.T) {
	st := store.NewMemory()
	m := newTestManager(t, st, ModeAuthoritative)
	good, bad := &fakeSink{}, &fakeSink{err: errors.New("netlink down")}
	m.addSink(good)
	m.addSink(bad)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	// Real callers persist the block before notifying; without the store
	// record a reconcile scan would (correctly) drop the mirror entry.
	if err := st.Set(ctx, "block:203.0.113.9", []byte("x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	ev := BlockEvent{IP: addr(t, "203.0.113.9"), Reason: "x", TTL: time.Minute}
	m.Notify(ev)

	deadline := time.Now().Add(2 * time.Second)
	for {
		good.mu.Lock()
		n := len(good.applied)
		good.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("healthy sink never received the event")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The erroring sink must not affect the mirror or lookups.
	if _, ok := m.Lookup("203.0.113.9"); !ok {
		t.Fatal("lookup lost the block because a sink errored")
	}
}

func TestManagerQueueOverflowNeverBlocks(t *testing.T) {
	// Workers are not started, so the sink queue fills; Notify must keep
	// returning without blocking and the mirror must keep enforcing.
	m := newTestManager(t, store.NewMemory(), ModeAuthoritative)
	m.addSink(&fakeSink{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range sinkQueueCap + 100 {
			m.Notify(BlockEvent{IP: addr(t, fmt.Sprintf("10.9.%d.%d", i/256, i%256)), Reason: "x", TTL: time.Minute})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Notify blocked on a full sink queue")
	}
	if _, ok := m.Lookup("10.9.0.0"); !ok {
		t.Fatal("mirror lost events during queue overflow")
	}
}

// scanFailStore lets a test flip the store into a failing state, which the
// memory backend cannot do on its own (its Scan never errors).
type scanFailStore struct {
	store.Store
	fail bool
}

type indexedNoScanStore struct {
	store.Store
	scans atomic.Int64
}

type partialBlockStore struct{ store.Store }

func (s *partialBlockStore) ScanActiveBlocks(context.Context, string, int) ([]store.KV, bool, error) {
	return []store.KV{{Key: "block:203.0.113.50", Value: []byte("partial"), ExpiresAt: time.Now().Add(time.Hour)}}, false, nil
}

func (s *indexedNoScanStore) Scan(ctx context.Context, prefix string) ([]store.KV, error) {
	s.scans.Add(1)
	return nil, errors.New("generic Scan must not be used")
}

func (s *indexedNoScanStore) ScanActiveBlocks(ctx context.Context, prefix string, limit int) ([]store.KV, bool, error) {
	return s.Store.(store.ActiveBlockScanner).ScanActiveBlocks(ctx, prefix, limit)
}

// blockingSnapshotStore takes the authoritative snapshot, then pauses before
// returning it. Tests can deterministically place a block after the snapshot
// but before reconcile publishes its completeness result.
type blockingSnapshotStore struct {
	store.Store
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (s *blockingSnapshotStore) ScanLimit(ctx context.Context, prefix string, limit int) ([]store.KV, bool, error) {
	kvs, err := s.Store.Scan(ctx, prefix)
	if err != nil {
		return nil, false, err
	}
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.resume:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	complete := len(kvs) <= limit
	if !complete {
		kvs = kvs[:limit]
	}
	return kvs, complete, nil
}

func TestManagerReconcileCannotOverwriteConcurrentCapacityDrop(t *testing.T) {
	ctx := t.Context()
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	st := &blockingSnapshotStore{
		Store: base, entered: make(chan struct{}), resume: make(chan struct{}),
	}
	m := New(Config{ReconcileInterval: time.Second, MaxEntries: shardCount, Mode: ModeAuthoritative},
		st, nil, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = m.Close() })

	done := make(chan struct{})
	go func() {
		m.reconcileOnce(ctx)
		close(done)
	}()
	<-st.entered // the empty store snapshot is now fixed

	// Fill every one-entry shard after the snapshot, then place one more
	// persisted block. Its mirror insertion must drop due to capacity.
	var perShard [shardCount]netip.Addr
	found := 0
	for i := 0; found < shardCount; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		shard := shardOf(a)
		if !perShard[shard].IsValid() {
			perShard[shard] = a
			found++
		}
	}
	for _, a := range perShard {
		if err := st.Set(ctx, "block:"+a.String(), []byte("fill"), time.Hour); err != nil {
			t.Fatal(err)
		}
		m.Notify(BlockEvent{IP: a, Reason: "fill", TTL: time.Hour})
	}
	target := addr(t, "203.0.113.200")
	if err := st.Set(ctx, "block:"+target.String(), []byte("target"), time.Hour); err != nil {
		t.Fatal(err)
	}
	m.Notify(BlockEvent{IP: target, Reason: "target", TTL: time.Hour})
	if _, ok := m.Lookup(target.String()); ok {
		t.Fatal("setup: target unexpectedly fit in the full mirror")
	}

	close(st.resume)
	<-done
	if !m.ReadThrough() || m.Status().Mirror.Complete {
		t.Fatal("stale reconcile marked a capacity-dropped mirror complete")
	}
}

func TestSinkReconcileCannotOverwriteNewerApply(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	st := &blockingSnapshotStore{
		Store: base, entered: make(chan struct{}), resume: make(chan struct{}),
	}
	met := guardianmetrics.New("memory")
	m := New(Config{ReconcileInterval: time.Second, MaxEntries: 1024, Mode: ModeAuthoritative},
		st, met, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = m.Close() })
	sink := &fakeSink{}
	m.addSink(sink)
	sr := m.sinks[0]
	m.wg.Add(1)
	go m.runSink(ctx, sr)

	done := make(chan struct{})
	go func() {
		m.reconcileOnce(ctx)
		close(done)
	}()
	<-st.entered // the empty replace-all snapshot is fixed

	ip := addr(t, "203.0.113.77")
	if err := st.Set(ctx, "block:"+ip.String(), []byte("new"), time.Hour); err != nil {
		t.Fatal(err)
	}
	m.Notify(BlockEvent{IP: ip, Reason: "new", TTL: time.Hour})
	close(st.resume)
	<-done

	deadline := time.Now().Add(time.Second)
	for {
		sink.mu.Lock()
		applied, reconciled := len(sink.applied), len(sink.reconciled)
		sink.mu.Unlock()
		if applied == 1 {
			if reconciled != 0 {
				t.Fatalf("stale replace-all ran after newer event: reconciles=%d", reconciled)
			}
			if got := metricCounter(t, met, "guardian_offload_reconcile_skipped_total", "reason", "concurrent_event"); got != 1 {
				t.Fatalf("concurrent-event skip counter = %v, want 1", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("newer sink event was not applied")
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *scanFailStore) Scan(ctx context.Context, prefix string) ([]store.KV, error) {
	if s.fail {
		return nil, errors.New("store down")
	}
	return s.Store.Scan(ctx, prefix)
}

func TestManagerReconcileSeedsAndConverges(t *testing.T) {
	ctx := context.Background()
	st := &scanFailStore{Store: store.NewMemory()}
	if err := st.Set(ctx, "block:203.0.113.1", []byte("persisted"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(ctx, "block:garbage-key", []byte("skipped"), time.Hour); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, st, ModeAuthoritative)
	sink := &fakeSink{}
	m.addSink(sink)

	// Before the seed scan even authoritative mode reads through.
	if !m.ReadThrough() {
		t.Fatal("unseeded manager claimed authority")
	}
	m.reconcileOnce(ctx)
	if m.ReadThrough() {
		t.Fatal("seeded authoritative manager still reads through")
	}
	if reason, ok := m.Lookup("203.0.113.1"); !ok || reason != "persisted" {
		t.Fatalf("persisted block not seeded: %q, %v", reason, ok)
	}
	sink.mu.Lock()
	if len(sink.reconciled) != 1 || len(sink.reconciled[0]) != 1 {
		t.Fatalf("sink reconcile sets = %v; want one set with one entry", sink.reconciled)
	}
	sink.mu.Unlock()

	// A store-side unblock converges on the next scan.
	if err := st.Delete(ctx, "block:203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	m.reconcileOnce(ctx)
	if _, ok := m.Lookup("203.0.113.1"); ok {
		t.Fatal("store-side unblock did not converge")
	}

	// A scan error keeps the last state and counts.
	m.Notify(BlockEvent{IP: addr(t, "203.0.113.2"), Reason: "kept", TTL: time.Hour})
	st.fail = true
	m.reconcileOnce(ctx)
	if _, ok := m.Lookup("203.0.113.2"); !ok {
		t.Fatal("scan failure wiped the mirror")
	}
	if m.reconcileErrs.Load() == 0 {
		t.Fatal("scan failure not counted")
	}
}

func TestManagerReconcileUsesActiveBlockIndex(t *testing.T) {
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	st := &indexedNoScanStore{Store: base}
	ctx := t.Context()
	for i := range 1000 {
		if err := st.Set(ctx, fmt.Sprintf("challenge:%04d", i), []byte("noise"), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Set(ctx, "block:203.0.113.44", []byte("indexed"), time.Hour); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, st, ModeAuthoritative)
	m.reconcileOnce(ctx)
	if got := st.scans.Load(); got != 0 {
		t.Fatalf("reconcile used generic Scan %d times", got)
	}
	if reason, ok := m.Lookup("203.0.113.44"); !ok || reason != "indexed" {
		t.Fatalf("indexed block not reconciled: %q, %v", reason, ok)
	}
}

func TestManagerDoesNotReplaceSinksFromIncompleteIndex(t *testing.T) {
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	met := guardianmetrics.New("memory")
	m := New(Config{ReconcileInterval: time.Second, MaxEntries: 1024, Mode: ModeAuthoritative},
		&partialBlockStore{Store: base}, met, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = m.Close() })
	sink := &fakeSink{}
	m.addSink(sink)
	m.reconcileOnce(t.Context())
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.reconciled) != 0 {
		t.Fatalf("incomplete snapshot replaced sink: %+v", sink.reconciled)
	}
	if !m.ReadThrough() || m.Status().Mirror.Complete {
		t.Fatal("incomplete indexed snapshot was treated as authoritative")
	}
	if got := metricCounter(t, met, "guardian_offload_reconcile_skipped_total", "reason", "incomplete_snapshot"); got != 1 {
		t.Fatalf("incomplete-snapshot skip counter = %v, want 1", got)
	}
}

func TestManagerReadThroughModeAndLearn(t *testing.T) {
	st := store.NewMemory()
	m := newTestManager(t, st, ModeReadThrough)
	m.reconcileOnce(context.Background())
	if !m.ReadThrough() {
		t.Fatal("read_through mode must keep consulting the store after seeding")
	}
	m.Learn("203.0.113.7", "threshold:pow_fail")
	if reason, ok := m.Lookup("203.0.113.7"); !ok || reason != "threshold:pow_fail" {
		t.Fatalf("learned entry = %q, %v", reason, ok)
	}
	// Provisional retention: the learned entry expires within two reconcile
	// intervals unless a scan confirms it.
	m.now = func() time.Time { return time.Now().Add(3 * m.cfg.ReconcileInterval) }
	if _, ok := m.Lookup("203.0.113.7"); ok {
		t.Fatal("provisional entry outlived its retention")
	}
}

func TestManagerForceReconcile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := store.NewMemory()
	m := New(Config{ReconcileInterval: time.Hour, MaxEntries: 64, Mode: ModeAuthoritative},
		st, nil, slog.New(slog.DiscardHandler))
	defer m.Close()
	m.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for !m.seeded.Load() {
		if time.Now().After(deadline) {
			t.Fatal("startup seed never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := st.Set(ctx, "block:203.0.113.3", []byte("forced"), time.Hour); err != nil {
		t.Fatal(err)
	}
	m.ForceReconcile()
	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, ok := m.Lookup("203.0.113.3"); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("forced reconcile never picked up the new block")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
