// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package attackmode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

type applyThenErrorStore struct{ store.Store }

func (s *applyThenErrorStore) SetPostureVote(ctx context.Context, id string, level int, ttl time.Duration) error {
	if err := s.Store.(store.PostureVotes).SetPostureVote(ctx, id, level, ttl); err != nil {
		return err
	}
	return errors.New("ambiguous write timeout")
}
func (s *applyThenErrorStore) DeletePostureVote(ctx context.Context, id string) error {
	return s.Store.(store.PostureVotes).DeletePostureVote(ctx, id)
}
func (s *applyThenErrorStore) MaxPostureVote(ctx context.Context, exclude string) (int, error) {
	return s.Store.(store.PostureVotes).MaxPostureVote(ctx, exclude)
}

type invalidVoteStore struct{ store.Store }

func (s *invalidVoteStore) SetPostureVote(context.Context, string, int, time.Duration) error {
	return nil
}
func (s *invalidVoteStore) DeletePostureVote(context.Context, string) error     { return nil }
func (s *invalidVoteStore) MaxPostureVote(context.Context, string) (int, error) { return 999, nil }

type unsupportedVoteStore struct{ store.Store }

func (s *unsupportedVoteStore) SetPostureVote(context.Context, string, int, time.Duration) error {
	return store.ErrCapabilityUnsupported
}
func (s *unsupportedVoteStore) DeletePostureVote(context.Context, string) error {
	return store.ErrCapabilityUnsupported
}
func (s *unsupportedVoteStore) MaxPostureVote(context.Context, string) (int, error) {
	return 0, store.ErrCapabilityUnsupported
}

type postureNoScanStore struct {
	store.Store
	scans atomic.Int64
}

func (s *postureNoScanStore) Scan(context.Context, string) ([]store.KV, error) {
	s.scans.Add(1)
	return nil, errors.New("generic Scan must not be used")
}
func (s *postureNoScanStore) SetPostureVote(ctx context.Context, id string, level int, ttl time.Duration) error {
	return s.Store.(store.PostureVotes).SetPostureVote(ctx, id, level, ttl)
}
func (s *postureNoScanStore) DeletePostureVote(ctx context.Context, id string) error {
	return s.Store.(store.PostureVotes).DeletePostureVote(ctx, id)
}
func (s *postureNoScanStore) MaxPostureVote(ctx context.Context, exclude string) (int, error) {
	return s.Store.(store.PostureVotes).MaxPostureVote(ctx, exclude)
}

func setPeerVote(t *testing.T, st store.Store, id string, level int, ttl time.Duration) {
	t.Helper()
	if err := st.(store.PostureVotes).SetPostureVote(t.Context(), id, level, ttl); err != nil {
		t.Fatal(err)
	}
}

func maxVote(t *testing.T, st store.Store) int {
	t.Helper()
	level, err := st.(store.PostureVotes).MaxPostureVote(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	return level
}

func TestSharePostureAdoptsPeerLevel(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true

	// A peer instance published "attack" under its own per-instance key.
	setPeerVote(t, st, "peer-abc", 2, time.Minute)

	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	// This instance sees no local traffic, but must adopt the peer's attack
	// posture on the next tick.
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Attack || d.State().Reason != "peer" {
		t.Fatalf("did not adopt peer level: %s / %q", d.State().Level, d.State().Reason)
	}
}

func TestSharePostureNeverScansGeneralKeyspace(t *testing.T) {
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	st := &postureNoScanStore{Store: base}
	for i := range 1000 {
		if err := st.Set(t.Context(), fmt.Sprintf("challenge:%04d", i), []byte("noise"), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	setPeerVote(t, st, "peer", 2, time.Hour)
	cfg := testConfig()
	cfg.SharePosture = true
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Attack {
		t.Fatalf("did not adopt indexed peer vote: %s", d.State().Level)
	}
	if got := st.scans.Load(); got != 0 {
		t.Fatalf("posture tick used generic Scan %d times", got)
	}
}

func TestSharePostureDisabledIgnoresPeer(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = false
	setPeerVote(t, st, "peer-abc", 2, time.Minute)
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Normal {
		t.Fatalf("share_posture off but adopted peer: %s", d.State().Level)
	}
}

func TestSharePostureIgnoresOutOfRangePeerLevel(t *testing.T) {
	base := store.NewMemory()
	st := &invalidVoteStore{Store: base}
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Normal {
		t.Fatalf("adopted invalid peer posture: %s", d.State().Level)
	}
}

func TestSharePostureWarnsOnceWhenCapabilityUnsupported(t *testing.T) {
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	st := &unsupportedVoteStore{Store: base}
	cfg := testConfig()
	cfg.SharePosture = true
	var logs bytes.Buffer
	d := New(cfg, st, slog.New(slog.NewTextHandler(&logs, nil)))

	d.TickForTest()
	d.TickForTest()
	const message = "store does not support fleet posture votes"
	if got := strings.Count(logs.String(), message); got != 1 {
		t.Fatalf("unsupported-capability warnings = %d, want 1; logs=%q", got, logs.String())
	}
	if d.State().Level != Normal {
		t.Fatalf("unsupported posture sharing changed local level: %s", d.State().Level)
	}
}

// TestPinNormalDefeatsPeerAdoption: with sharing on and a peer reporting
// Attack, an operator's Pin(Normal) kill switch must hold, not flap back to
// Attack every tick.
func TestPinNormalDefeatsPeerAdoption(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	setPeerVote(t, st, "peer-abc", 2, time.Minute)
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	d.Pin(Normal, 0) // kill switch
	for range 5 {
		c.add(bucketWidth)
		d.TickForTest()
		if d.State().Level != Normal {
			t.Fatalf("Pin(Normal) kill switch defeated by peer adoption: level = %s", d.State().Level)
		}
	}
}

// TestPinClearsOwnSharedVote covers the source-replica side of the kill
// switch. Once this instance has published Attack, pinning it must delete that
// vote immediately; otherwise quiet peers keep adopting the stale Attack value
// until its window TTL expires.
func TestPinClearsOwnSharedVote(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	// First tick detects Attack; the next publishes the already-detected local
	// level under this instance's key.
	issueAndTick(d, c, 6000, 0)
	issueAndTick(d, c, 6000, 0)
	if got := maxVote(t, st); got != int(Attack) {
		t.Fatalf("setup: shared Attack vote = %d, want %d", got, Attack)
	}

	d.Pin(Normal, 0)
	if got := maxVote(t, st); got != 0 {
		t.Fatalf("Pin(Normal) left own shared vote live: level=%d", got)
	}
}

func TestPinClearsVoteAfterAmbiguousSetError(t *testing.T) {
	base := store.NewMemory()
	t.Cleanup(func() { base.Close() })
	st := &applyThenErrorStore{Store: base}
	cfg := testConfig()
	cfg.SharePosture = true
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	issueAndTick(d, c, 6000, 0)
	issueAndTick(d, c, 6000, 0)
	if got := maxVote(t, base); got != int(Attack) {
		t.Fatalf("setup: ambiguous SET did not apply: level=%d", got)
	}

	d.Pin(Normal, 0)
	if got := maxVote(t, base); got != 0 {
		t.Fatalf("pin left ambiguously-applied vote live: level=%d", got)
	}
}

func TestDisablingSharingClearsOwnVote(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)
	issueAndTick(d, c, 6000, 0)
	issueAndTick(d, c, 6000, 0)
	if got := maxVote(t, st); got != int(Attack) {
		t.Fatal("setup: shared vote missing")
	}

	cfg.SharePosture = false
	d.SetConfig(cfg)
	if got := maxVote(t, st); got != 0 {
		t.Fatalf("disabling share_posture left own vote live: level=%d", got)
	}
}

// TestAdoptedPeerLevelDoesNotDecayImmediately: a level adopted from a peer must
// honor min_dwell, not drop on the very next tick.
func TestAdoptedPeerLevelDoesNotDecayImmediately(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	setPeerVote(t, st, "peer-abc", 2, time.Hour)
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Attack {
		t.Fatalf("setup: level = %s", d.State().Level)
	}
	// Next tick, still no local signals: the adopted level must hold (peer key
	// still says Attack, and dwell has not elapsed).
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Attack {
		t.Fatalf("adopted level decayed immediately: level = %s", d.State().Level)
	}
}

func TestAdoptedPeerLevelDwellsAndDecaysOneStepAfterVoteDisappears(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	setPeerVote(t, st, "peer-abc", 2, time.Hour)
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Attack {
		t.Fatalf("setup: level = %s", d.State().Level)
	}
	if err := st.DeletePostureVote(t.Context(), "peer-abc"); err != nil {
		t.Fatal(err)
	}

	// The adopted level must not vanish as soon as the peer key does.
	for elapsed := bucketWidth; elapsed < cfg.MinDwell; elapsed += bucketWidth {
		c.add(bucketWidth)
		d.TickForTest()
		if d.State().Level != Attack {
			t.Fatalf("adopted Attack decayed before min_dwell at %v: %s", elapsed, d.State().Level)
		}
	}
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Elevated {
		t.Fatalf("adopted Attack did not decay exactly one step: %s", d.State().Level)
	}
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Elevated {
		t.Fatalf("intermediate Elevated posture skipped its own dwell: %s", d.State().Level)
	}
}

// TestDecayedReplicaDoesNotClobberPeer: an instance that only ADOPTED a peer's
// attack level must not write it back, so when the peer clears, this instance
// does not keep voting Attack.
func TestDecayedReplicaDoesNotWriteBack(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	ctx := t.Context()
	setPeerVote(t, st, "peer-abc", 2, time.Hour)
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	c.add(bucketWidth)
	d.TickForTest() // adopts Attack from the peer

	// Excluding the peer leaves no vote: this instance only adopted, never
	// detected, and therefore must not write the posture back.
	if got, err := st.MaxPostureVote(ctx, "peer-abc"); err != nil || got != 0 {
		t.Fatalf("adopting instance wrote its own posture vote: level=%d err=%v", got, err)
	}
}
