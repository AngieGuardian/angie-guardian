// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package attackmode

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

type applyThenErrorStore struct{ store.Store }

func (s *applyThenErrorStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := s.Store.Set(ctx, key, value, ttl); err != nil {
		return err
	}
	return errors.New("ambiguous write timeout")
}

func TestSharePostureAdoptsPeerLevel(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true

	// A peer instance published "attack" under its own per-instance key.
	if err := st.Set(t.Context(), posturePrefix+"peer-abc", []byte("2"), time.Minute); err != nil {
		t.Fatal(err)
	}

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

func TestSharePostureDisabledIgnoresPeer(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = false
	if err := st.Set(t.Context(), posturePrefix+"peer-abc", []byte("2"), time.Minute); err != nil {
		t.Fatal(err)
	}
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
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	if err := st.Set(t.Context(), posturePrefix+"peer-corrupt", []byte("999"), time.Minute); err != nil {
		t.Fatal(err)
	}
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

// TestPinNormalDefeatsPeerAdoption: with sharing on and a peer reporting
// Attack, an operator's Pin(Normal) kill switch must hold, not flap back to
// Attack every tick.
func TestPinNormalDefeatsPeerAdoption(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	if err := st.Set(t.Context(), posturePrefix+"peer-abc", []byte("2"), time.Minute); err != nil {
		t.Fatal(err)
	}
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
	key := posturePrefix + d.instanceID
	if _, ok, err := st.Get(t.Context(), key); err != nil || !ok {
		t.Fatalf("setup: shared Attack vote missing: ok=%v err=%v", ok, err)
	}

	d.Pin(Normal, 0)
	if _, ok, err := st.Get(t.Context(), key); err != nil || ok {
		t.Fatalf("Pin(Normal) left own shared vote live: ok=%v err=%v", ok, err)
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
	key := posturePrefix + d.instanceID
	if _, ok, err := base.Get(t.Context(), key); err != nil || !ok {
		t.Fatalf("setup: ambiguous SET did not apply: ok=%v err=%v", ok, err)
	}

	d.Pin(Normal, 0)
	if _, ok, err := base.Get(t.Context(), key); err != nil || ok {
		t.Fatalf("pin left ambiguously-applied vote live: ok=%v err=%v", ok, err)
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
	key := posturePrefix + d.instanceID
	if _, ok, _ := st.Get(t.Context(), key); !ok {
		t.Fatal("setup: shared vote missing")
	}

	cfg.SharePosture = false
	d.SetConfig(cfg)
	if _, ok, err := st.Get(t.Context(), key); err != nil || ok {
		t.Fatalf("disabling share_posture left own vote live: ok=%v err=%v", ok, err)
	}
}

// TestAdoptedPeerLevelDoesNotDecayImmediately: a level adopted from a peer must
// honor min_dwell, not drop on the very next tick.
func TestAdoptedPeerLevelDoesNotDecayImmediately(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true
	if err := st.Set(t.Context(), posturePrefix+"peer-abc", []byte("2"), time.Hour); err != nil {
		t.Fatal(err)
	}
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
	peerKey := posturePrefix + "peer-abc"
	if err := st.Set(t.Context(), peerKey, []byte("2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)
	c.add(bucketWidth)
	d.TickForTest()
	if d.State().Level != Attack {
		t.Fatalf("setup: level = %s", d.State().Level)
	}
	if err := st.Delete(t.Context(), peerKey); err != nil {
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
	if err := st.Set(ctx, posturePrefix+"peer-abc", []byte("2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	c := &clock{}
	c.t.Store(time.Now().UnixNano())
	d := New(cfg, st, slog.New(slog.DiscardHandler))
	d.SetClockForTest(c.now)

	c.add(bucketWidth)
	d.TickForTest() // adopts Attack from the peer

	// This instance's own key must NOT exist: it only adopted, never detected.
	kvs, err := st.Scan(ctx, posturePrefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range kvs {
		if kv.Key != posturePrefix+"peer-abc" {
			t.Fatalf("adopting instance wrote its own posture vote %q=%q (write-back clobber risk)", kv.Key, kv.Value)
		}
	}
}
