// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package attackmode

import (
	"log/slog"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

func TestSharePostureAdoptsPeerLevel(t *testing.T) {
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	cfg := testConfig()
	cfg.SharePosture = true

	// A peer already published "attack" into the shared store.
	if err := st.Set(t.Context(), posturePrefix, []byte("2"), time.Minute); err != nil {
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
	if err := st.Set(t.Context(), posturePrefix, []byte("2"), time.Minute); err != nil {
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
