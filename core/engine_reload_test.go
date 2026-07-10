// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// reloadedYAML flips the pipelineYAML policy: the old denylist is gone and
// 198.51.100.0/24 (allowed before) is now denied.
const reloadedYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
  denylist:
    ips: [ "198.51.100.0/24" ]
`

// TestEngineReload: Reload atomically swaps the active config, so the same
// request flips decisions, while behavioural state in the store survives.
func TestEngineReload(t *testing.T) {
	ctx := context.Background()
	cfg := loadTestConfig(t, pipelineYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	newlyDenied := req("x.test", "198.51.100.7", "/page", "Mozilla")
	oldDenied := req("x.test", "203.0.113.9", "/page", "Mozilla")
	if d := e.Evaluate(ctx, newlyDenied); d.Action != ActionAllow {
		t.Fatalf("before reload: got %s (%s), want allow", d.Action, d.Reason)
	}
	if d := e.Evaluate(ctx, oldDenied); d.Action != ActionDeny {
		t.Fatalf("before reload: got %s (%s), want deny", d.Action, d.Reason)
	}

	// A behavioural block placed before the reload must survive it: that
	// state lives in the store, not in the config snapshot.
	if err := e.BlockIP(ctx, "192.0.2.55", "test", time.Minute); err != nil {
		t.Fatal(err)
	}

	next := loadTestConfig(t, reloadedYAML)
	if err := e.Reload(next); err != nil {
		t.Fatal(err)
	}

	if got := e.Config(); got != next {
		t.Errorf("Config() = %p, want the reloaded config %p", got, next)
	}
	if d := e.Evaluate(ctx, newlyDenied); d.Action != ActionDeny {
		t.Errorf("after reload: got %s (%s), want deny (new denylist)", d.Action, d.Reason)
	}
	if d := e.Evaluate(ctx, oldDenied); d.Action != ActionAllow {
		t.Errorf("after reload: got %s (%s), want allow (old denylist dropped)", d.Action, d.Reason)
	}
	if _, blocked, err := e.BlockStatus(ctx, "192.0.2.55"); err != nil || !blocked {
		t.Errorf("block did not survive reload: blocked=%v err=%v", blocked, err)
	}
}
