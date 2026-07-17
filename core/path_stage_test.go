// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const pathStageYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  waf:
    keywords: { enabled: true, rules_file: %q }
domains:
  shop.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
    paths:
      "/api/":
        pow: { enabled: false }
      "/admin/":
        pow: { base_difficulty: 2 }
`

func pathStageEngine(t *testing.T) *Engine {
	t.Helper()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(stageRules), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, fmt.Sprintf(pathStageYAML, rules))
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

// TestPathOverrideStages: the pipeline resolves the per-path config, so PoW
// can be off for one path prefix while the rest of the host, and the WAF on
// that same prefix, keep working.
func TestPathOverrideStages(t *testing.T) {
	ctx := context.Background()
	e := pathStageEngine(t)
	ua := "Mozilla/5.0 (X11; Linux x86_64)"

	cases := []struct {
		name       string
		req        *RequestContext
		action     Action
		reason     string
		difficulty int
	}{
		{"root path is challenged at the domain difficulty",
			req("shop.test", "198.51.100.1", "/", ua), ActionChallenge, "pow:no_token", 4},
		{"pow-disabled path passes through",
			req("shop.test", "198.51.100.1", "/api/v1/items", ua), ActionAllow, "default", 0},
		{"encoded path cannot dodge the override",
			req("shop.test", "198.51.100.1", "/api%2Fv1%2Fitems", ua), ActionAllow, "default", 0},
		{"prefix must match a whole segment start",
			req("shop.test", "198.51.100.2", "/apix", ua), ActionChallenge, "pow:no_token", 4},
		{"harder path is challenged at its own difficulty",
			req("shop.test", "198.51.100.3", "/admin/panel", ua), ActionChallenge, "pow:no_token", 8},
		{"WAF deny still fires on the pow-disabled path",
			req("shop.test", "198.51.100.4", "/api/backup/.env", "curl"), ActionDeny, "waf:dotfile", 0},
		{"WAF challenge action degrades to deny where pow is path-disabled",
			req("shop.test", "198.51.100.5", "/api/union all select", "curl"), ActionDeny, "waf:sqli", 0},
		{"WAF challenge action still challenges where pow is on",
			req("shop.test", "198.51.100.6", "/union all select", "curl"), ActionChallenge, "waf:sqli", 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
			if tc.difficulty > 0 && d.Difficulty != tc.difficulty {
				t.Errorf("difficulty = %d bits, want %d", d.Difficulty, tc.difficulty)
			}
		})
	}
}

// TestPathOverrideReload: adding a path override via Reload takes effect on
// the next Evaluate without a restart.
func TestPathOverrideReload(t *testing.T) {
	ctx := context.Background()
	cfg := loadTestConfig(t, `
store: { backend: memory }
signing_key_file: test-signing.key
domains:
  shop.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
`)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	apiReq := req("shop.test", "198.51.100.9", "/api/v1/items", "Mozilla/5.0")
	if d := e.Evaluate(ctx, apiReq); d.Action != ActionChallenge {
		t.Fatalf("before reload: got %s (%s), want challenge", d.Action, d.Reason)
	}

	next := loadTestConfig(t, `
store: { backend: memory }
signing_key_file: test-signing.key
domains:
  shop.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
    paths:
      "/api/":
        pow: { enabled: false }
`)
	if err := e.Reload(next); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, apiReq); d.Action != ActionAllow {
		t.Errorf("after reload: got %s (%s), want allow via the new /api/ override", d.Action, d.Reason)
	}
	if d := e.Evaluate(ctx, req("shop.test", "198.51.100.9", "/", "Mozilla/5.0")); d.Action != ActionChallenge {
		t.Errorf("after reload: root path got %s (%s), want challenge", d.Action, d.Reason)
	}
}
