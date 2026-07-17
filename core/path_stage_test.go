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
	"time"

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

func pathStageEngine(t *testing.T) (*Engine, *pow.Manager) {
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
	mgr := pow.NewManager(key, st)
	e, err := NewEngine(cfg, st, mgr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, mgr
}

// TestPathOverrideStages: the pipeline resolves the per-path config, so PoW
// can be off for one path prefix while the rest of the host, and the WAF on
// that same prefix, keep working.
func TestPathOverrideStages(t *testing.T) {
	ctx := context.Background()
	e, _ := pathStageEngine(t)
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

// TestPathTokenDifficulty: a token vouches only where its solved difficulty
// meets the resolved path's base. A cheap token cannot ride into a harder
// path; the client is re-challenged at that path's bits instead.
func TestPathTokenDifficulty(t *testing.T) {
	ctx := context.Background()
	e, mgr := pathStageEngine(t)
	ip, ua := "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64)"

	cheap := mintTestToken(t, mgr, "shop.test", ip, ua, 4)
	r := req("shop.test", ip, "/", ua)
	r.Cookie = pow.CookieName + "=" + cheap
	if d := e.Evaluate(ctx, r); d.Action != ActionAllow || d.Reason != "pow:token" {
		t.Errorf("4-bit token on 4-bit path: got %s/%s, want allow/pow:token", d.Action, d.Reason)
	}
	r = req("shop.test", ip, "/admin/panel", ua)
	r.Cookie = pow.CookieName + "=" + cheap
	if d := e.Evaluate(ctx, r); d.Action != ActionChallenge || d.Difficulty != 8 {
		t.Errorf("4-bit token on 8-bit path: got %s (dif %d), want challenge at 8 bits", d.Action, d.Difficulty)
	}

	strong := mintTestToken(t, mgr, "shop.test", ip, ua, 8)
	r = req("shop.test", ip, "/admin/panel", ua)
	r.Cookie = pow.CookieName + "=" + strong
	if d := e.Evaluate(ctx, r); d.Action != ActionAllow || d.Reason != "pow:token" {
		t.Errorf("8-bit token on 8-bit path: got %s/%s, want allow/pow:token", d.Action, d.Reason)
	}
	r = req("shop.test", ip, "/", ua)
	r.Cookie = pow.CookieName + "=" + strong
	if d := e.Evaluate(ctx, r); d.Action != ActionAllow {
		t.Errorf("8-bit token on 4-bit path: got %s/%s, want allow", d.Action, d.Reason)
	}
}

// TestPathTokenTTL: a token minted with a long token_ttl on one path does not
// survive its full lifetime on a stricter path whose token_ttl is shorter. The
// pipeline passes the resolved per-path token_ttl into verification, so the
// overlay's shorter lifetime is enforced even though the token's own exp (from
// the issuing path) is still in the future.
func TestPathTokenTTL(t *testing.T) {
	ctx := context.Background()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(stageRules), 0o600); err != nil {
		t.Fatal(err)
	}
	// "/" keeps the default long token_ttl; "/admin/" scopes it to 1s.
	yaml := `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  waf:
    keywords: { enabled: true, rules_file: %q }
domains:
  shop.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, token_ttl: 1h }
    paths:
      "/admin/":
        pow: { token_ttl: 1s }
`
	cfg := loadTestConfig(t, fmt.Sprintf(yaml, rules))
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := pow.NewManager(key, st)
	e, err := NewEngine(cfg, st, mgr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	ip, ua := "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64)"
	tok := mintTestToken(t, mgr, "shop.test", ip, ua, 4) // minted with a 1h token_ttl

	// Fresh: the token vouches on both paths.
	r := req("shop.test", ip, "/admin/panel", ua)
	r.Cookie = pow.CookieName + "=" + tok
	if d := e.Evaluate(ctx, r); d.Action != ActionAllow || d.Reason != "pow:token" {
		t.Fatalf("fresh token on /admin/: got %s/%s, want allow/pow:token", d.Action, d.Reason)
	}

	// Past the /admin/ 1s token_ttl: rejected there and re-challenged, even
	// though the token's own 1h exp has not elapsed.
	time.Sleep(1100 * time.Millisecond)
	r = req("shop.test", ip, "/admin/panel", ua)
	r.Cookie = pow.CookieName + "=" + tok
	if d := e.Evaluate(ctx, r); d.Action != ActionChallenge {
		t.Errorf("aged token on /admin/ (1s ttl): got %s/%s, want challenge", d.Action, d.Reason)
	}
	// The lax "/" path still honors the token's full 1h lifetime.
	r = req("shop.test", ip, "/", ua)
	r.Cookie = pow.CookieName + "=" + tok
	if d := e.Evaluate(ctx, r); d.Action != ActionAllow || d.Reason != "pow:token" {
		t.Errorf("aged token on / (1h ttl): got %s/%s, want allow/pow:token", d.Action, d.Reason)
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
