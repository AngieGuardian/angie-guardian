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

	"github.com/melroy89/angie-guardian/core/intel/inteltest"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// intelEngine builds an engine with real mmdb fixtures and a local deny feed:
//   - 198.51.100.0/24 -> NL, AS64500 (the "home" network)
//   - 203.0.113.0/24  -> RU (deny-listed country)
//   - 192.0.2.0/24    -> CN (challenge-listed country)
//   - 100.64.7.0/24   -> deny reputation feed
//   - 100.64.8.0/24   -> challenge reputation feed
func intelEngine(t *testing.T) (*Engine, *pow.Manager) {
	t.Helper()
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{
		"198.51.100.0/24": "NL",
		"203.0.113.0/24":  "RU",
		"192.0.2.0/24":    "CN",
	})
	asnDB := inteltest.WriteASNDB(t, dir, map[string]uint32{
		"198.51.100.0/24": 64500,
		"100.64.9.0/24":   64666,
	})
	denyFeed := filepath.Join(dir, "deny.list")
	if err := os.WriteFile(denyFeed, []byte("100.64.7.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chalFeed := filepath.Join(dir, "challenge.list")
	if err := os.WriteFile(chalFeed, []byte("100.64.8.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := loadTestConfig(t, fmt.Sprintf(`
store: { backend: memory }
signing_key_file: test-signing.key
geoip:
  location_db: %s
  asn_db: %s
reputation:
  feeds:
    - { name: bad-actors, file: %s, action: deny }
    - { name: gray-actors, file: %s, action: challenge }
defaults:
  geo:
    enabled: true
    deny: { countries: [ RU ] }
    challenge: { countries: [ CN ], asns: [ 64666 ] }
  reputation:
    enabled: true
  pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
domains:
  nopow.test:
    pow: { enabled: false }
  nointel.test:
    geo: { enabled: false }
    reputation: { enabled: false }
`, countryDB, asnDB, denyFeed, chalFeed))

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

func TestIntelStages(t *testing.T) {
	ctx := context.Background()
	e, mgr := intelEngine(t)
	ua := "Mozilla/5.0 (X11; Linux x86_64)"

	cases := []struct {
		name       string
		req        *RequestContext
		action     Action
		reason     string
		difficulty int
	}{
		// Difficulty expectations are in leading-zero bits: base_difficulty 1
		// = 4 bits; a reputation challenge adds one full step (+4 bits).
		{"home country browses (pow challenge, not geo)",
			req("x.test", "198.51.100.7", "/", ua), ActionChallenge, "pow:no_token", 4},
		{"deny-listed country",
			req("x.test", "203.0.113.5", "/", ua), ActionDeny, "geo:country:RU", 0},
		{"challenge-listed country",
			req("x.test", "192.0.2.5", "/", ua), ActionChallenge, "geo:country:CN", 4},
		{"challenge-listed asn",
			req("x.test", "100.64.9.1", "/", ua), ActionChallenge, "geo:asn:64666", 4},
		{"deny feed hit",
			req("x.test", "100.64.7.1", "/", ua), ActionDeny, "reputation:bad-actors", 0},
		{"challenge feed hit pays extra",
			req("x.test", "100.64.8.1", "/", ua), ActionChallenge, "reputation:gray-actors", 8},
		// Deny applies even where PoW is off; challenge policies go inert
		// there rather than cutting the origin off.
		{"deny feed on pow-less domain",
			req("nopow.test", "100.64.7.1", "/", ua), ActionDeny, "reputation:bad-actors", 0},
		{"geo deny on pow-less domain",
			req("nopow.test", "203.0.113.5", "/", ua), ActionDeny, "geo:country:RU", 0},
		{"challenge country on pow-less domain passes",
			req("nopow.test", "192.0.2.5", "/", ua), ActionAllow, "default", 0},
		// Per-domain opt-out.
		{"intel disabled domain ignores deny feed and geo",
			req("nointel.test", "100.64.7.1", "/", ua), ActionChallenge, "pow:no_token", 4},
		// Deny-listed geo also applies to non-browser clients.
		{"geo deny hits curl too",
			req("x.test", "203.0.113.5", "/", "curl/8.0"), ActionDeny, "geo:country:RU", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
			if tc.difficulty > 0 && d.Difficulty != tc.difficulty {
				t.Errorf("difficulty = %d, want %d", d.Difficulty, tc.difficulty)
			}
		})
	}

	// A client from a challenge-listed country solves once and then browses
	// on its token: the geo challenge must sit AFTER the token stage.
	ip := "192.0.2.99"
	token := mintTestToken(t, mgr, "x.test", ip, ua, 4)
	d := e.Evaluate(ctx, &RequestContext{
		Host: "x.test", Method: "GET", URI: "/page", RemoteAddr: ip,
		UserAgent: ua, Cookie: pow.CookieName + "=" + token,
	})
	if d.Action != ActionAllow || d.Reason != "pow:token" {
		t.Fatalf("vouched client from challenged country: got %s/%s, want allow/pow:token", d.Action, d.Reason)
	}

	// But a token must NOT carry a client past a geo/reputation deny.
	ip = "203.0.113.42"
	token = mintTestToken(t, mgr, "x.test", ip, ua, 4)
	d = e.Evaluate(ctx, &RequestContext{
		Host: "x.test", Method: "GET", URI: "/page", RemoteAddr: ip,
		UserAgent: ua, Cookie: pow.CookieName + "=" + token,
	})
	if d.Action != ActionDeny || d.Reason != "geo:country:RU" {
		t.Fatalf("token must not bypass geo deny: got %s/%s", d.Action, d.Reason)
	}
}

// TestIntelUnconfigured pins the nil-provider path: engines without geoip or
// feeds behave exactly as before.
func TestIntelUnconfigured(t *testing.T) {
	e := testEngine(t)
	if e.Intel() != nil {
		t.Fatal("engine without intel config should have a nil provider")
	}
	d := e.Evaluate(context.Background(), req("x.test", "198.51.100.7", "/page", "curl"))
	if d.Action != ActionAllow {
		t.Fatalf("got %s, want allow", d.Action)
	}
}
