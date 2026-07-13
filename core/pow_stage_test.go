// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const powYAML = `
store: { backend: memory }
defaults:
  pow: { enabled: false }
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
`

func powEngine(t *testing.T) (*Engine, *pow.Manager) {
	t.Helper()
	cfg := loadTestConfig(t, powYAML)
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

// mintTestToken runs the real issue→solve→redeem flow at 4 bits difficulty.
func mintTestToken(t *testing.T, mgr *pow.Manager, host, ip, ua string) string {
	t.Helper()
	ctx := context.Background()
	ch, err := mgr.Issue(ctx, host, ip, "/", 4, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	var nonce string
	for n := 0; ; n++ {
		nonce = strconv.Itoa(n)
		sum := sha256.Sum256([]byte(ch.Challenge + nonce))
		if hex.EncodeToString(sum[:])[0] == '0' {
			break
		}
	}
	res, err := mgr.Redeem(ctx, &pow.RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
		Host: host, IP: ip, UserAgent: ua,
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

func TestPoWStages(t *testing.T) {
	ctx := context.Background()
	e, mgr := powEngine(t)
	ip, ua := "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64)"
	token := mintTestToken(t, mgr, "html.test", ip, ua)

	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"browser without token is challenged",
			&RequestContext{Host: "html.test", Method: "GET", URI: "/", RemoteAddr: ip, UserAgent: ua},
			ActionChallenge, "pow:no_token"},
		{"non-browser UA is challenged",
			&RequestContext{Host: "html.test", Method: "GET", URI: "/", RemoteAddr: ip, UserAgent: "curl/8.0"},
			ActionChallenge, "pow:no_token"},
		{"POST is challenged",
			&RequestContext{Host: "html.test", Method: "POST", URI: "/form", RemoteAddr: ip, UserAgent: ua},
			ActionChallenge, "pow:no_token"},
		{"valid token is allowed",
			&RequestContext{Host: "html.test", Method: "GET", URI: "/", RemoteAddr: ip, UserAgent: ua,
				Cookie: "other=1; " + pow.CookieName + "=" + token},
			ActionAllow, "pow:token"},
		{"garbage token is re-challenged",
			&RequestContext{Host: "html.test", Method: "GET", URI: "/", RemoteAddr: ip, UserAgent: ua,
				Cookie: pow.CookieName + "=garbage"},
			ActionChallenge, "pow:no_token"},
		{"token from another IP is re-challenged",
			&RequestContext{Host: "html.test", Method: "GET", URI: "/", RemoteAddr: "203.0.113.1", UserAgent: ua,
				Cookie: pow.CookieName + "=" + token},
			ActionChallenge, "pow:no_token"},
		{"pow-disabled domain never challenges",
			&RequestContext{Host: "plain.test", Method: "GET", URI: "/", RemoteAddr: ip, UserAgent: ua},
			ActionAllow, "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
			if tc.action == ActionChallenge && d.Difficulty != 4 {
				t.Errorf("difficulty = %d bits, want base_difficulty 1 = 4 bits", d.Difficulty)
			}
		})
	}
}
