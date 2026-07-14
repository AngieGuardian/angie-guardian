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

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

const anomalyYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: false }
domains:
  anom.test:
    pow: { enabled: true, mode: suspicion, base_difficulty: 2, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: %q, challenge_at: 0.4, deny_at: 0.8 }
  always.test:
    pow: { enabled: true, mode: always, base_difficulty: 2, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: %q, challenge_at: 0.4, deny_at: 0.8 }
`

const commonUA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"

func anomalyEngine(t *testing.T) *Engine {
	t.Helper()
	// Train a baseline of shallow blog traffic under two hosts.
	tr := &anomaly.Trainer{}
	for _, host := range []string{"anom.test", "always.test"} {
		for i := 0; i < 2000; i++ {
			tr.Add(&anomaly.LogRecord{
				Host: host, URI: fmt.Sprintf("/blog/post-%d", i%40),
				UserAgent: commonUA, Status: 200,
			})
		}
	}
	model := filepath.Join(t.TempDir(), "model.json")
	if err := tr.Finish(100).Save(model); err != nil {
		t.Fatal(err)
	}

	cfg := loadTestConfig(t, fmt.Sprintf(anomalyYAML, model, model))
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

const scannerPath = "/cgi-bin/luci/;stok=/x?exec=1&payload=qQfk3zqzn0KpcnNIqIz6O0aXBs1x9kzq&a=1&b=2&c=3&d=4"

func TestAnomalyStage(t *testing.T) {
	ctx := context.Background()
	e := anomalyEngine(t)

	// Suspicion mode: an ordinary-looking new browser browses freely.
	d := e.Evaluate(ctx, req("anom.test", "198.51.100.40", "/blog/post-7", commonUA))
	if d.Action != ActionAllow || d.Reason != "default" {
		t.Fatalf("normal request in suspicion mode: got %s/%s, want allow/default", d.Action, d.Reason)
	}

	// Mode always still challenges ordinary unvouched requests.
	d = e.Evaluate(ctx, req("always.test", "198.51.100.41", "/blog/post-7", commonUA))
	if d.Action != ActionChallenge || d.Reason != "pow:no_token" {
		t.Fatalf("normal request in always mode: got %s/%s, want challenge/pow:no_token", d.Action, d.Reason)
	}

	// A moderately weird request (scanner path, common UA) gets challenged
	// with escalated difficulty.
	d = e.Evaluate(ctx, req("anom.test", "198.51.100.42", scannerPath, commonUA))
	if d.Action != ActionChallenge || d.Reason != "anomaly:challenge" {
		t.Fatalf("weird path: got %s/%s, want challenge/anomaly:challenge", d.Action, d.Reason)
	}
	for _, host := range []string{"ANOM.test:443", "anom.test."} {
		d = e.Evaluate(ctx, req(host, "198.51.100.44", scannerPath, commonUA))
		if d.Action != ActionChallenge || d.Reason != "anomaly:challenge" {
			t.Errorf("equivalent host %q: got %s/%s, want challenge/anomaly:challenge", host, d.Action, d.Reason)
		}
	}
	if d.Difficulty <= 8 || d.Difficulty > 24 {
		t.Fatalf("escalated difficulty = %d bits, want in (8..24]", d.Difficulty)
	}

	// Fully anomalous (scanner path + rare UA) crosses deny_at.
	d = e.Evaluate(ctx, req("anom.test", "198.51.100.43", scannerPath, "zgrab/0.x"))
	if d.Action != ActionDeny || d.Reason != "anomaly:deny" {
		t.Fatalf("fully anomalous: got %s/%s, want deny/anomaly:deny", d.Action, d.Reason)
	}
}

func TestScaleDifficulty(t *testing.T) {
	// Bits scale: base_difficulty 2 = 8 bits, max_difficulty 6 = 24 bits.
	for _, tc := range []struct {
		score float64
		want  int
	}{
		{0.40, 8},  // at the challenge threshold: base
		{0.70, 16}, // halfway: middle
		{1.00, 24}, // maximal: max
		{0.97, 23},
	} {
		if got := scaleDifficulty(8, 24, tc.score, 0.4); got != tc.want {
			t.Errorf("scaleDifficulty(score=%.2f) = %d, want %d", tc.score, got, tc.want)
		}
	}
	// Degenerate config: challenge_at = 1 falls back to base.
	if got := scaleDifficulty(8, 24, 1.0, 1.0); got != 8 {
		t.Errorf("challengeAt=1: got %d, want base", got)
	}
}

func TestSuspicionModeRequiresAnomaly(t *testing.T) {
	yaml := `
store: { backend: memory }
domains:
  broken.test:
    pow: { enabled: true, mode: suspicion }
`
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("suspicion mode without anomaly must fail validation")
	}
}
