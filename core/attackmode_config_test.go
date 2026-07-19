// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"strings"
	"testing"
	"time"
)

func TestAttackModeDefaults(t *testing.T) {
	cfg := loadTestConfig(t, "store: { backend: memory }\nattack_mode: { enabled: true }\n")
	a := cfg.AttackMode
	if !a.Enabled {
		t.Fatal("enabled not parsed")
	}
	if a.Window.Std() != 30*time.Second || a.MinDwell.Std() != 60*time.Second {
		t.Fatalf("window/dwell defaults: %v / %v", a.Window.Std(), a.MinDwell.Std())
	}
	if !a.SharePostureEnabled() {
		t.Fatal("share_posture should default true")
	}
	if a.Signals.ChallengeRate.Count != 200 || a.Signals.AttackChallengeRate.Count != 1000 {
		t.Fatalf("signal rate defaults: %+v", a.Signals)
	}
	if a.Signals.MinSolveRatio != 0.2 || a.Signals.StoreErrorRatio != 0.05 || a.Signals.StoreSlowRatio != 0.25 {
		t.Fatalf("ratio defaults: %+v", a.Signals)
	}
	if a.ExtraBits(1) != 2 || a.ExtraBits(2) != 4 || a.ExtraBits(0) != 0 {
		t.Fatalf("extra bits: elevated=%d attack=%d normal=%d", a.ExtraBits(1), a.ExtraBits(2), a.ExtraBits(0))
	}
	if a.CapBits() != 28 {
		t.Fatalf("cap bits = %d, want 28", a.CapBits())
	}
	if !a.Effects.ForceAlwaysEnabled() || !a.Effects.StatelessEnabled() {
		t.Fatal("force_always/stateless should default true")
	}
	if a.Effects.ScoreboardFactor != 1.0 {
		t.Fatalf("scoreboard_factor default = %v", a.Effects.ScoreboardFactor)
	}
}

func TestAttackModeDisabledByDefault(t *testing.T) {
	cfg := loadTestConfig(t, "store: { backend: memory }\n")
	if cfg.AttackMode.Enabled {
		t.Fatal("attack_mode must be off when absent")
	}
	// Defaults still fill so a later admin force has sane numbers.
	if cfg.AttackMode.Window.Std() != 30*time.Second {
		t.Fatalf("window default not filled: %v", cfg.AttackMode.Window.Std())
	}
}

func TestIssuanceRateLimitDefaultAndOverride(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
signing_key_file: k
defaults:
  pow: { enabled: true, base_difficulty: 4 }
domains:
  a.test:
    pow: { issuance_rate_limit: 10/min }
    paths:
      "/api/": {}
`)
	if got := cfg.Defaults.PoW.IssuanceRateLimit; got.Count != 60 || got.Per != time.Minute {
		t.Fatalf("default issuance rate = %+v, want 60/min", got)
	}
	dc := cfg.DomainFor("a.test")
	if got := dc.PoW.IssuanceRateLimit; got.Count != 10 {
		t.Fatalf("domain override = %+v, want 10/min", got)
	}
	// The path overlay omits it, so it inherits the domain's 10/min.
	pc := dc.ForPath("/api/x")
	if got := pc.PoW.IssuanceRateLimit; got.Count != 10 {
		t.Fatalf("path inherit = %+v, want 10/min", got)
	}
}

func TestAttackModeValidation(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"window too small", "attack_mode: { window: 5s }", "window"},
		{"window too big", "attack_mode: { window: 20m }", "window"},
		{"dwell below window", "attack_mode: { window: 30s, min_dwell: 20s }", "min_dwell"},
		{"attack below elevated", "attack_mode: { signals: { challenge_rate: 100/s, attack_challenge_rate: 50/s } }", "attack_challenge_rate"},
		{"bad solve ratio", "attack_mode: { signals: { min_solve_ratio: 2 } }", "min_solve_ratio"},
		{"bad error ratio", "attack_mode: { signals: { store_error_ratio: -1 } }", "store_error_ratio"},
		{"raise too big", "attack_mode: { effects: { attack_difficulty_raise: 3 } }", "attack_difficulty_raise"},
		{"raise nan", "attack_mode: { effects: { attack_difficulty_raise: .nan } }", "attack_difficulty_raise"},
		{"raise not quarter", "attack_mode: { effects: { elevated_difficulty_raise: 0.3 } }", "multiple of 0.25"},
		{"cap out of range", "attack_mode: { effects: { difficulty_cap: 9 } }", "difficulty_cap"},
		{"cap infinite", "attack_mode: { effects: { difficulty_cap: .inf } }", "difficulty_cap"},
		{"bad scoreboard factor", "attack_mode: { effects: { scoreboard_factor: 1.5 } }", "scoreboard_factor"},
		{"scoreboard nan", "attack_mode: { effects: { scoreboard_factor: .nan } }", "scoreboard_factor"},
		{"negative inflight", "attack_mode: { effects: { max_inflight: -1 } }", "max_inflight"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfigErr(t, "store: { backend: memory }\n"+tc.yaml+"\n")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestAttackModePartialSignalsBlockDisablesOmitted: SIGNALS use omit-to-disable
// within a partial block (a rate cannot be written "0/s"), while EFFECTS use
// pointer presence (an omitted raise defaults, an explicit 0 disables). This
// pins both semantics.
func TestAttackModePartialSignalsBlockDisablesOmitted(t *testing.T) {
	cfg := loadTestConfig(t, `
store: { backend: memory }
attack_mode:
  enabled: true
  signals: { attack_challenge_rate: 500/s, store_error_ratio: 0.1 }
  effects: { attack_difficulty_raise: 1.0 }
`)
	s := cfg.AttackMode.Signals
	if s.ChallengeRate.Count != 0 {
		t.Fatalf("omitted challenge_rate was defaulted to %+v (partial signals block should leave it disabled)", s.ChallengeRate)
	}
	if s.AttackChallengeRate.Count != 500 {
		t.Fatalf("attack_challenge_rate = %+v, want 500/s", s.AttackChallengeRate)
	}
	if s.StoreSlowRatio != 0 {
		t.Fatalf("omitted store_slow_ratio should stay disabled (0), got %v", s.StoreSlowRatio)
	}
	// Effects: an OMITTED raise defaults (pointer nil), unlike signals.
	if cfg.AttackMode.ExtraBits(1) != 2 {
		t.Fatalf("omitted elevated raise = %d, want default 2 (effects omit -> default)", cfg.AttackMode.ExtraBits(1))
	}
	if cfg.AttackMode.ExtraBits(2) != 4 {
		t.Fatalf("attack_difficulty_raise 1.0 = %d bits, want 4", cfg.AttackMode.ExtraBits(2))
	}
	// Whole-block-absent still gets full defaults.
	full := loadTestConfig(t, "store: { backend: memory }\nattack_mode: { enabled: true }\n")
	if full.AttackMode.Signals.ChallengeRate.Count != 200 || full.AttackMode.ExtraBits(1) != 2 {
		t.Fatalf("absent block did not get defaults: %+v", full.AttackMode)
	}
}

// TestAttackEffectsExplicitZeroRaise: an explicit 0 raise is honoured even as
// the ONLY field in the effects block (the pointer distinguishes it from an
// omitted field, so it is not defaulted to 0.5/1.0).
func TestAttackEffectsExplicitZeroRaise(t *testing.T) {
	// attack_difficulty_raise: 0 alone must stay 0, not become 1.0.
	cfg := loadTestConfig(t, `
store: { backend: memory }
attack_mode: { enabled: true, effects: { attack_difficulty_raise: 0.0 } }
`)
	if cfg.AttackMode.ExtraBits(2) != 0 {
		t.Fatalf("explicit attack_difficulty_raise 0 was defaulted: attack bits = %d, want 0", cfg.AttackMode.ExtraBits(2))
	}
	// The omitted elevated raise in the same block still defaults, since it is
	// a distinct field (pointer nil vs set).
	if cfg.AttackMode.ExtraBits(1) != 2 {
		t.Fatalf("omitted elevated raise = %d, want its default 2 bits", cfg.AttackMode.ExtraBits(1))
	}
	// difficulty_cap omitted -> default 7.0 (28 bits).
	if cfg.AttackMode.CapBits() != 28 {
		t.Fatalf("cap = %d, want default 28 bits", cfg.AttackMode.CapBits())
	}
	// elevated_difficulty_raise: 0 alone must stay 0.
	cfg2 := loadTestConfig(t, `
store: { backend: memory }
attack_mode: { enabled: true, effects: { elevated_difficulty_raise: 0.0 } }
`)
	if cfg2.AttackMode.ExtraBits(1) != 0 {
		t.Fatalf("explicit elevated_difficulty_raise 0 was defaulted: elevated bits = %d, want 0", cfg2.AttackMode.ExtraBits(1))
	}
	if cfg2.AttackMode.ExtraBits(2) != 4 {
		t.Fatalf("omitted attack raise = %d, want its default 4 bits", cfg2.AttackMode.ExtraBits(2))
	}
}

// TestAttackDifficultyCapVsBase: a difficulty_cap below a PoW-enabled domain's
// base_difficulty is refused, because the fleet raise would otherwise clamp
// new challenges under the base the token stage verifies against.
func TestAttackDifficultyCapVsBase(t *testing.T) {
	yaml := `
store: { backend: memory }
signing_key_file: k
attack_mode: { enabled: true, effects: { difficulty_cap: 6.0 } }
defaults:
  pow: { enabled: true, base_difficulty: 7, max_difficulty: 7 }
domains:
  a.test: {}
`
	_, err := loadConfigErr(t, yaml)
	if err == nil || !strings.Contains(err.Error(), "difficulty_cap") {
		t.Fatalf("err = %v, want a difficulty_cap-below-base error", err)
	}

	// A per-path base above the cap is also caught.
	yaml2 := `
store: { backend: memory }
signing_key_file: k
attack_mode: { enabled: true, effects: { difficulty_cap: 6.0 } }
defaults:
  pow: { enabled: true, base_difficulty: 5, max_difficulty: 6 }
domains:
  a.test:
    paths:
      "/hard": { pow: { base_difficulty: 7, max_difficulty: 7 } }
`
	if _, err := loadConfigErr(t, yaml2); err == nil || !strings.Contains(err.Error(), "difficulty_cap") {
		t.Fatalf("path base above cap: err = %v, want a difficulty_cap error", err)
	}

	// A cap at or above every base is fine.
	ok := `
store: { backend: memory }
signing_key_file: k
attack_mode: { enabled: true, effects: { difficulty_cap: 7.0 } }
defaults:
  pow: { enabled: true, base_difficulty: 7, max_difficulty: 7 }
domains:
  a.test: {}
`
	if _, err := loadConfigErr(t, ok); err != nil {
		t.Fatalf("cap == base should be valid, got %v", err)
	}
}
