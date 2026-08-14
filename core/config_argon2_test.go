// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArgon2IDConfigDefaultsAndDomainOverride(t *testing.T) {
	cfg := loadTestConfig(t, `
signing_key_file: test.key
defaults:
  pow: { enabled: true }
domains:
  memory.test:
    pow:
      algorithm: argon2id
      argon2id: { memory_kib: 8192, base_iterations: 1, max_iterations: 2, attack_iterations_cap: 3 }
`)
	if cfg.Defaults.PoW.Algorithm != PoWAlgorithmSHA256 {
		t.Fatalf("default algorithm = %q, want sha256", cfg.Defaults.PoW.Algorithm)
	}
	p := cfg.DomainFor("memory.test").PoW
	if !p.UsesArgon2ID() || p.Argon2ID.MemoryKiB != 8192 || p.TokenMinBits() != 0 {
		t.Fatalf("argon2id domain = %+v", p)
	}
	if cfg.Argon2Verifier.MaxConcurrent != 1 || cfg.Argon2Verifier.VerificationRateLimit.Count != 10 || cfg.Argon2Verifier.VerificationRateLimit.Per != time.Minute {
		t.Fatalf("verifier defaults = %+v", cfg.Argon2Verifier)
	}
	if p.NoScriptFallback {
		t.Fatal("noscript_fallback must remain off by default")
	}
	if p.NoScriptRedemptionRateLimit.Count != 6 || p.NoScriptRedemptionRateLimit.Per != time.Minute {
		t.Fatalf("no-script redemption default = %+v", p.NoScriptRedemptionRateLimit)
	}
}

func TestArgon2IDConfigRejectsUnsafeAndPathScopedWork(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"too little memory", "defaults:\n  pow:\n    algorithm: argon2id\n    argon2id: { memory_kib: 4096 }\n", "memory_kib"},
		{"too many iterations", "defaults:\n  pow:\n    algorithm: argon2id\n    argon2id: { attack_iterations_cap: 4 }\n", "attack_iterations_cap"},
		{"algorithm at path", "defaults:\n  paths:\n    /private/: { pow: { algorithm: argon2id } }\n", "domain-scoped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "guardian.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadConfig error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
