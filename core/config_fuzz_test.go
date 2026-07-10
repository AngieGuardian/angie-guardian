// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadConfig feeds arbitrary bytes to the full guardian.yaml loader
// (decode + finalize + per-domain merge + all the compile/validate steps).
// A malformed config must always fail with an error, never panic: guardiand
// runs `-t` on it and reloads it on SIGHUP, so a panic here would crash the
// daemon on a bad edit instead of rejecting it.
func FuzzLoadConfig(f *testing.F) {
	seeds := []string{
		"",
		"listen: 127.0.0.1:8071\n",
		"store: { backend: memory }\ndefaults:\n  pow: { enabled: true, base_difficulty: 5 }\n",
		"defaults:\n  pow: { base_difficulty: 999 }\n",              // out-of-range
		"defaults:\n  pow: { base_difficulty: 4.1 }\n",              // not a 0.25 step
		"domains:\n  a.test: {}\n  A.TEST: {}\n",                    // normalize collision
		"defaults:\n  geo: { enabled: true }\n",                     // geo without db
		"reputation:\n  feeds:\n    - name: x\n",                    // feed missing source
		"defaults:\n  allowlist: { ips: [\"not-an-ip\"] }\n",        // bad CIDR
		"defaults:\n  verified_bots:\n    bots:\n      - name: x\n", // preset-less bot
		"listen: [not, a, string]\n",
		"\x00\x00\x00",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "guardian.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Skip()
		}
		cfg, err := LoadConfig(path)
		// A config that loads must be usable: DomainFor is on the request hot
		// path and must never panic on a config the loader accepted.
		if err == nil && cfg != nil {
			_ = cfg.DomainFor("fuzz.test")
			_ = cfg.DomainLabel("fuzz.test")
		}
	})
}
