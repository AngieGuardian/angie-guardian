// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdminTokenPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "admin.token")

	tok1, err := LoadOrCreateAdminToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok1) < 32 {
		t.Fatalf("generated token too short: %q", tok1)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}

	// Loading again must return the same token, never regenerate: a rotating
	// token would silently log the operator's dashboard/scripts out.
	tok2, err := LoadOrCreateAdminToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != tok2 {
		t.Fatalf("token regenerated on reload: %q vs %q", tok1, tok2)
	}
}

func TestAdminTokenRespectsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte("  operator-chosen-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := LoadOrCreateAdminToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "operator-chosen-token" {
		t.Fatalf("token = %q, want trimmed file content", tok)
	}
}

func TestAdminTokenEmptyFileRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateAdminToken(path); err == nil {
		t.Fatal("empty token file should be an error, not an empty bearer token")
	}
}
