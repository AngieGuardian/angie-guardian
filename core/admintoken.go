// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadOrCreateAdminToken returns the admin bearer token stored at path,
// generating and persisting a random one (0600) only if the file does not
// exist yet. Like the PoW signing key, it is never regenerated on restart, so
// a dashboard session or a scripted curl keeps working across restarts and
// the operator never has to invent a token by hand.
func LoadOrCreateAdminToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", fmt.Errorf("%s exists but is empty; delete it to generate a fresh token", path)
		}
		return token, nil
	case errors.Is(err, os.ErrNotExist):
		return generateAdminToken(path)
	default:
		return "", err
	}
}

// GenerateAdminToken returns a fresh random bearer token (not persisted).
// Used for the ephemeral token when no admin.token or token_file is set.
func GenerateAdminToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func generateAdminToken(path string) (string, error) {
	token, err := GenerateAdminToken()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// Write and sync a private temporary file first, then publish it with a
	// hard link. Link is create-if-absent and atomic: a concurrent loser can
	// only observe the winner's complete file, never an empty final path.
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".create-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", err
	}
	if _, err := f.Write([]byte(token + "\n")); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Link(tmp, path); errors.Is(err, os.ErrExist) {
		return LoadOrCreateAdminToken(path)
	} else if err != nil {
		return "", err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return token, nil
}
