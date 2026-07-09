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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	// O_EXCL: if two instances race on first start, exactly one wins and the
	// other loads the winner's token instead of silently overwriting it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateAdminToken(path)
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write([]byte(token + "\n")); err != nil {
		return "", err
	}
	return token, nil
}
