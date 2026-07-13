// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pow implements the proof-of-work challenge layer: Ed25519-signed
// JWT tokens, SHA-256 leading-zeros challenges, and replay-safe redemption.
// The signing key is persistent (restarts don't invalidate cookies, replicas
// can share it) and challenges are marked spent atomically from day one.
package pow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadOrCreateKey returns the Ed25519 signing key stored at path, generating
// and persisting one (0600) only if the file does not exist yet. It is never
// regenerated on restart — that is the whole point (plan §7).
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	key, err := loadKey(path)
	switch {
	case err == nil:
		return key, nil
	case errors.Is(err, os.ErrNotExist):
		return generateKey(path)
	default:
		return nil, err
	}
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseKey(raw, path)
}

func parseKey(raw []byte, path string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: expected a PEM \"PRIVATE KEY\" block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return key, nil
}

func generateKey(path string) (ed25519.PrivateKey, error) {
	key, buf, err := newKeyPEM()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: if two instances race on first start, exactly one wins and the
	// other loads the winner's key instead of silently overwriting it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, rerr
		}
		return parseKey(raw, path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return nil, err
	}
	return key, nil
}

func newKeyPEM() (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadPreviousKeys loads retired signing keys from a directory, for the
// verification set during rotation. Files are read in lexical order; missing
// directory is not an error (no previous keys). Only *.key files are read.
func LoadPreviousKeys(dir string) ([]ed25519.PrivateKey, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".key") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	keys := make([]ed25519.PrivateKey, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		k, err := parseKey(raw, path)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// RotateKey generates a fresh Ed25519 key, archives the current key file into
// prevDir, and atomically replaces keyPath. Rotations sharing keyPath are
// serialized across processes; archive names contain both the timestamp and
// old-key fingerprint so same-second rotations cannot overwrite each other.
func RotateKey(keyPath, prevDir string, nowUnix int64) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(prevDir) == "" {
		return nil, errors.New("previous_key_dir is required for safe key rotation")
	}
	unlock, err := lockRotation(keyPath + ".rotate.lock")
	if err != nil {
		return nil, fmt.Errorf("lock key rotation: %w", err)
	}
	defer unlock()

	current, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read current key: %w", err)
	}
	if _, err := parseKey(current, keyPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(prevDir, 0o700); err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(current)
	archive := filepath.Join(prevDir, fmt.Sprintf("%d-%x.key", nowUnix, fingerprint[:8]))
	if err := archiveKey(archive, current); err != nil {
		return nil, fmt.Errorf("archive current key: %w", err)
	}

	key, buf, err := newKeyPEM()
	if err != nil {
		return nil, err
	}
	if err := atomicReplaceKey(keyPath, buf); err != nil {
		return nil, fmt.Errorf("replace current key: %w", err)
	}
	return key, nil
}

func archiveKey(path string, contents []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if bytes.Equal(existing, contents) {
			return nil // retry after an interrupted replacement
		}
		return fmt.Errorf("archive collision at %s", path)
	}
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(contents); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(path))
}

func atomicReplaceKey(path string, contents []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".rotate-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	// Some shared/network filesystems do not implement directory fsync. The
	// files themselves were fsynced before this best-effort durability step.
	_ = d.Sync()
	return nil
}
