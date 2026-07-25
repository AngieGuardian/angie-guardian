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
	"strconv"
	"strings"
	"time"
)

// LoadOrCreateKey returns the Ed25519 signing key stored at path, generating
// and persisting one (0600) only if the file does not exist yet. Never
// regenerate it on restart: every live PoW token is signed by it, so a fresh
// key invalidates all of them at once and re-challenges every vouched client
// the moment the daemon comes back. Rotation is the deliberate path for
// replacing it (see Rotate), because that retires the old key into prevDir
// where it still verifies until the tokens it signed expire.
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

// loadKeySetSnapshot reads the current key and retirement archive while
// holding the same cross-process lock as RotateKey. Without one snapshot lock,
// a verifier can observe the old current file after it has been archived but
// before the atomic replacement and incorrectly reinstall a retired key as
// current.
func loadKeySetSnapshot(keyPath, prevDir string, now time.Time) (ed25519.PrivateKey, []RetiredKey, error) {
	unlock, err := lockRotation(keyPath + ".rotate.lock")
	if err != nil {
		return nil, nil, fmt.Errorf("lock key snapshot: %w", err)
	}
	defer unlock()
	current, err := loadKey(keyPath)
	if err != nil {
		return nil, nil, err
	}
	previous, err := loadRetiredKeysAt(prevDir, now)
	if err != nil {
		return nil, nil, err
	}
	return current, previous, nil
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Initial creation shares the rotation lock: the winner fully writes and
	// atomically publishes the key before any concurrent starter can read it.
	unlock, err := lockRotation(path + ".rotate.lock")
	if err != nil {
		return nil, fmt.Errorf("lock key creation: %w", err)
	}
	defer unlock()
	if key, err := loadKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, buf, err := newKeyPEM()
	if err != nil {
		return nil, err
	}
	if err := atomicReplaceKey(path, buf); err != nil {
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

// RetiredKey carries an archived private key and when it stopped being the
// active signer. Verification uses that timestamp to bound the lifetime of
// tokens accepted from the key.
type RetiredKey struct {
	Key       ed25519.PrivateKey
	RetiredAt time.Time
}

// LoadRetiredKeys loads archived signing keys and their retirement metadata.
// Archive names created by RotateKey start with a Unix timestamp; legacy or
// manually named files fall back to their modification time.
func LoadRetiredKeys(dir string) ([]RetiredKey, error) {
	return loadRetiredKeysAt(dir, time.Now())
}

// loadRetiredKeysAt is the clock-injected implementation used by Manager
// refreshes and boundary tests. Archives older than the maximum accepted token
// lifetime are no longer useful for verification and are omitted. Duplicate
// archives of the same key retain the latest retirement timestamp: an archive
// written by a failed replacement attempt must not make the later successful
// retirement appear to have happened early.
func loadRetiredKeysAt(dir string, now time.Time) ([]RetiredKey, error) {
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
	keys := make([]RetiredKey, 0, len(names))
	byFingerprint := make(map[[32]byte]int, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		retiredAt := retirementTimeFromName(name)
		if retiredAt.IsZero() {
			if info, err := os.Stat(path); err == nil {
				retiredAt = info.ModTime()
			}
		}
		// Rotation archives carry a trusted retirement timestamp in their
		// filename. Check the horizon before reading/parsing the key so archive
		// retention does not make refresh crypto work grow without bound.
		if !retiredAt.IsZero() && now.After(retiredAt.Add(maxAcceptedTokenLifetime)) {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		k, err := parseKey(raw, path)
		if err != nil {
			return nil, err
		}
		fingerprint := sha256.Sum256(k.Public().(ed25519.PublicKey))
		if i, ok := byFingerprint[fingerprint]; ok {
			if retiredAt.After(keys[i].RetiredAt) {
				keys[i].RetiredAt = retiredAt
			}
			continue
		}
		byFingerprint[fingerprint] = len(keys)
		keys = append(keys, RetiredKey{Key: k, RetiredAt: retiredAt})
	}
	return keys, nil
}

func retirementTimeFromName(name string) time.Time {
	stamp, _, ok := strings.Cut(name, "-")
	if !ok {
		return time.Time{}
	}
	unix, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// LoadPreviousKeys is the compatibility view used by callers that only need
// the archived key material (for example startup logging and key-set tests).
func LoadPreviousKeys(dir string) ([]ed25519.PrivateKey, error) {
	retired, err := LoadRetiredKeys(dir)
	if err != nil {
		return nil, err
	}
	keys := make([]ed25519.PrivateKey, len(retired))
	for i := range retired {
		keys[i] = retired[i].Key
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
