// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CookieName is the host-scoped cookie carrying the PoW token.
const CookieName = "guardian_token"

// TokenClaims are the JWT claims of a PoW token (plan §5.3). The token is
// bound to {host, client fingerprint} so it cannot be replayed cross-domain
// or from a different client.
type TokenClaims struct {
	Host        string `json:"host"`
	ChallengeID string `json:"cid"`
	Difficulty  int    `json:"dif"`
	jwt.RegisteredClaims
}

func (m *Manager) mintToken(host, fingerprint, challengeID string, difficulty int, ttl time.Duration) (string, error) {
	now := m.now()
	claims := &TokenClaims{
		Host:        strings.ToLower(host),
		ChallengeID: challengeID,
		Difficulty:  difficulty,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fingerprint,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return m.signToken(jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims))
}

// signToken serializes signing with file-based rotation and reads the current
// key while holding the same cross-process lock used by RotateKey. A peer can
// therefore never retire the key between our refresh and signature creation.
// In-memory-only managers have no shared files and sign directly.
func (m *Manager) signToken(token *jwt.Token) (string, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.keyPath == "" {
		return token.SignedString(m.signingKey())
	}

	unlock, err := lockRotation(m.keyPath + ".rotate.lock")
	if err != nil {
		return "", fmt.Errorf("lock key for signing: %w", err)
	}
	defer unlock()

	current, err := loadKey(m.keyPath)
	if err != nil {
		return "", err
	}
	m.mu.RLock()
	changed := !m.keys[0].private.Equal(current)
	m.mu.RUnlock()
	if changed {
		previous, err := loadRetiredKeysAt(m.prevDir, m.now())
		if err != nil {
			return "", err
		}
		m.setRetiredKeys(current, previous)
	}
	m.lastRefresh = m.now()
	return token.SignedString(current)
}

func (m *Manager) verificationKeys() []managerKey {
	now := m.now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]managerKey, 0, len(m.keys))
	for _, key := range m.keys {
		if key.retiredAt.IsZero() || !now.After(key.retiredAt.Add(maxAcceptedTokenLifetime)) {
			keys = append(keys, key)
		}
	}
	return keys
}

const maxAcceptedTokenLifetime = 7 * 24 * time.Hour

// VerifyToken checks signature, exp/nbf and the host + fingerprint binding.
// Results are cached briefly so repeat requests from a vouched client don't
// pay the Ed25519 verification on every request. During key rotation the
// signature is checked against the current key first, then any previous
// verification keys, so tokens minted before a rotation stay valid until
// they age out via exp (plan §7).
func (m *Manager) VerifyToken(token, host, ip, userAgent string) error {
	now := m.now()
	cacheKey := sha256.Sum256([]byte(token + "\x00" + strings.ToLower(host) + "\x00" + ip + "\x00" + userAgent))
	if m.cache.get(cacheKey, now) {
		return nil
	}
	claims, err := m.verifyTokenOnce(token, host, ip, userAgent)
	if err != nil {
		if refreshed, _ := m.refreshKeys(true); refreshed {
			claims, err = m.verifyTokenOnce(token, host, ip, userAgent)
		}
	}
	if err != nil {
		return err
	}
	m.cache.put(cacheKey, claims.ExpiresAt.Time, now)
	return nil
}

func (m *Manager) verifyTokenOnce(token, host, ip, userAgent string) (*TokenClaims, error) {
	var errs []error
	for _, key := range m.verificationKeys() {
		claims := &TokenClaims{}
		_, err := jwt.ParseWithClaims(token, claims,
			func(*jwt.Token) (any, error) { return key.private.Public().(ed25519.PublicKey), nil },
			jwt.WithValidMethods([]string{"EdDSA"}),
			jwt.WithExpirationRequired(),
			jwt.WithTimeFunc(m.now),
		)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if claims.IssuedAt == nil || claims.ExpiresAt == nil {
			return nil, errors.New("token requires issued-at and expiration claims")
		}
		if !claims.ExpiresAt.Time.After(claims.IssuedAt.Time) ||
			claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) > maxAcceptedTokenLifetime {
			return nil, fmt.Errorf("token lifetime exceeds %v", maxAcceptedTokenLifetime)
		}
		if !key.retiredAt.IsZero() {
			if claims.IssuedAt.Time.After(key.retiredAt) {
				return nil, errors.New("token was issued after its signing key was retired")
			}
			if claims.ExpiresAt.Time.After(key.retiredAt.Add(maxAcceptedTokenLifetime)) {
				return nil, errors.New("token outlives the retired-key acceptance horizon")
			}
		}
		if !strings.EqualFold(claims.Host, host) {
			return nil, fmt.Errorf("token bound to host %q, presented on %q", claims.Host, host)
		}
		if claims.Subject != Fingerprint(ip, userAgent) {
			return nil, fmt.Errorf("token fingerprint mismatch")
		}
		return claims, nil
	}
	return nil, errors.Join(errs...)
}

// Fingerprint identifies a client for token binding without storing any PII:
// a truncated hash of IP and User-Agent.
func Fingerprint(ip, userAgent string) string {
	sum := sha256.Sum256([]byte(ip + "\x00" + userAgent))
	return hex.EncodeToString(sum[:16])
}
