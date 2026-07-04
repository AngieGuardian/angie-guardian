// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(m.signingKey())
}

// verifyKeys returns the current + previous public keys as a
// jwt.VerificationKeySet, so the parser accepts a token signed by any of
// them — this is what makes key rotation non-disruptive.
func (m *Manager) verifyKeys() jwt.VerificationKeySet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]jwt.VerificationKey, len(m.keys))
	for i, k := range m.keys {
		keys[i] = k.Public().(ed25519.PublicKey)
	}
	return jwt.VerificationKeySet{Keys: keys}
}

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
	claims := &TokenClaims{}
	_, err := jwt.ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return m.verifyKeys(), nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil {
		return err
	}
	if !strings.EqualFold(claims.Host, host) {
		return fmt.Errorf("token bound to host %q, presented on %q", claims.Host, host)
	}
	if claims.Subject != Fingerprint(ip, userAgent) {
		return fmt.Errorf("token fingerprint mismatch")
	}
	m.cache.put(cacheKey, claims.ExpiresAt.Time, now)
	return nil
}

// Fingerprint identifies a client for token binding without storing any PII:
// a truncated hash of IP and User-Agent.
func Fingerprint(ip, userAgent string) string {
	sum := sha256.Sum256([]byte(ip + "\x00" + userAgent))
	return hex.EncodeToString(sum[:16])
}
