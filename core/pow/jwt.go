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
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(m.key)
}

// VerifyToken checks signature, exp/nbf and the host + fingerprint binding.
// Results are cached briefly so repeat requests from a vouched client don't
// pay the Ed25519 verification on every request.
func (m *Manager) VerifyToken(token, host, ip, userAgent string) error {
	now := m.now()
	cacheKey := sha256.Sum256([]byte(token + "\x00" + strings.ToLower(host) + "\x00" + ip + "\x00" + userAgent))
	if m.cache.get(cacheKey, now) {
		return nil
	}
	claims := &TokenClaims{}
	_, err := jwt.ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return m.key.Public().(ed25519.PublicKey), nil },
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
