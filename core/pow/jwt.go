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
	"strconv"
	"strings"
	"sync"
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

// VerifyToken checks signature, exp/nbf, the host + fingerprint binding, that
// the token was solved at no less than minBits difficulty, and that it is no
// older than maxAge. The token carries the difficulty it was actually solved
// at, so a token earned on a cheap path cannot vouch for a path whose config
// demands harder work; pass 0 to accept any difficulty. maxAge caps the token
// against the target path's token_ttl: a token minted with a long lifetime on
// one path is rejected once iat+maxAge has elapsed on a path with a shorter
// token_ttl, so a full overlay's shorter lifetime is honored (the token's own
// exp remains the issuing-path upper bound); pass 0 to enforce only exp.
// Results are cached briefly so repeat requests from a vouched client don't
// pay the Ed25519 verification on every request. During key rotation the
// signature is checked against the current key first, then any previous
// verification keys, so tokens minted before a rotation stay valid until they
// age out via exp (plan §7).
func (m *Manager) VerifyToken(token, host, ip, userAgent string, minBits int, maxAge time.Duration) error {
	// Refresh before consulting the cache as well as before signature
	// verification. A cached or signature-valid token from a key this replica
	// still thinks is current must not suppress learning that a peer retired it.
	if err := m.refreshKeysBeforeTokenAccept(); err != nil {
		return fmt.Errorf("refresh token verification keys: %w", err)
	}
	now := m.now()
	cacheKey := tokenCacheKey(token, host, ip, userAgent, minBits, maxAge)
	if m.cache.get(cacheKey, now) {
		return nil
	}
	claims, err := m.verifyTokenOnce(token, host, ip, userAgent)
	if err != nil {
		refreshed, refreshErr := m.refreshKeys(true)
		if refreshErr != nil {
			return fmt.Errorf("refresh token verification keys after signature miss: %w", refreshErr)
		}
		if refreshed {
			claims, err = m.verifyTokenOnce(token, host, ip, userAgent)
		}
	}
	if err != nil {
		return err
	}
	if claims.Difficulty < minBits {
		return fmt.Errorf("token solved at %d bits, path requires %d", claims.Difficulty, minBits)
	}
	// The target path may demand a shorter lifetime than the path that issued
	// the token. Reject once iat+maxAge has elapsed even though exp is later.
	expiry := claims.ExpiresAt.Time
	if maxAge > 0 {
		if ttlExpiry := claims.IssuedAt.Time.Add(maxAge); ttlExpiry.Before(expiry) {
			expiry = ttlExpiry
		}
		if !now.Before(expiry) {
			return fmt.Errorf("token older than path token_ttl %v", maxAge)
		}
	}
	// Cache only up to the effective expiry so a later re-verification with a
	// shorter maxAge is not masked by an earlier long-lived cache entry.
	m.cache.put(cacheKey, expiry, now)
	return nil
}

// tokenKeyScratch holds reusable buffers for building the verification cache
// key. The key is a SHA-256 over the token plus its full binding, recomputed on
// every request from a vouched client — the hottest path in the product — and
// joining those parts into one string previously allocated the joined string,
// its []byte copy and the formatted max-age each time. The read path is
// GC-bound at the rates Guardian targets, so that allocation traffic cost more
// than the hashing did.
var tokenKeyScratch = sync.Pool{New: func() any { b := make([]byte, 0, 512); return &b }}

// maxTokenKeyScratch bounds what goes back into the pool. A cookie value is
// attacker-supplied and can run to the proxy's whole header budget; a buffer
// grown to hold one must not be retained for the life of the process.
const maxTokenKeyScratch = 4096

// tokenCacheKey digests the token and every input the verification result
// depends on, so a cache hit implies the exact same token, client, host,
// difficulty floor and lifetime bound already verified. The digest must stay
// cryptographic: the token is client-supplied, so a weaker hash would let a
// crafted token collide onto a genuine token's cached "valid" entry.
func tokenCacheKey(token, host, ip, userAgent string, minBits int, maxAge time.Duration) [32]byte {
	p := tokenKeyScratch.Get().(*[]byte)
	b := (*p)[:0]
	b = append(b, token...)
	b = append(b, 0)
	// ToLower returns the input unchanged (no allocation) for an already-lower
	// host, which is what Angie's $host always gives us.
	b = append(b, strings.ToLower(host)...)
	b = append(b, 0)
	b = append(b, ip...)
	b = append(b, 0)
	b = append(b, userAgent...)
	b = append(b, 0)
	b = strconv.AppendInt(b, int64(minBits), 10)
	b = append(b, 0)
	b = strconv.AppendInt(b, int64(maxAge), 10)
	sum := sha256.Sum256(b)
	if cap(b) <= maxTokenKeyScratch {
		*p = b
		tokenKeyScratch.Put(p)
	}
	return sum
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
