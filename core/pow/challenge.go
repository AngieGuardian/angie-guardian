// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"sync"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// Manager issues and redeems PoW challenges. It is transport-agnostic; all
// per-domain policy (difficulty, TTLs) is passed in by the caller.
//
// The signing key can be rotated at runtime: keys is guarded by mu, holding
// the current signing key at index 0 followed by retired keys still accepted
// for verification. hmacSecret stays pinned to the key the Manager started
// with so challenges issued around a rotation remain redeemable.
type Manager struct {
	mu         sync.RWMutex
	keys       []ed25519.PrivateKey // keys[0] signs; all verify
	hmacSecret []byte
	store      store.Store
	cache      *tokenCache

	// NoJSMinDelay is the minimum wall-clock wait before a meta-refresh
	// (no-JS) redemption is accepted. Overridable for tests.
	NoJSMinDelay time.Duration

	now func() time.Time
}

func NewManager(key ed25519.PrivateKey, st store.Store) *Manager {
	return NewManagerWithKeys(key, nil, st)
}

// NewManagerWithKeys builds a Manager that signs with current and also
// verifies tokens signed by any key in previous (rotation support, plan §7).
func NewManagerWithKeys(current ed25519.PrivateKey, previous []ed25519.PrivateKey, st store.Store) *Manager {
	// The HMAC secret for challenge derivation is derived from the signing
	// key's seed, so one persistent secret file serves both purposes and all
	// instances sharing the key derive the same challenges.
	sum := sha256.Sum256(append([]byte("guardian-hmac-v1\x00"), current.Seed()...))
	return &Manager{
		keys:         append([]ed25519.PrivateKey{current}, previous...),
		hmacSecret:   sum[:],
		store:        st,
		cache:        newTokenCache(),
		NoJSMinDelay: 5 * time.Second,
		now:          time.Now,
	}
}

// SetKeys atomically replaces the key set (current at index 0). Called after
// a rotation reloads keys from disk. The token cache is cleared so a token
// signed by a now-removed key is re-verified rather than served from cache.
func (m *Manager) SetKeys(current ed25519.PrivateKey, previous []ed25519.PrivateKey) {
	m.mu.Lock()
	m.keys = append([]ed25519.PrivateKey{current}, previous...)
	m.mu.Unlock()
	m.cache.reset()
}

func (m *Manager) signingKey() ed25519.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[0]
}

// Rotate generates a new signing key, archives the current one into prevDir,
// and swaps the key set so the new key signs while the old key still
// verifies live tokens. keyPath/prevDir are the same paths guardiand loaded
// from, so a restart (or a peer instance's reload) reconstructs the same set.
func (m *Manager) Rotate(keyPath, prevDir string) error {
	newKey, err := RotateKey(keyPath, prevDir, m.now().Unix())
	if err != nil {
		return err
	}
	previous, err := LoadPreviousKeys(prevDir)
	if err != nil {
		return err
	}
	m.SetKeys(newKey, previous)
	return nil
}

// Challenge is what the interstitial page needs to render and solve.
// Difficulty is the required number of leading zero bits of
// SHA-256(challenge + nonce); each bit doubles the expected work.
type Challenge struct {
	ID         string `json:"challenge_id"`
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty_bits"`
}

// record is the stored issuance record (plan §5.1). State moves from
// "issued" to "spent" exactly once via compare-and-swap. Difficulty is in
// leading zero bits.
type record struct {
	State      string `json:"state"`
	Host       string `json:"host"`
	IP         string `json:"ip"`
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
	URI        string `json:"uri"`
	NoJS       bool   `json:"nojs"`
	IssuedAt   int64  `json:"issued_at"` // unix milliseconds
}

func challengeKey(id string) string { return "challenge:" + id }

// Issue derives a fresh challenge bound to {host, ip} and persists its
// issuance record with the given TTL. allowNoJS enables the meta-refresh
// redemption path for this specific challenge.
func (m *Manager) Issue(ctx context.Context, host, ip, uri string, difficulty int, ttl time.Duration, allowNoJS bool) (*Challenge, error) {
	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idRaw)

	// challenge = HMAC(secret, host || ip || time_bucket || id): opaque to the
	// client, deterministic for us, rotates with the hourly bucket (plan §5.1).
	bucket := m.now().Unix() / 3600
	mac := hmac.New(sha256.New, m.hmacSecret)
	fmt.Fprintf(mac, "%s\x00%s\x00%d\x00%s", strings.ToLower(host), ip, bucket, id)
	challenge := hex.EncodeToString(mac.Sum(nil))

	rec, err := json.Marshal(&record{
		State:      "issued",
		Host:       strings.ToLower(host),
		IP:         ip,
		Challenge:  challenge,
		Difficulty: difficulty,
		URI:        uri,
		NoJS:       allowNoJS,
		IssuedAt:   m.now().UnixMilli(),
	})
	if err != nil {
		return nil, err
	}
	created, err := m.store.CompareAndSwap(ctx, challengeKey(id), nil, rec, ttl)
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, errors.New("challenge id collision")
	}
	return &Challenge{ID: id, Challenge: challenge, Difficulty: difficulty}, nil
}

// RedeemRequest carries a solution (or a no-JS wait) plus the caller-supplied
// per-domain token policy.
type RedeemRequest struct {
	ChallengeID string
	Nonce       string // ignored for NoJS redemptions
	NoJS        bool
	Host        string
	IP          string
	UserAgent   string
	TokenTTL    time.Duration

	// ChallengeTTL bounds how long the spent marker must outlive redemption
	// so a solved challenge can never be replayed (plan §11).
	ChallengeTTL time.Duration
}

// RedeemResult is a minted token plus where to send the client afterwards.
type RedeemResult struct {
	Token       string
	TokenTTL    time.Duration
	RedirectURI string
}

var (
	ErrChallengeUnknown = errors.New("challenge unknown, expired or already spent")
	ErrBadSolution      = errors.New("solution does not meet the required difficulty")
	ErrBindingMismatch  = errors.New("challenge was issued to a different client")
	ErrTooFast          = errors.New("no-JS redemption attempted too quickly")
	ErrNoJSDisabled     = errors.New("no-JS redemption not allowed for this challenge")
)

// Redeem validates a challenge solution and mints a signed token. The spent
// flag is set with an atomic compare-and-swap on the exact stored bytes, so
// two concurrent redemptions of one challenge can never both mint (the
// mint-twice replay class).
func (m *Manager) Redeem(ctx context.Context, req *RedeemRequest) (*RedeemResult, error) {
	if len(req.ChallengeID) != 32 {
		return nil, ErrChallengeUnknown
	}
	raw, ok, err := m.store.Get(ctx, challengeKey(req.ChallengeID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrChallengeUnknown
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if rec.State != "issued" {
		return nil, ErrChallengeUnknown
	}
	if !strings.EqualFold(rec.Host, req.Host) || rec.IP != req.IP {
		return nil, ErrBindingMismatch
	}

	if req.NoJS {
		if !rec.NoJS {
			return nil, ErrNoJSDisabled
		}
		if m.now().Sub(time.UnixMilli(rec.IssuedAt)) < m.NoJSMinDelay {
			return nil, ErrTooFast
		}
	} else {
		sum := sha256.Sum256([]byte(rec.Challenge + req.Nonce))
		if leadingZeroBits(sum[:]) < rec.Difficulty {
			return nil, ErrBadSolution
		}
	}

	rec.State = "spent"
	spent, err := json.Marshal(&rec)
	if err != nil {
		return nil, err
	}
	swapped, err := m.store.CompareAndSwap(ctx, challengeKey(req.ChallengeID), raw, spent, req.ChallengeTTL)
	if err != nil {
		return nil, err
	}
	if !swapped {
		return nil, ErrChallengeUnknown // lost the race: someone spent it first
	}

	// The client just proved it solves what it requests: forget its
	// unsolved-issuance escalation counter (best-effort; see escalation.go).
	_ = m.store.Delete(ctx, escalationKey(rec.IP))

	token, err := m.mintToken(rec.Host, Fingerprint(req.IP, req.UserAgent), req.ChallengeID, rec.Difficulty, req.TokenTTL)
	if err != nil {
		return nil, err
	}
	return &RedeemResult{Token: token, TokenTTL: req.TokenTTL, RedirectURI: rec.URI}, nil
}

// leadingZeroBits counts the leading zero bits of a hash, the unit of
// challenge difficulty: each required bit doubles the expected solve work
// (a hex-digit step on the config scale is 4 bits = 16x).
func leadingZeroBits(sum []byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}
