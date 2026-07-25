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
	"hash"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// Manager issues and redeems PoW challenges. It is transport-agnostic; all
// per-domain policy (difficulty, TTLs) is passed in by the caller.
//
// The signing key can be rotated at runtime: keys is guarded by mu, holding
// the current signing key at index 0 followed by retired keys still accepted
// for verification. Each key has a derived HMAC secret in hmacSecrets at the
// same index: index 0 signs (issues) challenges, and stateless redemption
// verifies against ALL of them, so an s1. challenge issued by a peer that
// rotated to a different current key (its old key is retired here) still
// redeems. Stateful challenges are unaffected: their challenge string is
// stored, not recomputed.
type Manager struct {
	mu          sync.RWMutex
	keys        []managerKey // keys[0] signs; all verify
	hmacSecret  []byte       // == hmacSecrets[0]; the issuing secret
	hmacSecrets [][]byte     // per-key derived secrets; hmacSecrets[i] pairs keys[i]
	store       store.Store
	cache       *tokenCache
	spent       *tokenCache         // local replay guard when the shared spent CAS is down
	counters    *store.CounterCache // escalation counts, off the write hot path

	reloadMu           sync.Mutex
	keyPath            string
	prevDir            string
	lastRefresh        time.Time
	lastRefreshErr     error
	lastFailureRefresh time.Time
	lastFailureErr     error

	// File-backed token verification must periodically refresh even when an
	// old-key signature still succeeds: otherwise a quiet replica can keep
	// treating a compromised retired key as current forever. The atomic
	// deadline keeps the common path lock-free, while routineRefresh coalesces
	// the one disk reload due every keyRefreshInterval.
	fileBacked           atomic.Bool
	routineRefreshUntil  atomic.Int64
	routineRefresh       atomic.Pointer[keyRefreshRound]
	routineRefreshFailed atomic.Pointer[keyRefreshFailure]

	// NoJSMinDelay is the minimum wall-clock wait before a meta-refresh
	// (no-JS) redemption is accepted. Overridable for tests.
	NoJSMinDelay time.Duration

	// macs recycles the issuing-secret HMAC state across challenge issuances
	// (the zero value is ready to use; see macCache).
	macs macCache

	now func() time.Time
}

// macCache pools HMAC-SHA256 states keyed by their secret. Building the state
// costs two SHA-256 inits and several allocations, paid once per issued
// challenge — the hottest write path under a flood — while the issuing secret
// changes only on key rotation. A pooled state is reused only when its secret
// matches the caller's exactly; after a rotation the stale states simply fail
// that comparison once and are dropped for the collector.
type macCache struct {
	pool sync.Pool // holds *keyedMAC
}

// keyedMAC is one pooled HMAC state together with the secret it was keyed
// with. Reset restores the post-key initial state, so reuse leaks nothing
// between requests beyond the key the state inherently holds.
type keyedMAC struct {
	secret []byte
	mac    hash.Hash
}

func (c *macCache) get(secret []byte) *keyedMAC {
	if v := c.pool.Get(); v != nil {
		km := v.(*keyedMAC)
		if hmac.Equal(km.secret, secret) {
			km.mac.Reset()
			return km
		}
		// Keyed with a retired secret (rotation happened): discard.
	}
	return &keyedMAC{secret: secret, mac: hmac.New(sha256.New, secret)}
}

func (c *macCache) put(km *keyedMAC) { c.pool.Put(km) }

type managerKey struct {
	private   ed25519.PrivateKey
	retiredAt time.Time // zero for the current signing key
}

type keyRefreshRound struct {
	done chan struct{}
	err  error // published before done is closed
}

type keyRefreshFailure struct{ err error }

func NewManager(key ed25519.PrivateKey, st store.Store) *Manager {
	return NewManagerWithKeys(key, nil, st)
}

// NewManagerFromFiles creates a manager that can notice rotations performed
// by another Guardian process sharing the same key files. The current key is
// refreshed periodically before signing and immediately (rate limited) when
// verification misses the in-memory key set.
func NewManagerFromFiles(keyPath, prevDir string, st store.Store) (*Manager, error) {
	if _, err := LoadOrCreateKey(keyPath); err != nil {
		return nil, err
	}
	key, previous, err := loadKeySetSnapshot(keyPath, prevDir, time.Now())
	if err != nil {
		return nil, err
	}
	m := newManagerWithRetiredKeys(key, previous, st)
	m.keyPath = keyPath
	m.prevDir = prevDir
	m.lastRefresh = m.now()
	m.fileBacked.Store(true)
	m.routineRefreshUntil.Store(m.lastRefresh.Add(keyRefreshInterval).UnixNano())
	return m, nil
}

// NewManagerWithKeys builds a Manager that signs with current and also
// verifies tokens signed by any key in previous (rotation support).
func NewManagerWithKeys(current ed25519.PrivateKey, previous []ed25519.PrivateKey, st store.Store) *Manager {
	retired := make([]RetiredKey, len(previous))
	now := time.Now()
	for i := range previous {
		retired[i] = RetiredKey{Key: previous[i], RetiredAt: now}
	}
	return newManagerWithRetiredKeys(current, retired, st)
}

func newManagerWithRetiredKeys(current ed25519.PrivateKey, previous []RetiredKey, st store.Store) *Manager {
	keys := make([]managerKey, 1, 1+len(previous))
	keys[0] = managerKey{private: current}
	for _, key := range previous {
		keys = append(keys, managerKey{private: key.Key, retiredAt: key.RetiredAt})
	}
	secrets := deriveHMACSecrets(keys)
	return &Manager{
		keys:         keys,
		hmacSecret:   secrets[0],
		hmacSecrets:  secrets,
		store:        st,
		cache:        newTokenCache(),
		spent:        newTokenCache(),
		counters:     store.NewCounterCache(st),
		NoJSMinDelay: 5 * time.Second,
		now:          time.Now,
	}
}

// deriveHMACSecrets computes one HMAC secret per key, from that key's seed, so
// all instances sharing a key derive the same secret and can verify each
// other's stateless challenges across a rotation.
func deriveHMACSecrets(keys []managerKey) [][]byte {
	secrets := make([][]byte, len(keys))
	for i, k := range keys {
		sum := sha256.Sum256(append([]byte("guardian-hmac-v1\x00"), k.private.Seed()...))
		secrets[i] = sum[:]
	}
	return secrets
}

// FlushCounters drains the escalation counter cache's unpushed deltas to the
// store, bounded by ctx. Call at shutdown, after traffic has stopped and
// before the store closes, so shared/durable backends keep the last windows'
// counts across a restart.
func (m *Manager) FlushCounters(ctx context.Context) error {
	if m == nil {
		return nil // PoW not configured
	}
	return m.counters.Flush(ctx)
}

// SetKeys atomically replaces the key set (current at index 0). Called after
// a rotation reloads keys from disk. The token cache is cleared so a token
// signed by a now-removed key is re-verified rather than served from cache.
func (m *Manager) SetKeys(current ed25519.PrivateKey, previous []ed25519.PrivateKey) {
	retired := make([]RetiredKey, len(previous))
	now := m.now()
	for i := range previous {
		retired[i] = RetiredKey{Key: previous[i], RetiredAt: now}
	}
	m.setRetiredKeys(current, retired)
}

func (m *Manager) setRetiredKeys(current ed25519.PrivateKey, previous []RetiredKey) {
	keys := make([]managerKey, 1, 1+len(previous))
	keys[0] = managerKey{private: current}
	for _, key := range previous {
		keys = append(keys, managerKey{private: key.Key, retiredAt: key.RetiredAt})
	}
	secrets := deriveHMACSecrets(keys)
	m.mu.Lock()
	m.keys = keys
	m.hmacSecret = secrets[0]
	m.hmacSecrets = secrets
	m.mu.Unlock()
	m.cache.reset()
}

// keySetMatches reports whether a disk refresh found exactly the key set
// already installed. Avoiding a redundant SetKeys preserves the verified-token
// cache across the routine 250ms refreshes.
func (m *Manager) keySetMatches(current ed25519.PrivateKey, previous []RetiredKey) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.keys) != 1+len(previous) || !m.keys[0].private.Equal(current) {
		return false
	}
	for i, key := range previous {
		installed := m.keys[i+1]
		if !installed.private.Equal(key.Key) || !installed.retiredAt.Equal(key.RetiredAt) {
			return false
		}
	}
	return true
}

func (m *Manager) signingKey() ed25519.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[0].private
}

// Rotate generates a new signing key, archives the current one into prevDir,
// and swaps the key set so the new key signs while the old key still
// verifies live tokens. keyPath/prevDir are the same paths guardiand loaded
// from, so a restart (or a peer instance's reload) reconstructs the same set.
func (m *Manager) Rotate(keyPath, prevDir string) error {
	_, err := RotateKey(keyPath, prevDir, m.now().Unix())
	if err != nil {
		return err
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.keyPath, m.prevDir = keyPath, prevDir
	m.fileBacked.Store(true)
	err = m.reloadKeysLocked()
	if err != nil {
		m.rememberRoutineRefresh(err)
	}
	return err
}

const keyRefreshInterval = 250 * time.Millisecond

// ReloadKeys immediately reloads the current and retired keys from the files
// configured by NewManagerFromFiles or the last successful Rotate call.
func (m *Manager) ReloadKeys() error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.keyPath == "" {
		return errors.New("manager has no signing key files configured")
	}
	err := m.reloadKeysLocked()
	if err != nil {
		m.rememberRoutineRefresh(err)
	}
	return err
}

func (m *Manager) reloadKeysLocked() error {
	current, previous, err := loadKeySetSnapshot(m.keyPath, m.prevDir, m.now())
	if err != nil {
		return err
	}
	if !m.keySetMatches(current, previous) {
		m.setRetiredKeys(current, previous)
	}
	refreshedAt := m.now()
	m.lastRefresh = refreshedAt
	m.lastRefreshErr = nil
	m.lastFailureErr = nil
	m.routineRefreshFailed.Store(nil)
	m.routineRefreshUntil.Store(refreshedAt.Add(keyRefreshInterval).UnixNano())
	return nil
}

// rememberRoutineRefresh publishes one routine refresh result to the atomic
// verification fast path. Errors remain fail-closed for the whole throttle
// interval rather than being forgotten by the next cached-token request.
func (m *Manager) rememberRoutineRefresh(err error) {
	if err == nil {
		m.routineRefreshFailed.Store(nil)
	} else {
		m.routineRefreshFailed.Store(&keyRefreshFailure{err: err})
	}
	m.routineRefreshUntil.Store(m.now().Add(keyRefreshInterval).UnixNano())
}

// refreshKeysBeforeTokenAccept is the periodic file-backed verification gate.
// Inside the throttle window it is lock-free. At expiry exactly one caller
// reloads; concurrent callers wait on that round instead of piling up on
// reloadMu or accepting against stale keys while the refresh is in progress.
func (m *Manager) refreshKeysBeforeTokenAccept() error {
	if !m.fileBacked.Load() {
		return nil
	}
	for {
		if m.now().UnixNano() < m.routineRefreshUntil.Load() {
			if failed := m.routineRefreshFailed.Load(); failed != nil {
				return failed.err
			}
			return nil
		}
		if running := m.routineRefresh.Load(); running != nil {
			<-running.done
			return running.err
		}
		round := &keyRefreshRound{done: make(chan struct{})}
		if !m.routineRefresh.CompareAndSwap(nil, round) {
			continue
		}
		_, round.err = m.refreshKeys(false)
		close(round.done)
		m.routineRefresh.CompareAndSwap(round, nil)
		return round.err
	}
}

// refreshKeys performs a throttled file refresh. A verification failure uses
// its own throttle so a newly rotated peer key is noticed immediately even if
// a routine signing refresh happened moments earlier.
func (m *Manager) refreshKeys(afterVerificationFailure bool) (bool, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.keyPath == "" {
		return false, nil
	}
	now := m.now()
	if afterVerificationFailure {
		if !m.lastFailureRefresh.IsZero() && now.Sub(m.lastFailureRefresh) < keyRefreshInterval {
			return false, m.lastFailureErr
		}
		m.lastFailureRefresh = now
	} else {
		if !m.lastRefresh.IsZero() && now.Sub(m.lastRefresh) < keyRefreshInterval {
			m.rememberRoutineRefresh(m.lastRefreshErr)
			return false, m.lastRefreshErr
		}
		m.lastRefresh = now // throttle repeated read failures too
	}
	if err := m.reloadKeysLocked(); err != nil {
		if afterVerificationFailure {
			m.lastFailureErr = err
		} else {
			m.lastRefreshErr = err
		}
		m.rememberRoutineRefresh(err)
		return false, err
	}
	return true, nil
}

// Challenge is what the interstitial page needs to render and solve.
// Difficulty is the required number of leading zero bits of
// SHA-256(challenge + nonce); each bit doubles the expected work.
type Challenge struct {
	ID         string `json:"challenge_id"`
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty_bits"`
}

// record is the stored issuance record. State moves from
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
	var idRaw [16]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		return nil, err
	}
	// hex.Encode into a stack scratch, then one string conversion:
	// EncodeToString would allocate the intermediate byte slice as well.
	var idHex [32]byte
	hex.Encode(idHex[:], idRaw[:])
	id := string(idHex[:])

	// challenge = HMAC(secret, host || ip || time_bucket || id): opaque to the
	// client, deterministic for us, rotates with the hourly bucket.
	// Stateful challenges store this string in the record, so cross-rotation
	// redemption reads it back rather than recomputing; the issuing secret is
	// sufficient here.
	//
	// The message is appended into a stack scratch and written once (fmt would
	// box every argument), and the HMAC state comes from the per-secret pool:
	// this runs once per issued challenge, which under a flood is the hottest
	// write path in the product.
	bucket := m.now().Unix() / 3600
	// 384 covers the realistic maximum without a heap allocation: a 253-byte
	// DNS name, a 45-byte IPv6 text form, a 19-digit bucket, the 32-byte id and
	// three separators. A longer (attacker-supplied) Host is not a correctness
	// problem: append simply spills to the heap for that one issuance. Do not
	// "fix" that with a length check, and do not shrink the array below the sum
	// above, or the common case starts allocating.
	var msgBuf [384]byte
	msg := append(msgBuf[:0], strings.ToLower(host)...)
	msg = append(msg, 0)
	msg = append(msg, ip...)
	msg = append(msg, 0)
	msg = strconv.AppendInt(msg, bucket, 10)
	msg = append(msg, 0)
	msg = append(msg, id...)
	km := m.macs.get(m.issuingSecret())
	km.mac.Write(msg)
	var sumBuf [sha256.Size]byte
	var chalHex [2 * sha256.Size]byte
	hex.Encode(chalHex[:], km.mac.Sum(sumBuf[:0]))
	challenge := string(chalHex[:])
	m.macs.put(km)

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
	// so a solved challenge can never be replayed.
	ChallengeTTL time.Duration

	// TTLs optionally resolves the token and spent-marker TTLs from the URI
	// the challenge was issued for, so per-path token policy applies at
	// redemption (the solve POST itself does not carry the original URI).
	// When nil, TokenTTL and ChallengeTTL are used as given.
	TTLs func(uri string) (token, challenge time.Duration)
}

// RedeemResult is a minted token plus where to send the client afterwards.
type RedeemResult struct {
	Token       string
	TokenTTL    time.Duration
	RedirectURI string
	// SoftError is set when a token was minted despite a non-fatal issue
	// (currently only a failed single-spend write during a store outage, on
	// the stateless path). The caller may count it; the redemption still
	// succeeds.
	SoftError error
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
	// A stateless challenge carries its own authenticated state; it is always
	// accepted (both formats coexist forever) so a challenge issued just
	// before an attack-mode flip still redeems.
	if IsStatelessID(req.ChallengeID) {
		return m.redeemStateless(ctx, req)
	}
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
	tokenTTL, challengeTTL := req.TokenTTL, req.ChallengeTTL
	if req.TTLs != nil {
		tokenTTL, challengeTTL = req.TTLs(rec.URI)
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
	swapped, err := m.store.CompareAndSwap(ctx, challengeKey(req.ChallengeID), raw, spent, challengeTTL)
	if err != nil {
		return nil, err
	}
	if !swapped {
		return nil, ErrChallengeUnknown // lost the race: someone spent it first
	}

	// The client just proved it solves what it requests: forget its
	// unsolved-issuance escalation counter (best-effort; see escalation.go).
	m.counters.Forget(escalationKey(rec.Host, rec.IP))

	token, err := m.mintToken(rec.Host, Fingerprint(req.IP, req.UserAgent), req.ChallengeID, rec.Difficulty, tokenTTL)
	if err != nil {
		return nil, err
	}
	return &RedeemResult{Token: token, TokenTTL: tokenTTL, RedirectURI: rec.URI}, nil
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
