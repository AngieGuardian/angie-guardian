// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Stateless challenge issuance. Under attack the ordinary Issue path writes a
// store record per new client, and embedded bbolt's single fsync'd writer
// tops out around 4k/s, so a flood of fresh clients saturates the store. A
// stateless challenge instead carries its own authenticated state in the ID:
// no store write at issue time. Single-spend still holds, moved to redeem
// time (a spent marker keyed by the challenge, written only after the client
// has actually paid the proof of work), so the only store write an attacker
// can induce costs them real compute first.
//
// The ID is self-describing and versioned so it coexists with the 32-hex
// stateful ID forever: Redeem dispatches on the "s1." prefix and both formats
// are accepted unconditionally, so a challenge issued seconds before or after
// a posture flip still redeems.

const statelessPrefix = "s1."

// statelessMaxURI caps the redirect URI carried in the payload, so a crafted
// long URI cannot bloat the challenge ID.
const statelessMaxURI = 512

// statelessSkew tolerates modest clock skew between issuing and redeeming
// instances that share the signing key.
const statelessSkew = 30 * time.Second

// statelessPayload is the authenticated content of a stateless challenge ID.
// Field names are short because the whole thing is base64'd into the ID.
type statelessPayload struct {
	V    int    `json:"v"`
	Host string `json:"h"`
	IP   string `json:"i"`
	Bits int    `json:"d"`
	URI  string `json:"u"`
	NoJS int    `json:"n"` // 0/1
	TS   int64  `json:"t"` // issued-at unix millis
	Rand string `json:"r"` // 96-bit hex, so identical requests differ
}

var b64 = base64.RawURLEncoding

// IssueStateless mints a challenge with NO store write. The returned ID is
// self-authenticating; the solve string is derived from the same secret and
// returned for the client's solver but never embedded in the ID.
func (m *Manager) IssueStateless(host, ip, uri string, difficulty int, allowNoJS bool) (*Challenge, error) {
	if len(uri) > statelessMaxURI {
		uri = "/"
	}
	r := make([]byte, 12)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	nojs := 0
	if allowNoJS {
		nojs = 1
	}
	p := statelessPayload{
		V: 1, Host: strings.ToLower(host), IP: ip, Bits: difficulty,
		URI: uri, NoJS: nojs, TS: m.now().UnixMilli(), Rand: hex.EncodeToString(r),
	}
	payload, err := json.Marshal(&p)
	if err != nil {
		return nil, err
	}
	// A quiet file-backed replica may not have observed a peer's rotation yet.
	// Perform the rate-limited key refresh before issuing, while keeping the
	// attack hot path free of a per-challenge file lock/read. A challenge minted
	// during the short refresh interval is still accepted through the archived
	// key; the refresh prevents indefinite issuance with a stale key.
	_, _ = m.refreshKeys(false)
	secret := m.issuingSecret()
	mac, solve := statelessMAC(secret, payload), statelessSolve(secret, payload)
	id := statelessPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(mac)
	return &Challenge{ID: id, Challenge: solve, Difficulty: difficulty}, nil
}

// issuingSecret returns the current signing key's HMAC secret (a snapshot; the
// slice is never mutated in place, so the pointer is safe to read after the
// lock is released).
func (m *Manager) issuingSecret() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hmacSecret
}

// verifySecrets snapshots every key's HMAC secret (current + retired), so a
// stateless challenge signed by any live key in the fleet verifies.
func (m *Manager) verifySecrets() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hmacSecrets
}

// matchStatelessSecret returns the first live HMAC secret whose MAC over
// payload equals gotMAC, or nil if none match.
func (m *Manager) matchStatelessSecret(gotMAC, payload []byte) []byte {
	for _, s := range m.verifySecrets() {
		if hmac.Equal(gotMAC, statelessMAC(s, payload)) {
			return s
		}
	}
	return nil
}

// statelessMAC authenticates the payload (16-byte truncated HMAC is ample for
// a short-lived, client-bound token).
func statelessMAC(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("guardian-stateless-v1\x00"))
	mac.Write(payload)
	return mac.Sum(nil)[:16]
}

// statelessSolve derives the string the client hashes against, from the same
// secret, so it need not be transmitted inside the ID.
func statelessSolve(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("guardian-stateless-chal-v1\x00"))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// IsStatelessID reports whether an ID is the stateless format.
func IsStatelessID(id string) bool { return strings.HasPrefix(id, statelessPrefix) }

// redeemStateless verifies a stateless challenge and mints a token. Cheap
// checks (MAC, freshness, binding, solution) run before the single-spend
// store write, so an attacker only induces a store op by actually paying the
// proof of work.
func (m *Manager) redeemStateless(ctx context.Context, req *RedeemRequest) (*RedeemResult, error) {
	rest, ok := strings.CutPrefix(req.ChallengeID, statelessPrefix)
	if !ok {
		return nil, ErrChallengeUnknown
	}
	payloadB64, macB64, ok := strings.Cut(rest, ".")
	if !ok {
		return nil, ErrChallengeUnknown
	}
	payload, err := b64.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrChallengeUnknown
	}
	gotMAC, err := b64.DecodeString(macB64)
	if err != nil {
		return nil, ErrChallengeUnknown
	}
	// Try every live key's secret (current + retired), so a challenge issued
	// by a peer that has since rotated to a different current key still
	// verifies. The matching secret is reused for the solve-string check.
	secret := m.matchStatelessSecret(gotMAC, payload)
	if secret == nil {
		// A peer may have rotated to a key this file-backed instance has not
		// yet re-read (rolling restart). Do the same rate-limited disk refresh
		// as VerifyToken, then retry the MAC once against the refreshed
		// secrets. A no-op for in-memory managers (no keyPath).
		if refreshed, _ := m.refreshKeys(true); refreshed {
			secret = m.matchStatelessSecret(gotMAC, payload)
		}
	}
	if secret == nil {
		return nil, ErrChallengeUnknown
	}
	var p statelessPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.V != 1 {
		return nil, ErrChallengeUnknown
	}

	// Freshness: the resolved (possibly per-path) challenge TTL, plus a skew
	// allowance for a peer instance's clock.
	tokenTTL, challengeTTL := req.TokenTTL, req.ChallengeTTL
	if req.TTLs != nil {
		tokenTTL, challengeTTL = req.TTLs(p.URI)
	}
	now := m.now()
	issued := time.UnixMilli(p.TS)
	if now.Sub(issued) > challengeTTL || issued.Sub(now) > statelessSkew {
		return nil, ErrChallengeUnknown
	}

	// Binding.
	if !strings.EqualFold(p.Host, req.Host) || p.IP != req.IP {
		return nil, ErrBindingMismatch
	}

	challenge := statelessSolve(secret, payload)
	if req.NoJS {
		if p.NoJS != 1 {
			return nil, ErrNoJSDisabled
		}
		if now.Sub(issued) < m.NoJSMinDelay {
			return nil, ErrTooFast
		}
	} else {
		sum := sha256.Sum256([]byte(challenge + req.Nonce))
		if leadingZeroBits(sum[:]) < p.Bits {
			return nil, ErrBadSolution
		}
	}

	// Single-spend: create-only marker keyed by the challenge. The remaining
	// TTL matches how long the challenge could still be replayed.
	remaining := challengeTTL - now.Sub(issued)
	if remaining <= 0 {
		remaining = time.Minute
	}
	spentDigest := sha256.Sum256([]byte(challenge))
	if m.spent.get(spentDigest, now) {
		return nil, ErrChallengeUnknown
	}
	spentKey := "spent1:" + hex.EncodeToString(spentDigest[:16])
	swapped, err := m.store.CompareAndSwap(ctx, spentKey, nil, []byte{1}, remaining)
	if err != nil {
		// Store is down: claim the challenge in a bounded local replay cache,
		// then mint fail-open. This preserves availability without letting the
		// same process repeatedly mint from one solved challenge; the shared CAS
		// remains the cross-replica guarantee and the caller exposes its failure.
		if !m.spent.claim(spentDigest, now.Add(remaining), now) {
			return nil, ErrChallengeUnknown
		}
		return m.finishStateless(&p, req, tokenTTL, errSpentCASFailed)
	}
	if !swapped {
		return nil, ErrChallengeUnknown // already spent (replay)
	}
	_ = m.spent.claim(spentDigest, now.Add(remaining), now)
	return m.finishStateless(&p, req, tokenTTL, nil)
}

// errSpentCASFailed signals that the single-spend write failed but a token was
// minted anyway; the transport counts it without treating it as an error.
var errSpentCASFailed = fmt.Errorf("stateless spend cas failed; token minted fail-open")

func (m *Manager) finishStateless(p *statelessPayload, req *RedeemRequest, tokenTTL time.Duration, softErr error) (*RedeemResult, error) {
	m.counters.Forget(escalationKey(p.Host, p.IP))
	token, err := m.mintToken(p.Host, Fingerprint(req.IP, req.UserAgent), "", p.Bits, tokenTTL)
	if err != nil {
		return nil, err
	}
	return &RedeemResult{Token: token, TokenTTL: tokenTTL, RedirectURI: p.URI, SoftError: softErr}, nil
}
