// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// Signer mints and verifies opaque tamper-proof identifiers:
// instead of a raw UUID, an ID carries an expiry and an HMAC bound to
// {purpose, host}, so any modification, forgery, cross-domain replay or
// cross-purpose reuse fails verification instantly and can be scored as a
// tamper event. One primitive, reused wherever Guardian hands out an ID.
type Signer struct {
	secret []byte
	now    func() time.Time
}

var (
	ErrIDTampered = errors.New("id forged or tampered")
	ErrIDExpired  = errors.New("id expired")
)

const (
	idPayloadLen = 8 + 16 // expiry + random
	idMacLen     = 16     // truncated HMAC-SHA256
	idRawLen     = idPayloadLen + idMacLen
)

func NewSigner(secret []byte) *Signer {
	return &Signer{secret: secret, now: time.Now}
}

// Mint returns a URL-safe opaque ID valid for ttl, bound to purpose and host.
func (s *Signer) Mint(purpose, host string, ttl time.Duration) (string, error) {
	raw := make([]byte, idPayloadLen, idRawLen)
	binary.BigEndian.PutUint64(raw, uint64(s.now().Add(ttl).Unix()))
	if _, err := rand.Read(raw[8:idPayloadLen]); err != nil {
		return "", err
	}
	raw = append(raw, s.mac(purpose, host, raw[:idPayloadLen])...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Verify checks integrity, binding and expiry. Integrity is checked first so
// an expired-but-genuine ID is distinguishable from a forgery.
func (s *Signer) Verify(id, purpose, host string) error {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != idRawLen {
		return ErrIDTampered
	}
	if !hmac.Equal(raw[idPayloadLen:], s.mac(purpose, host, raw[:idPayloadLen])) {
		return ErrIDTampered
	}
	if s.now().Unix() > int64(binary.BigEndian.Uint64(raw)) {
		return ErrIDExpired
	}
	return nil
}

func (s *Signer) mac(purpose, host string, payload []byte) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write([]byte(strings.ToLower(host)))
	m.Write([]byte{0})
	m.Write(payload)
	return m.Sum(nil)[:idMacLen]
}
