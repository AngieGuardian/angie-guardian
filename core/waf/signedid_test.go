// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import (
	"errors"
	"testing"
	"time"
)

func TestSignedIDRoundTrip(t *testing.T) {
	s := NewSigner([]byte("test-secret-0123456789abcdef0123"))

	id, err := s.Mint("challenge", "example.com", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(id, "challenge", "example.com"); err != nil {
		t.Fatalf("genuine id rejected: %v", err)
	}
	if err := s.Verify(id, "challenge", "EXAMPLE.com"); err != nil {
		t.Fatalf("host binding must be case-insensitive: %v", err)
	}

	// Cross-purpose, cross-host and tampered IDs all fail as forgeries.
	if err := s.Verify(id, "session", "example.com"); !errors.Is(err, ErrIDTampered) {
		t.Errorf("cross-purpose: %v, want ErrIDTampered", err)
	}
	if err := s.Verify(id, "challenge", "evil.com"); !errors.Is(err, ErrIDTampered) {
		t.Errorf("cross-host: %v, want ErrIDTampered", err)
	}
	if err := s.Verify(id[:len(id)-2]+"xx", "challenge", "example.com"); !errors.Is(err, ErrIDTampered) {
		t.Errorf("tampered: %v, want ErrIDTampered", err)
	}
	if err := s.Verify("not-base64!!!", "challenge", "example.com"); !errors.Is(err, ErrIDTampered) {
		t.Errorf("garbage: %v, want ErrIDTampered", err)
	}

	// A different signer never validates IDs from this one.
	other := NewSigner([]byte("another-secret-xxxxxxxxxxxxxxxxx"))
	if err := other.Verify(id, "challenge", "example.com"); !errors.Is(err, ErrIDTampered) {
		t.Errorf("cross-signer: %v, want ErrIDTampered", err)
	}
}

func TestSignedIDExpiry(t *testing.T) {
	s := NewSigner([]byte("test-secret"))
	base := time.Now()
	s.now = func() time.Time { return base }

	id, err := s.Mint("x", "h", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(id, "x", "h"); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if err := s.Verify(id, "x", "h"); !errors.Is(err, ErrIDExpired) {
		t.Fatalf("expired id: %v, want ErrIDExpired", err)
	}
}
