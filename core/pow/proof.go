// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Algorithm string

const (
	AlgorithmSHA256   Algorithm = "sha256"
	AlgorithmArgon2ID Algorithm = "argon2id"
	argon2SaltSize              = 16
	argon2ProofSize             = 32
)

// ProofSpec is immutable work policy authenticated with a challenge. SHA-256
// uses Difficulty; Argon2id uses MemoryKiB/Iterations/Salt and has no second
// leading-zero search.
type ProofSpec struct {
	Algorithm  Algorithm
	Difficulty int
	MemoryKiB  uint32
	Iterations uint32
	Salt       [argon2SaltSize]byte
}

func (s ProofSpec) algorithm() Algorithm {
	if s.Algorithm == "" {
		return AlgorithmSHA256
	}
	return s.Algorithm
}

func (s ProofSpec) validate() error {
	switch s.algorithm() {
	case AlgorithmSHA256:
		if s.Difficulty < 0 || s.Difficulty > 32 {
			return fmt.Errorf("sha256 difficulty %d is outside 0..32", s.Difficulty)
		}
	case AlgorithmArgon2ID:
		if s.MemoryKiB < 8*1024 || s.MemoryKiB > 32*1024 {
			return fmt.Errorf("argon2id memory %d KiB is outside 8192..32768", s.MemoryKiB)
		}
		if s.Iterations < 1 || s.Iterations > 3 {
			return fmt.Errorf("argon2id iterations %d is outside 1..3", s.Iterations)
		}
	default:
		return fmt.Errorf("unknown proof algorithm %q", s.Algorithm)
	}
	return nil
}

func verifyArgon2ID(challenge string, spec ProofSpec, proofHex string) bool {
	if len(proofHex) != hex.EncodedLen(argon2ProofSize) {
		return false
	}
	var got [argon2ProofSize]byte
	if _, err := hex.Decode(got[:], []byte(proofHex)); err != nil {
		return false
	}
	want := argon2.IDKey([]byte(challenge), spec.Salt[:], spec.Iterations, spec.MemoryKiB, 1, argon2ProofSize)
	ok := subtle.ConstantTimeCompare(got[:], want) == 1
	clear(want)
	return ok
}
