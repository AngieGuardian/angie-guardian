// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"strconv"
	"testing"
)

var sink [32]byte

func BenchmarkNativeSolveLoop(b *testing.B) {
	challenge := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for i := 0; i < b.N; i++ {
		sink = sha256.Sum256([]byte(challenge + strconv.Itoa(i)))
	}
}
