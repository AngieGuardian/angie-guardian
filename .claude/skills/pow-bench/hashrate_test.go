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
