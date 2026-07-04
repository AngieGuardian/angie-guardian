// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !wasip1

package main

// This stub exists only so `go build ./...` and the linters can compile the
// package on non-wasm targets. The real guest (handle_request + the ABI
// bindings) lives in files guarded by //go:build wasip1 and is produced by
//
//	GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
func main() {}
