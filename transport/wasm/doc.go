// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main (transport/wasm) is the optional http-wasm guest build of
// Guardian's stateless WAF checks, for running in-process inside Angie via its
// WebAssembly support instead of the sidecar.
//
// It is stateless WAF-only: static allowlist, static denylist, honeypot trap
// paths, and WAF rules with literal/regex matchers. Because the http-wasm ABI is
// synchronous with no shared store or outbound HTTP, the stateful features
// (proof-of-work challenges, behavioural IP blocking, anomaly scoring) are not
// available here and require the sidecar (cmd/guardiand).
//
// The guest sources its per-domain configuration from the host via the
// http-wasm get_config call (see deploy/angie-wasm.conf), parsed once by
// stateless.ParseGuestConfig.
//
// Build (requires Go 1.24+ for //go:wasmexport):
//
//	GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
//
// The guest itself is guarded by //go:build wasip1. On other targets this
// package is a stub (main below), so it never affects normal builds, tests or
// the sidecar; `go build ./...` compiles it as an inert command.
package main
