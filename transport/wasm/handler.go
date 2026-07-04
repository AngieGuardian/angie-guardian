// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build wasip1

// Command guardian-wasm is the http-wasm guest: the stateless WAF subset of
// Guardian, compiled to WebAssembly to run in-process inside Angie via its
// WASM support. It is an optional alternative to the sidecar for operators who
// want the WASM integration; it runs the store-free checks only (allowlist,
// denylist, honeypot, signatures). Stateful features (proof-of-work,
// behavioural blocking, anomaly scoring) require the sidecar.
//
// Build: GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
package main

import (
	"strconv"

	"github.com/melroy89/angie-guardian/core/stateless"
)

// config is parsed once from the host on first request and cached. A parse
// failure is recorded so we fail closed (deny) rather than silently allowing
// everything with no rules.
var (
	config    *stateless.GuestConfig
	configErr string
	loaded    bool
)

func ensureConfig() {
	if loaded {
		return
	}
	loaded = true
	gc, err := stateless.ParseGuestConfig(getConfig())
	if err != nil {
		configErr = err.Error()
		logError("guardian-wasm: config error: " + configErr)
		return
	}
	config = gc
	logInfo("guardian-wasm: config loaded")
}

// ABI control-flow return values for handle_request (low 32 bits):
//
//	next=1 -> allow, continue to the next handler / backend
//	next=0 -> stop, return the response the guest set
const (
	next       uint64 = 1
	stop       uint64 = 0
	denyStatus        = 403
)

//go:wasmexport handle_request
func handleRequest() uint64 {
	ensureConfig()

	// Fail closed if the config could not be parsed: deny rather than run
	// with no protection.
	if config == nil {
		setStatus(500)
		writeResponseBody([]byte("Guardian WASM misconfigured\n"))
		return stop
	}

	req := &stateless.RequestContext{
		Host:       getHeader("Host"),
		Method:     getMethod(),
		URI:        getURI(),
		RemoteAddr: sourceIP(),
		UserAgent:  getHeader("User-Agent"),
		Cookie:     getHeader("Cookie"),
	}

	d := config.Evaluate(req)
	if d.Action == stateless.ActionAllow {
		return next
	}

	// ActionDeny (challenge degrades to deny in the stateless path).
	setStatus(denyStatus)
	writeResponseBody([]byte("Access denied by Angie Guardian\n"))
	logInfo("guardian-wasm deny host=" + req.Host + " ip=" + req.RemoteAddr + " reason=" + d.Reason)
	return stop
}

// sourceIP strips the port from the host-reported source address
// ("ip:port"), leaving the bare client IP that RequestContext expects.
func sourceIP() string {
	addr := getSourceAddr()
	// Split on the last colon; leave IPv6 literals in brackets intact.
	if len(addr) > 0 && addr[len(addr)-1] != ']' {
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				host := addr[:i]
				// Confirm the tail is a port number; if not, keep the whole string.
				if _, err := strconv.Atoi(addr[i+1:]); err == nil {
					return trimBrackets(host)
				}
				break
			}
		}
	}
	return trimBrackets(addr)
}

func trimBrackets(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

// main is required for the wasip1 reactor but does nothing; the entry point is
// the exported handle_request, invoked per request by the host.
func main() {}
