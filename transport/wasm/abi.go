// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build wasip1

package main

import (
	"runtime"
	"unsafe"
)

// This file binds the http-wasm HTTP Handler ABI host functions, imported
// from the "http_handler" module. The host (Angie) provides them; the guest
// calls them to inspect the request and shape the response. Buffers are
// passed as (pointer, length) into the guest's linear memory.
//
// kind selects request (0) vs response (1) for header/body operations.
const (
	kindRequest  int32 = 0
	kindResponse int32 = 1
)

//go:wasmimport http_handler get_uri
func hostGetURI(buf uint32, bufLimit uint32) uint32

//go:wasmimport http_handler get_source_addr
func hostGetSourceAddr(buf uint32, bufLimit uint32) uint32

//go:wasmimport http_handler get_header_values
func hostGetHeaderValues(kind int32, name uint32, nameLen uint32, buf uint32, bufLimit uint32) uint64

//go:wasmimport http_handler get_config
func hostGetConfig(buf uint32, bufLimit uint32) uint32

//go:wasmimport http_handler set_status_code
func hostSetStatusCode(status uint32)

//go:wasmimport http_handler write_body
func hostWriteBody(kind int32, body uint32, bodyLen uint32)

//go:wasmimport http_handler log
func hostLog(level int32, msg uint32, msgLen uint32)

// ptr returns the linear-memory address of a byte slice's backing array as a
// uint32, the address width the host expects for wasm32. Because the host
// functions take a plain uint32 (not a pointer type), the compiler does not
// keep the backing slice alive across the call; every caller must therefore
// keep the slice reachable (use it after the call, or runtime.KeepAlive) until
// the host has finished reading it.
func ptr(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&b[0])))
}

// initialReadBuf is the first buffer size for the grow-and-retry read
// protocol; large enough that most values (methods, URIs, headers) fit in one
// host call.
const initialReadBuf = 512

// readInto runs the http-wasm read protocol: call get to fill a buffer and
// return the total length; if the value was truncated, grow to exactly that
// length and call once more; then clamp. buf stays referenced across every
// host call, so its backing array is never collected mid-call. Returns the
// filled prefix (a sub-slice of the final buffer).
func readInto(get func(buf uint32, bufLimit uint32) uint32) []byte {
	buf := make([]byte, initialReadBuf)
	n := get(ptr(buf), uint32(len(buf)))
	if n > uint32(len(buf)) {
		buf = make([]byte, n)
		n = get(ptr(buf), uint32(len(buf)))
	}
	if n > uint32(len(buf)) {
		n = uint32(len(buf))
	}
	return buf[:n]
}

func readString(get func(buf uint32, bufLimit uint32) uint32) string {
	return string(readInto(get))
}

// getURI, getSourceAddr wrap the simple string getters.
func getURI() string        { return readString(hostGetURI) }
func getSourceAddr() string { return readString(hostGetSourceAddr) }

// getHeader returns the first value of a request header, or "". The ABI packs
// count in the high 32 bits and byte-length in the low 32 bits of the return;
// when several values are present they are NUL-separated, and we take the
// first. It uses the same grow-and-retry protocol as readInto, keeping both
// the name and value buffers referenced across each host call.
func getHeader(name string) string {
	nb := []byte(name)
	read := func(buf uint32, bufLimit uint32) uint32 {
		cl := hostGetHeaderValues(kindRequest, ptr(nb), uint32(len(nb)), buf, bufLimit)
		runtime.KeepAlive(nb) // nb must outlive the host read of the name
		// The low 32 bits are the byte length; the read protocol only cares
		// about that (an absent header reports length 0, yielding "").
		return uint32(cl)
	}
	values := readInto(read)
	for i, c := range values {
		if c == 0 {
			return string(values[:i])
		}
	}
	return string(values)
}

// getConfig returns the module's configuration blob (JSON/YAML) set on the
// Angie side.
func getConfig() []byte {
	return readInto(hostGetConfig)
}

func setStatus(code uint32) { hostSetStatusCode(code) }

func writeResponseBody(b []byte) {
	if len(b) == 0 {
		return
	}
	hostWriteBody(kindResponse, ptr(b), uint32(len(b)))
	runtime.KeepAlive(b) // b must outlive the host read
}

// log levels per the http-wasm ABI (debug=-1, info=0, warn=1, error=2).
func logInfo(msg string)  { hostLogMessage(0, msg) }
func logError(msg string) { hostLogMessage(2, msg) }

func hostLogMessage(level int32, msg string) {
	b := []byte(msg)
	hostLog(level, ptr(b), uint32(len(b)))
	runtime.KeepAlive(b) // b must outlive the host read
}
