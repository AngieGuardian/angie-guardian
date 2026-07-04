// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build wasip1

package main

import "unsafe"

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

//go:wasmimport http_handler get_method
func hostGetMethod(buf uint32, bufLimit uint32) uint32

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
// uint32, the address width the host expects for wasm32.
func ptr(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&b[0])))
}

// readString calls a host getter that fills buf and returns the total length,
// growing the buffer and retrying once if the value was truncated.
func readString(get func(buf uint32, bufLimit uint32) uint32) string {
	buf := make([]byte, 256)
	n := get(ptr(buf), uint32(len(buf)))
	if n > uint32(len(buf)) {
		buf = make([]byte, n)
		n = get(ptr(buf), uint32(len(buf)))
	}
	if n > uint32(len(buf)) {
		n = uint32(len(buf))
	}
	return string(buf[:n])
}

// getMethod, getURI, getSourceAddr wrap the simple string getters.
func getMethod() string     { return readString(hostGetMethod) }
func getURI() string        { return readString(hostGetURI) }
func getSourceAddr() string { return readString(hostGetSourceAddr) }

// getHeader returns the first value of a request header, or "". The ABI packs
// count in the high 32 bits and byte-length in the low 32 bits of the return;
// when several values are present they are NUL-separated, and we take the
// first.
func getHeader(name string) string {
	nb := []byte(name)
	buf := make([]byte, 512)
	countLen := hostGetHeaderValues(kindRequest, ptr(nb), uint32(len(nb)), ptr(buf), uint32(len(buf)))
	count := uint32(countLen >> 32)
	length := uint32(countLen)
	if count == 0 || length == 0 {
		return ""
	}
	if length > uint32(len(buf)) {
		buf = make([]byte, length)
		countLen = hostGetHeaderValues(kindRequest, ptr(nb), uint32(len(nb)), ptr(buf), uint32(len(buf)))
		length = uint32(countLen)
		if length > uint32(len(buf)) {
			length = uint32(len(buf))
		}
	}
	values := buf[:length]
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
	buf := make([]byte, 4096)
	n := hostGetConfig(ptr(buf), uint32(len(buf)))
	if n > uint32(len(buf)) {
		buf = make([]byte, n)
		n = hostGetConfig(ptr(buf), uint32(len(buf)))
	}
	if n > uint32(len(buf)) {
		n = uint32(len(buf))
	}
	return buf[:n]
}

func setStatus(code uint32) { hostSetStatusCode(code) }

func writeResponseBody(b []byte) {
	if len(b) == 0 {
		return
	}
	hostWriteBody(kindResponse, ptr(b), uint32(len(b)))
}

// log levels per the http-wasm ABI (debug=-1, info=0, warn=1, error=2).
func logInfo(msg string) {
	b := []byte(msg)
	hostLog(0, ptr(b), uint32(len(b)))
}

func logError(msg string) {
	b := []byte(msg)
	hostLog(2, ptr(b), uint32(len(b)))
}
