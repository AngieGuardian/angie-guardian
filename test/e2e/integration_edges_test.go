// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Guardian's auth_request subrequest carries only the request line and headers
// (proxy_pass_request_body off), never the body. These tests prove that
// contract holds end to end through real Angie: the awkward request shapes an
// adopter hits first — large POST bodies, non-GET methods, WebSocket upgrades —
// are handled correctly and the real body still reaches the backend intact.

// TestLargePOSTPassesThrough: a large POST body is allowed through to the
// backend unbuffered and uncorrupted. The auth subrequest carries no body
// (proxy_pass_request_body off), so the real body must still reach the backend
// whole. Uses the WAF-only host (PoW disabled) so a browser-less client is
// allowed.
//
// Body size is kept under Angie's default client_max_body_size (1 MiB): that
// limit is unaffected by auth_request and still governs uploads, so a site with
// large uploads must raise client_max_body_size in Angie regardless of Guardian
// (see the integration docs). A body over the limit is rejected by Angie with
// 413 before Guardian or the backend ever see it.
func TestLargePOSTPassesThrough(t *testing.T) {
	const size = 512 << 10 // 512 KiB: large, but under the default 1 MiB cap
	body := strings.Repeat("A", size)

	// A 502/503 here is a transient upstream hiccup in the shared compose stack
	// (Angie momentarily could not reach the backend or the auth sidecar), not a
	// body-passthrough failure, so retry a few times before failing. The body
	// reader is rebuilt each attempt since it is consumed on the first send.
	resp := postWithRetry(t, site+"/api", map[string]string{
		"Host":         wafOnlyHost,
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/octet-stream",
	}, body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("large POST: status %d, want 200 (allowed through to backend)", resp.StatusCode)
	}
	// whoami (/api) echoes the request it received as JSON, including the
	// Content-Length header it saw. Its presence with the full size is proof
	// the whole body reached the backend, not a truncated or empty one from the
	// body-less auth hop.
	echoed := bodyOf(t, resp)
	if !strings.Contains(echoed, `"Content-Length":["`+strconv.Itoa(size)+`"]`) {
		snippet := echoed
		if len(snippet) > 400 {
			snippet = snippet[:400]
		}
		t.Errorf("backend did not receive the full %d-byte body; echo was:\n%s", size, snippet)
	}
}

// TestPOSTHitsWAF: the WAF still evaluates a non-GET request even though its
// body is never sent to the sidecar. A POST to a dotfile-probe path is blocked
// on method+path+headers alone, confirming body-less auth does not weaken
// rule matching for POST/PUT/etc.
func TestPOSTHitsWAF(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	resp := req(t, http.MethodPost, site+"/.env", map[string]string{
		"Host":       powHost,
		"User-Agent": "curl/8",
	}, strings.NewReader("payload=x"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /.env: status %d, want 403 (WAF evaluates non-GET)", resp.StatusCode)
	}
}

// TestWebSocketUpgradeAuthorized: a WebSocket upgrade handshake goes through
// auth_request like any other request (the Upgrade/Connection headers ride the
// subrequest). An allowed upgrade reaches the backend; the point is that the
// upgrade request is not mishandled or hung by the auth hop. whoami is not a
// WS server, so we assert the handshake was authorized and proxied (not a
// Guardian 401/403), i.e. the upgrade path is not broken by the sidecar.
func TestWebSocketUpgradeAuthorized(t *testing.T) {
	resp := req(t, http.MethodGet, site+"/ws", map[string]string{
		"Host":                  wafOnlyHost, // PoW disabled: a raw client is allowed
		"User-Agent":            "Mozilla/5.0",
		"Connection":            "Upgrade",
		"Upgrade":               "websocket",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
	}, nil)

	// The auth decision must be "allow": Guardian must not 401/403 a WS upgrade
	// from an allowed client. The backend (whoami) doesn't speak WS, so the
	// response is whatever it returns for a plain GET — the assertion is only
	// that Guardian did not divert it to a challenge or denied page.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		t.Fatalf("WebSocket upgrade was blocked by Guardian: status %d, want it authorized and proxied", resp.StatusCode)
	}
	if a := resp.Header.Get("X-Guardian-Action"); a != "" && a != "allow" {
		t.Errorf("WS upgrade guardian action = %q, want allow", a)
	}
}
