// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
)

func TestAllowlistPoWExemptionsThroughAngie(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()
	for _, tc := range []struct{ host, prefix, ua, exemption string }{
		{"ua-exempt.localhost", "", "FixtureMachine/1.0", "allowlist:ua"},
		{"path-exempt.localhost", "/exempt", "machine-client/1.0", "allowlist:path"},
		{"network-exempt.localhost", "", "machine-client/1.0", "allowlist:ip"},
	} {
		t.Run(tc.exemption, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				before := backendCount(t)
				headers := map[string]string{"Host": tc.host, "User-Agent": tc.ua, "Sec-Fetch-Dest": "empty", "Accept": "application/json"}
				resp := req(t, method, site+tc.prefix+"/ordered/items", headers, strings.NewReader("machine-operation=fixture"))
				body := bodyOf(t, resp)
				if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Hostname:") || (method == http.MethodPost && !strings.Contains(body, "machine-operation=fixture")) {
					t.Fatalf("%s exempt endpoint: %d %s", method, resp.StatusCode, body)
				}
				if after := backendCount(t); after != before+1 {
					t.Fatalf("backend count = %d, want %d", after, before+1)
				}
			}
			before := backendCount(t)
			resp := get(t, tc.prefix+"/ordered/secret", tc.host, tc.ua, nil)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("later deny: %d, want 403", resp.StatusCode)
			}
			if after := backendCount(t); after != before {
				t.Fatalf("denied request reached backend: %d -> %d", before, after)
			}
			var out struct {
				Decisions []struct {
					Host         string `json:"host"`
					Action       string `json:"action"`
					Reason       string `json:"reason"`
					PoWExemption string `json:"pow_exemption"`
				} `json:"decisions"`
			}
			response := adminReq(t, http.MethodGet, "/admin/decisions?host="+tc.host, nil)
			if err := json.UnmarshalRead(response.Body, &out); err != nil {
				t.Fatal(err)
			}
			if len(out.Decisions) == 0 || out.Decisions[0].Action != "deny" || out.Decisions[0].Reason != "waf:fixture-deny" || out.Decisions[0].PoWExemption != tc.exemption {
				t.Fatalf("final diagnostics = %+v", out)
			}

			// A WAF block is recorded and then rejects a safe exempt path too.
			resp = get(t, tc.prefix+"/ordered/scanner", tc.host, tc.ua, nil)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("later block: %d, want 403", resp.StatusCode)
			}
			ip, reason := findBlockedGateway(t)
			if ip == "" || reason != "waf:fixture-block" {
				t.Fatalf("block = %s/%s", ip, reason)
			}
			if resp := get(t, tc.prefix+"/items", tc.host, tc.ua, nil); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("existing block bypassed: %d", resp.StatusCode)
			}
			clearGatewayBlocks()
			blockIP(t, ip, "fixture-admin")
			if resp := get(t, tc.prefix+"/items", tc.host, tc.ua, nil); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("admin block bypassed: %d", resp.StatusCode)
			}
			clearGatewayBlocks()
			if resp := get(t, tc.prefix+"/trap", tc.host, tc.ua, nil); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("honeypot bypassed: %d", resp.StatusCode)
			}
			clearGatewayBlocks()
		})
	}
	// Narrow challenge-delivery routes retain WAF while reaching their endpoint.
	resp := get(t, "/.well-known/acme-challenge/fixture", powHost, "machine-client/1.0", nil)
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Hostname:") {
		t.Fatalf("ACME delivery route: %d %s", resp.StatusCode, body)
	}
	if resp := get(t, "/.well-known/acme-challenge/wp-login.php", powHost, "machine-client/1.0", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ACME path concealed WAF: %d", resp.StatusCode)
	}
}
