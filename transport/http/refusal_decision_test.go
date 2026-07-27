// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/melroy89/angie-guardian/core"
)

// TestAuthRecordsRefusalForUnchallengeableRequest covers the auth half of the
// favicon incident: the browser's favicon service fetches /favicon.ico on an
// anonymous channel, so the request arrives with no cookie, no Sec-Fetch-*
// even over HTTPS, and Accept: */*. It cannot present a token and cannot run
// the interstitial, so the challenge handler refuses it. Before this, /auth
// still recorded "challenge / pow:no_token" for it, and an operator reading
// /admin/decisions saw a challenge storm that never happened.
//
// The status must stay 401. Angie routes on the status code, so a refusal has
// to land in @guardian_challenge exactly as a challenge does, which is what
// keeps the wire behaviour and every operator's config unchanged.
func TestAuthRecordsRefusalForUnchallengeableRequest(t *testing.T) {
	ts := testServer(t)

	anon := guardianHeaders("html.test", "198.51.100.21", "/favicon.ico", "Mozilla/5.0")
	anon["Accept"] = "*/*"
	resp := do(t, "GET", ts.URL+"/auth", anon, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 so Angie still routes to @guardian_challenge",
			resp.StatusCode)
	}
	if got := resp.Header.Get("X-Guardian-Action"); got != "refuse" {
		t.Errorf("action = %q, want refuse", got)
	}
	if got := resp.Header.Get("X-Guardian-Reason"); got != "pow:unchallengeable" {
		t.Errorf("reason = %q, want pow:unchallengeable", got)
	}
	// No challenge is issued, so there is no difficulty for Angie to relay.
	if got := resp.Header.Get(hdrDifficulty); got != "" {
		t.Errorf("difficulty = %q, want it absent on a refusal", got)
	}

	// Control: the same request that does look like a navigation must still be
	// challenged, difficulty and all. Without this the test above would pass
	// just as well if the refusal swallowed every request on the host.
	nav := guardianHeaders("html.test", "198.51.100.22", "/", "Mozilla/5.0")
	nav["Accept"] = "text/html,application/xhtml+xml"
	resp = do(t, "GET", ts.URL+"/auth", nav, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("navigation status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Guardian-Action"); got != "challenge" {
		t.Errorf("navigation action = %q, want challenge", got)
	}
	if got := resp.Header.Get(hdrDifficulty); got == "" {
		t.Error("navigation carried no difficulty header")
	}
}

const refusalRollbackYAML = `
store: { backend: memory }
signing_key_file: test-signing.key
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
    paths:
      "/rollback":
        pow: { refuse_unchallengeable: false }
`

// TestChallengeHandlerHonoursTheRollbackKey covers the challenge hop's half of
// the opt-out, on the path it takes when Angie relays no verdict: an operator
// whose config predates the auth_request_set line, which is every deployment
// until it is added. The auth hop's half is pinned in core, and both together
// are covered end to end in test/e2e, but that suite is gated to protected refs
// and so does not run on a merge request. Without this, a regression that made
// the handler ignore the key would pass every check an MR actually runs and
// only surface after it landed on main.
//
// The failure it guards against is specific: if the handler refuses while the
// auth hop, reading the same key, recorded a challenge, the decision log again
// disagrees with the wire. That is the drift the config key exists to make
// impossible, in the opposite direction to the one that started all this.
func TestChallengeHandlerHonoursTheRollbackKey(t *testing.T) {
	ts := testServerWithYAML(t, refusalRollbackYAML)

	// Anonymous, no Fetch metadata, Accept: */*. Refused everywhere on this host
	// except the path that opted out.
	anon := func(uri string) map[string]string {
		h := guardianHeaders("html.test", "198.51.100.31", uri, "Mozilla/5.0")
		h["Accept"] = "*/*"
		return h
	}

	resp := do(t, "GET", ts.URL+"/challenge", anon("/rollback"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("opted-out path: status %d, want 200 interstitial", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("guardian-data")) {
		t.Fatalf("opted-out path did not get the interstitial; body:\n%s", body)
	}

	// Control: the same request one path over is still refused, so the overlay
	// is scoped rather than the key being ignored everywhere.
	other := do(t, "GET", ts.URL+"/challenge", anon("/elsewhere"), nil)
	if other.StatusCode != http.StatusForbidden {
		t.Errorf("unscoped path: status %d, want 403", other.StatusCode)
	}
}

// refuseKeyYAML builds a config differing from the next only in the switch, so
// a reload between the two swaps exactly one thing.
func refuseKeyYAML(on bool) string {
	return fmt.Sprintf(`
store: { backend: memory }
signing_key_file: test-signing.key
domains:
  html.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6, refuse_unchallengeable: %t }
`, on)
}

func loadConfigFromYAML(t *testing.T, yaml string) *core.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestRefusalVerdictSurvivesAReloadBetweenTheHops covers the one gap the config
// key alone left open. Both hops read the key, but they read it at different
// moments: /auth resolves it from the snapshot live when the auth subrequest
// runs, and @guardian_challenge from the snapshot live when the follow-up runs.
// Toggling the key in that gap made one hop refuse while the other issued.
//
// Both directions were reproduced before the relay existed: with the key on and
// then off, /auth logged refuse / pow:unchallengeable and the next hop served a
// 200 interstitial; off and then on, /auth logged challenge / pow:no_token and
// the next hop served a 403. Either way the record described a response nobody
// received, which is the whole failure this MR exists to remove, arriving
// through a different door.
//
// Neither the steady-state unit tests nor the e2e suite can catch it, because
// catching it requires reloading between two requests of one client request.
func TestRefusalVerdictSurvivesAReloadBetweenTheHops(t *testing.T) {
	cases := []struct {
		name       string
		start      bool
		reloadTo   bool
		wantAction string
		wantStatus int
		why        string
	}{
		{
			name: "switched off between the hops", start: true, reloadTo: false,
			wantAction: "refuse", wantStatus: http.StatusForbidden,
			why: "the refusal was recorded, so the refusal must be served",
		},
		{
			name: "switched on between the hops", start: false, reloadTo: true,
			wantAction: "challenge", wantStatus: http.StatusOK,
			why: "the challenge was recorded, so the interstitial must be served",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, srv := testServerAndHandler(t, refuseKeyYAML(tc.start))

			// The favicon request the incident was about: anonymous, no Fetch
			// metadata, Accept: */*.
			h := guardianHeaders("html.test", "198.51.100.41", "/favicon.ico", "Mozilla/5.0")
			h["Accept"] = "*/*"

			auth := do(t, "GET", ts.URL+"/auth", h, nil)
			if auth.StatusCode != http.StatusUnauthorized {
				t.Fatalf("auth status = %d, want 401", auth.StatusCode)
			}
			if got := auth.Header.Get("X-Guardian-Action"); got != tc.wantAction {
				t.Fatalf("recorded action = %q, want %q", got, tc.wantAction)
			}

			// Exactly what Angie carries across: auth_request_set captures the
			// auth response headers and proxy_set_header replays them on the
			// request into @guardian_challenge.
			next := maps.Clone(h)
			next[hdrRefusal] = auth.Header.Get(hdrRefusal)
			next[hdrDifficulty] = auth.Header.Get(hdrDifficulty)

			// The operator reloads while the client is between the two hops.
			if err := srv.engine.Reload(loadConfigFromYAML(t, refuseKeyYAML(tc.reloadTo))); err != nil {
				t.Fatal(err)
			}

			resp := do(t, "GET", ts.URL+"/challenge", next, nil)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("challenge status = %d, want %d: %s",
					resp.StatusCode, tc.wantStatus, tc.why)
			}
		})
	}
}

// TestChallengeHopDecidesLocallyWithoutARelay pins the fallback for an Angie
// config older than the auth_request_set line above, which is every deployment
// on the first daemon restart after upgrading. No relay must mean the previous
// behaviour exactly, not a refusal that stops happening.
func TestChallengeHopDecidesLocallyWithoutARelay(t *testing.T) {
	ts := testServerWithYAML(t, refuseKeyYAML(true))

	h := guardianHeaders("html.test", "198.51.100.42", "/favicon.ico", "Mozilla/5.0")
	h["Accept"] = "*/*"
	if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("no relay: status = %d, want 403 from the local decision", resp.StatusCode)
	}

	// An unrecognized value is not a licence to skip the local decision. It
	// reads as "nothing was relayed", so the refusal still happens.
	h[hdrRefusal] = "yes-please"
	if resp := do(t, "GET", ts.URL+"/challenge", h, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("garbage relay: status = %d, want 403 from the local decision", resp.StatusCode)
	}
}

// TestRefusalKindMatchesTheChallengeHandler pins that the auth path and the
// challenge handler answer one question with one predicate. They run on
// separate requests from Angie, so a drift between them would mean recording a
// refusal and then serving a challenge, or the reverse, with nothing failing.
func TestRefusalKindMatchesTheChallengeHandler(t *testing.T) {
	cases := []struct {
		name string
		hdr  map[string]string
		want string
		why  string
	}{
		{"anonymous favicon fetch", map[string]string{"Accept": "*/*"},
			outcomeAcceptRefused,
			"no Fetch metadata at all, which is what the favicon service sends"},
		{"declared subresource", map[string]string{"Sec-Fetch-Dest": "image", "Accept": "image/png"},
			outcomeSubresourceRefused,
			"the destination settles it before Accept is consulted"},
		{"ordinary navigation", map[string]string{
			"Sec-Fetch-Dest": "document", "Accept": "text/html"},
			"", "a document destination keeps the ordinary challenge path"},
		{"navigation by mode alone", map[string]string{
			"Sec-Fetch-Mode": "navigate", "Accept": "*/*"},
			"", "mode is an independent navigation signal and exempts on its own"},
		{"no headers at all", map[string]string{},
			"", "absent Accept says nothing, so the ordinary path is kept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tc.hdr {
				h.Set(k, v)
			}
			if got := refusalKind(h); got != tc.want {
				t.Errorf("refusalKind = %q, want %q (%s)", got, tc.want, tc.why)
			}
		})
	}
}
