// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"testing"

	"github.com/melroy89/angie-guardian/core/store"
)

// Invoke the overload gate directly: no burst or scheduler timing decides
// whether the fast path runs. Its diagnostic result must retain the existing
// verdict while avoiding every shared-store operation, including event writes.
func TestShedDecisionReasons(t *testing.T) {
	ops := &botShedOps{}
	raw := &botShedStore{Store: store.NewMemory()}
	e := allowlistExemptionEngineWithStore(t, true, false, store.Instrument(raw, ops))
	attachSeededBotMirror(t, e)
	tokenRequest := sourceRequest("none", "items")
	token := mintTestToken(t, e.pow, tokenRequest.Host, tokenRequest.RemoteAddr, tokenRequest.UserAgent, 4)
	tokenRequest.Cookie = "guardian_token=" + token
	if d := e.Evaluate(t.Context(), tokenRequest); d.Reason != "pow:token" {
		t.Fatalf("warm token path = %+v", d)
	}
	raw.fail = true
	for _, tc := range []struct {
		name, suffix, ip, ua, cookie string
		verdict                      ShedVerdict
		reason                       string
	}{
		{"shed", "items", "198.51.100.42", "curl", "", ShedReject, "admission:max_inflight"},
		{"challenge-sheds", "challenge", "198.51.100.42", "curl", "", ShedReject, "admission:max_inflight"},
		{"waf-pass", "explicit-allow", "198.51.100.42", "curl", "", ShedPass, "waf:explicit-allow"},
		{"token-pass", "items", "198.51.100.42", "curl", "guardian_token=" + token, ShedPass, "pow:token"},
		{"waf-deny", "secret", "198.51.100.42", "curl", "", ShedDeny, "waf:deny-secret"},
		{"waf-block", "scanner", "198.51.100.42", "curl", "", ShedDeny, "waf:block-scanner"},
		{"honeypot", "trap", "198.51.100.42", "curl", "", ShedDeny, "honeypot:path"},
		{"denylist-ip", "items", "198.51.100.66", "curl", "", ShedDeny, "denylist:ip"},
		{"denylist-ua", "items", "198.51.100.42", "DeniedClient", "", ShedDeny, "denylist:ua"},
		{"denylist-path", "deny-path", "198.51.100.42", "curl", "", ShedDeny, "denylist:path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeRequest := func() *RequestContext {
				r := req("site.test", tc.ip, "/"+tc.suffix, tc.ua)
				r.Cookie = tc.cookie
				return r
			}
			before := ops.calls.Load()
			verdict, reason := e.ShedDecisionWithReason(makeRequest())
			if verdict != tc.verdict || reason != tc.reason {
				t.Fatalf("overload = %v/%q, want %v/%q", verdict, reason, tc.verdict, tc.reason)
			}
			if got := e.ShedDecision(makeRequest()); got != verdict {
				t.Fatalf("compatibility wrapper changed verdict: %v != %v", got, verdict)
			}
			if ops.calls.Load() != before {
				t.Fatal("overload diagnostics accessed the shared store")
			}
		})
	}
}

func TestShedDecisionIntelReasons(t *testing.T) {
	e, _ := intelEngine(t)
	for _, tc := range []struct{ name, ip, reason string }{
		{"reputation-v4", "100.64.7.1", "reputation:bad-actors"},
		{"reputation-v6", "2001:db8:bad::1", "reputation:bad-actors"},
		{"geo-v4", "203.0.113.5", "geo:country:RU"},
		{"geo-v6", "2001:db8:f00d::1", "geo:country:RU"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason := e.ShedDecisionWithReason(req("x.test", tc.ip, "/", "Mozilla/5.0"))
			if verdict != ShedDeny || reason != tc.reason {
				t.Fatalf("overload intel = %v/%q, want deny/%q", verdict, reason, tc.reason)
			}
		})
	}
}
