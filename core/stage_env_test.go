// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"sync"
	"testing"
)

// Mix full and overload evaluations, including both positive and negative
// token/exemption decisions. Reused environments must never grant the next
// request a previous request's authorization.
func TestStageEnvConcurrentDecisionIsolation(t *testing.T) {
	e := allowlistExemptionEngine(t, true, false)
	r := sourceRequest("none", "items")
	cookie := "guardian_token=" + mintTestToken(t, e.pow, r.Host, r.RemoteAddr, r.UserAgent, 4)
	var wg sync.WaitGroup
	for worker := range 24 {
		wg.Go(func() {
			for iteration := range 100 {
				switch (worker + iteration) % 6 {
				case 0:
					r := sourceRequest("none", "items")
					r.Cookie = cookie
					if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.Reason != "pow:token" || d.PoWExemption != "" {
						t.Errorf("token authorization = %+v", d)
					}
				case 1:
					if d := e.Evaluate(t.Context(), sourceRequest("none", "items")); d.Action != ActionChallenge || d.Reason != reasonNoToken || d.PoWExemption != "" {
						t.Errorf("anonymous authorization inherited a decision: %+v", d)
					}
				case 2:
					if d := e.Evaluate(t.Context(), sourceRequest("ua", "items")); d.Action != ActionAllow || d.PoWExemption != "allowlist:ua" {
						t.Errorf("UA exemption = %+v", d)
					}
				case 3:
					r := sourceRequest("none", "items")
					r.Cookie = cookie
					if v, reason := e.ShedDecisionWithReason(r); v != ShedPass || reason != "pow:token" {
						t.Errorf("overload token = %v/%s", v, reason)
					}
				case 4, 5:
					source := "none"
					if (worker+iteration)%6 == 5 {
						source = "ua"
					}
					if v, reason := e.ShedDecisionWithReason(sourceRequest(source, "items")); v != ShedReject || reason != "admission:max_inflight" {
						t.Errorf("overload inherited a token or exemption: %v/%s", v, reason)
					}
				}
			}
		})
	}
	wg.Wait()
}
