// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/store"
)

func TestExemptionDecisionDiagnostics(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(`rules:
 - { id: challenge-first, action: challenge, keywords: [ secret ] }
 - { id: deny-secret, action: deny, keywords: [ secret ] }
`), 0600); err != nil {
		t.Fatal(err)
	}
	var logbuf bytes.Buffer
	ts, h := testServerAndHandlerWithStoreAndLogger(t, fmt.Sprintf(`
store: { backend: memory }
signing_key_file: test.key
defaults:
 pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
 allowlist: { uas: [ FixtureMachine ] }
 waf: { rules: { enabled: true, files: [ %q ] } }
`, rules), store.NewMemory(), nil, slog.New(slog.NewJSONHandler(&logbuf, nil)))
	for _, suffix := range []string{"items", "secret"} {
		headers := guardianHeaders("example.test", "198.51.100.42", "/"+suffix, "FixtureMachine/1.0")
		headers["X-Guardian-Method"] = "POST"
		headers["Sec-Fetch-Dest"] = "empty"
		headers["X-Guardian-Action"] = "allow"
		headers["X-Guardian-Reason"] = "allowlist:ua"
		resp := do(t, "GET", ts.URL+"/auth", headers, nil)
		action, reason, status := "allow", "default", http.StatusOK
		if suffix == "secret" {
			action, reason, status = "deny", "waf:deny-secret", http.StatusForbidden
		}
		if resp.StatusCode != status || resp.Header.Get("X-Guardian-Action") != action || resp.Header.Get("X-Guardian-Reason") != reason {
			t.Fatalf("auth outcome %s: %d %v", suffix, resp.StatusCode, resp.Header)
		}
		var decision map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(logbuf.String())), &decision); err != nil {
			t.Fatal(err, logbuf.String())
		}
		if decision["action"] != action || decision["reason"] != reason || decision["pow_exemption"] != "allowlist:ua" {
			t.Fatalf("decision log = %v", decision)
		}
		logbuf.Reset()
	}
	rows := h.engine.RecentDecisions(0)
	var wire []core.RecentDecision
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != 1 || wire[0].Reason != "waf:deny-secret" || wire[0].PoWExemption != "allowlist:ua" || !bytes.Contains(body, []byte(`"pow_exemption":"allowlist:ua"`)) {
		t.Fatalf("admin diagnostics JSON = %s", body)
	}
}
