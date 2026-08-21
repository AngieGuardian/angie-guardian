// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/prometheus/client_model/go"
)

func headerExemptionEngine(t *testing.T) *Engine {
	t.Helper()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(`
rules:
  - { id: deny-env, action: deny, keywords: [ "/.env" ] }
  - { id: challenge-sqli, action: challenge, keywords: [ "union-select" ] }
  - { id: block-scanner, action: block, targets: [ ua ], keywords: [ "sqlmap" ] }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, fmt.Sprintf(`
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: false }
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
    rules: { enabled: true, files: [ %q ] }
    honeypot: { enabled: true, paths: [ "/trap" ] }
  denylist: { ips: [ "203.0.113.0/24" ] }
domains:
  site.test:
    pow: { enabled: true, base_difficulty: 1, max_difficulty: 6 }
    paths:
      "/api/v1/":
        pow:
          header_exemptions:
            - { header: Authorization, prefix: "Bearer ", require_value: true, max_length: 128 }
            - { header: X-API-Key, require_value: true, max_length: 64 }
            - { header: X-Widget-Proof, prefix: "Widget ", require_value: true, max_length: 64 }
`, rules))
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "pow.key"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func exemptionRequest(host, ip, uri, ua, header string, values ...string) *RequestContext {
	r := req(host, ip, uri, ua)
	r.Header = func(name string) []string {
		if equalFoldASCII(name, header) {
			return values
		}
		return nil
	}
	return r
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func TestHeaderPoWExemptionPipelineSemantics(t *testing.T) {
	e := headerExemptionEngine(t)
	ctx := context.Background()

	cases := []struct {
		name   string
		req    *RequestContext
		action Action
		reason string
	}{
		{"missing follows normal challenge", req("site.test", "198.51.100.1", "/api/v1/items", "curl"), ActionChallenge, reasonNoToken},
		{"bearer shape skips only pow", exemptionRequest("site.test", "198.51.100.2", "/api/v1/items", "curl", "authorization", "Bearer opaque"), ActionAllow, "default"},
		{"api key example", exemptionRequest("site.test", "198.51.100.3", "/api/v1/items", "curl", "X-API-Key", "opaque"), ActionAllow, "default"},
		{"arbitrary header example", exemptionRequest("site.test", "198.51.100.4", "/api/v1/items", "curl", "x-widget-proof", "Widget opaque"), ActionAllow, "default"},
		{"outside path remains challenged", exemptionRequest("site.test", "198.51.100.5", "/page", "curl", "X-API-Key", "opaque"), ActionChallenge, reasonNoToken},
		{"empty does not match", exemptionRequest("site.test", "198.51.100.6", "/api/v1/items", "curl", "X-API-Key", ""), ActionChallenge, reasonNoToken},
		{"duplicate does not match", exemptionRequest("site.test", "198.51.100.7", "/api/v1/items", "curl", "X-API-Key", "one", "two"), ActionChallenge, reasonNoToken},
		{"denylist still wins", exemptionRequest("site.test", "203.0.113.7", "/api/v1/items", "curl", "X-API-Key", "opaque"), ActionDeny, "denylist:ip"},
		{"honeypot still wins", exemptionRequest("site.test", "198.51.100.8", "/trap", "curl", "X-API-Key", "opaque"), ActionDeny, "honeypot:path"},
		{"waf deny still wins", exemptionRequest("site.test", "198.51.100.9", "/api/v1/.env", "curl", "X-API-Key", "opaque"), ActionDeny, "waf:deny-env"},
		{"waf block still wins", exemptionRequest("site.test", "198.51.100.10", "/api/v1/items", "sqlmap", "X-API-Key", "opaque"), ActionDeny, "waf:block-scanner"},
		{"waf challenge is suppressed", exemptionRequest("site.test", "198.51.100.11", "/api/v1/union-select", "curl", "X-API-Key", "opaque"), ActionAllow, "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(ctx, tc.req)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
		})
	}

	blocked := exemptionRequest("site.test", "198.51.100.12", "/api/v1/items", "curl", "X-API-Key", "opaque")
	if err := e.BlockIP(ctx, blocked.RemoteAddr, "test", time.Minute); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, blocked); d.Action != ActionDeny || d.Reason != "behaviour_block:test" {
		t.Fatalf("behavioural block with exemption = %s/%s", d.Action, d.Reason)
	}
}

func TestHeaderPoWExemptionDoesNotPassShed(t *testing.T) {
	e := headerExemptionEngine(t)
	r := exemptionRequest("site.test", "198.51.100.20", "/api/v1/items", "curl", "X-API-Key", "opaque")
	if got := e.ShedDecision(r); got != ShedReject {
		t.Fatalf("shape-only marker shed verdict = %v, want ShedReject", got)
	}
	challengeRule := exemptionRequest("site.test", "198.51.100.21", "/api/v1/union-select", "curl", "X-API-Key", "opaque")
	if got := e.ShedDecision(challengeRule); got != ShedReject {
		t.Fatalf("challenge-rule marker shed verdict = %v, want ShedReject", got)
	}
}

func TestHeaderPoWExemptionMetricsAreBounded(t *testing.T) {
	e := headerExemptionEngine(t)
	m := metrics.New("memory")
	e.SetMetrics(m)
	e.Evaluate(t.Context(), exemptionRequest("site.test", "198.51.100.30", "/api/v1/items", "curl", "X-API-Key", "opaque"))
	e.Evaluate(t.Context(), exemptionRequest("site.test", "198.51.100.31", "/api/v1/items", "curl", "X-API-Key", "one", "two"))

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"matched/none": false, "ambiguous/none": false}
	for _, family := range families {
		if family.GetName() != "guardian_pow_header_exemptions_total" {
			continue
		}
		for _, sample := range family.GetMetric() {
			labels := metricLabels(sample)
			key := labels["outcome"] + "/" + labels["verifier"]
			if _, ok := want[key]; ok && sample.GetCounter().GetValue() == 1 {
				want[key] = true
			}
			if _, leaked := labels["header"]; leaked {
				t.Fatal("metric exposed configured header name")
			}
		}
	}
	for series, found := range want {
		if !found {
			t.Errorf("missing metric series %s", series)
		}
	}
}

func metricLabels(sample *io_prometheus_client.Metric) map[string]string {
	labels := make(map[string]string, len(sample.GetLabel()))
	for _, label := range sample.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}
