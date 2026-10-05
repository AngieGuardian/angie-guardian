// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/health"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	httptransport "github.com/melroy89/angie-guardian/transport/http"
)

func invoke(args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := run(args, &out, &err)
	return code, out.String(), err.String()
}
func writeFile(t *testing.T, name, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func apiArgs(t *testing.T, url string) []string {
	t.Helper()
	return []string{"--endpoint", url, "--token-file", writeFile(t, "token", "test-secret\n")}
}

func TestCommandContracts(t *testing.T) {
	cases := []struct {
		args                         []string
		method, path, response, want string
	}{
		{[]string{"block", "::ffff:203.0.113.9", "--reason", "manual abuse", "--ttl", "2d"}, "PUT", "/admin/blocks/203.0.113.9", `{"ip":"203.0.113.9","blocked":true,"reason":"manual abuse","ttl":"48h0m0s"}`, "Blocked 203.0.113.9"},
		{[]string{"block", "2001:db8::9"}, "PUT", "/admin/blocks/2001:db8::9", `{"ip":"2001:db8::9","blocked":true}`, "Blocked"},
		{[]string{"unblock", "2001:db8::9"}, "DELETE", "/admin/blocks/2001:db8::9?reset_backoff=true", `{"ip":"2001:db8::9","blocked":false,"reset":{"backoff_reset":true,"event_keys":2,"escalation_keys":1}}`, "reset.backoff_reset"},
		{[]string{"unblock", "203.0.113.9", "--keep-backoff"}, "DELETE", "/admin/blocks/203.0.113.9?reset_backoff=false", `{"ip":"203.0.113.9","blocked":false,"reset":{"incomplete":true}}`, "WARNING: counter reset incomplete"},
		{[]string{"status", "2001:db8::9"}, "GET", "/admin/blocks/2001:db8::9", `{"ip":"2001:db8::9","blocked":false}`, "not blocked"},
		{[]string{"list", "--limit", "10000"}, "GET", "/admin/blocks?limit=10000", `{"count":1,"complete":false,"blocks":[{"ip":"203.0.113.9","reason":"abuse","expires_at":"2026-10-06T01:00:00Z"}]}`, "WARNING: incomplete list"},
		{[]string{"stats"}, "GET", "/admin/stats", `{"blocks_active":12,"blocks_complete":false}`, "blocks_active"},
		{[]string{"decisions", "--ip", "::ffff:203.0.113.9", "--limit", "25"}, "GET", "/admin/decisions?limit=25&ip=203.0.113.9", `{"count":1,"truncated":true,"window":{"capacity":4096},"decisions":[{"ip":"203.0.113.9","action":"deny","reason":"waf:probe"}]}`, "WARNING: results truncated"},
		{[]string{"offenders"}, "GET", "/admin/offenders", `{"window":12,"ips":[{"ip":"203.0.113.9","count":12}]}`, "203.0.113.9"},
		{[]string{"config", "show"}, "GET", "/admin/config", `{"store":"memory","domains":{"shop.test":{"pow_enabled":true}}}`, "domains.shop.test.pow_enabled"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.RequestURI() != tc.path {
					t.Errorf("request %s %s", r.Method, r.URL.RequestURI())
				}
				if r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Error("missing auth")
				}
				if tc.method == "PUT" {
					var body map[string]string
					if err := json.UnmarshalRead(r.Body, &body); err != nil {
						t.Error(err)
					}
					if len(tc.args) > 2 && body["ttl"] != "2d" {
						t.Errorf("body: %v", body)
					}
				}
				io.WriteString(w, tc.response)
			}))
			defer srv.Close()
			args := append(apiArgs(t, srv.URL), tc.args...)
			code, out, err := invoke(args...)
			if code != 0 || err != "" || !strings.Contains(out, tc.want) || calls != 1 {
				t.Fatalf("code %d out %s err %s calls %d", code, out, err, calls)
			}
			code, out, err = invoke(append(args, "--json")...)
			var result map[string]any
			if code != 0 || json.Unmarshal([]byte(out), &result) != nil {
				t.Fatalf("JSON: %d %s %s", code, out, err)
			}
		})
	}
}

func TestInvalidInput(t *testing.T) {
	for _, args := range [][]string{{"wat"}, {"block"}, {"status", "bad"}, {"unblock", "fe80::1%eth0"}, {"block", "203.0.113.9", "--ttl", "0s"}, {"block", "203.0.113.9", "--ttl", "2y"}, {"block", "203.0.113.9", "--reason", "bad\nreason"}, {"list", "--limit", "10001"}, {"list", "--limit", "0"}, {"decisions", "--limit", "bad"}, {"decisions", "--ip", "bad"}, {"reload", "extra"}, {"config"}, {"stats", "--ttl", "2h"}, {"stats", "--timeout", "0"}, {"stats", "--timeout", "2m"}, {"--token-file"}} {
		code, _, err := invoke(args...)
		if code != 2 || err == "" {
			t.Errorf("%v: %d %s", args, code, err)
		}
	}
	for _, args := range [][]string{nil, {"--help"}, {"block", "--help"}, {"config", "show", "--help"}, {"--version"}} {
		code, out, err := invoke(args...)
		if code != 0 || out == "" || err != "" {
			t.Errorf("%v: %d %s %s", args, code, out, err)
		}
	}
}

func TestReload(t *testing.T) {
	for _, tc := range []struct {
		name              string
		check, reloadable bool
		status            int
		code, posts       int
	}{{"check", true, true, 200, 0, 0}, {"apply", false, true, 200, 0, 1}, {"restart", false, false, 200, 1, 0}, {"invalid", false, false, 422, 1, 0}, {"apply rejected", false, true, 422, 1, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			posts := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/reload/preflight" {
					if !tc.reloadable && tc.status == 422 {
						w.WriteHeader(422)
						io.WriteString(w, `{"error":"secret config fragment"}`)
						return
					}
					json.MarshalWrite(w, map[string]any{"reloadable": tc.reloadable, "restart_required": []string{"listen"}})
					return
				}
				if r.Method != "POST" || r.URL.Path != "/admin/reload" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				posts++
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					io.WriteString(w, `{"reloaded":true}`)
				} else {
					io.WriteString(w, `{"error":"secret config fragment"}`)
				}
			}))
			defer srv.Close()
			args := append(apiArgs(t, srv.URL), "reload", "--json")
			if tc.check {
				args = append(args, "--check")
			}
			code, out, err := invoke(args...)
			if code != tc.code || posts != tc.posts || strings.Contains(out+err, "secret config fragment") {
				t.Fatalf("%d %s %s posts %d", code, out, err, posts)
			}
		})
	}
}

func TestFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   int
	}{{401, `{"error":"unauthorized"}`, 3}, {403, `{}`, 3}, {500, `{"error":"test-secret\u001b[2Jbad"}`, 1}, {200, `broken`, 1}, {200, `null`, 1}, {302, `{}`, 1}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://127.0.0.1:1")
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}))
		code, out, err := invoke(append(apiArgs(t, srv.URL), "stats")...)
		srv.Close()
		if code != tc.code || strings.Contains(out+err, "test-secret") || strings.Contains(err, "\x1b") {
			t.Fatalf("%+v: %d %s %s", tc, code, out, err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		io.WriteString(w, `{}`)
	}))
	args := append(apiArgs(t, srv.URL), "stats", "--timeout", "1ms")
	code, _, _ := invoke(args...)
	if code != 4 {
		t.Fatalf("timeout code %d", code)
	}
	srv.Close()
	code, _, _ = invoke(args...)
	if code != 4 {
		t.Fatalf("connection code %d", code)
	}
}

func TestHealth(t *testing.T) {
	for _, ready := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("health must not send credentials")
			}
			if r.URL.Path == "/healthz" {
				io.WriteString(w, "ok\n")
				return
			}
			if !ready {
				w.WriteHeader(503)
			}
			json.MarshalWrite(w, map[string]any{"ready": ready, "reason": "store_unavailable"})
		}))
		code, out, err := invoke("health", "--endpoint", srv.URL, "--json")
		srv.Close()
		var result map[string]any
		if json.Unmarshal([]byte(out), &result) != nil {
			t.Fatal(out)
		}
		if result["liveness"].(map[string]any)["ok"] != true || result["readiness"].(map[string]any)["ok"] != ready || (ready && code != 0) || (!ready && code != 1) {
			t.Fatalf("ready %v: %d %s %s", ready, code, out, err)
		}
	}
}

func TestCredentialDiscovery(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "")
	tokenFile := writeFile(t, "token", "file-secret\n")
	config := writeFile(t, "guardian.yaml", "admin:\n  listen: 0.0.0.0:8072\n  token_file: "+tokenFile+"\nstore: { backend: broken }\n")
	c, err := newClient(options{config: config, timeout: time.Second}, true)
	if err != nil || c.endpoint != "http://127.0.0.1:8072" || c.token != "file-secret" {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("ADMIN_TOKEN", "env-secret")
	c, err = newClient(options{config: config, timeout: time.Second}, true)
	if err != nil || c.token != "env-secret" {
		t.Fatalf("env: %+v %v", c, err)
	}
	config = writeFile(t, "guardian.yaml", "admin: {listen: '[::]:8072', token: configured-secret}")
	c, err = newClient(options{config: config, timeout: time.Second}, true)
	if err != nil || c.token != "configured-secret" || c.endpoint != "http://[::1]:8072" {
		t.Fatalf("configured: %+v %v", c, err)
	}
	c, err = newClient(options{config: config, tokenFile: tokenFile, timeout: time.Second}, true)
	if err != nil || c.token != "file-secret" {
		t.Fatalf("override: %+v %v", c, err)
	}
	bad := writeFile(t, "guardian.yaml", "admin: [\nsecret: secret-text")
	c, err = newClient(options{config: bad, endpoint: "http://127.0.0.1:8072", tokenFile: tokenFile, timeout: time.Second}, true)
	if err != nil || c.token != "file-secret" {
		t.Fatalf("recovery: %+v %v", c, err)
	}
	t.Setenv("ADMIN_TOKEN", "")
	for _, o := range []options{{config: bad}, {config: "/missing"}, {config: config, tokenFile: "/missing"}, {endpoint: "http://user:secret@localhost", tokenFile: tokenFile}, {endpoint: "http://localhost/admin", tokenFile: tokenFile}, {endpoint: "http://localhost?token=secret", tokenFile: tokenFile}, {endpoint: "file:///tmp/socket", tokenFile: tokenFile}, {endpoint: "http://localhost", tokenFile: writeFile(t, "empty", "")}} {
		_, err := newClient(o, true)
		if err == nil || strings.Contains(err.Error(), "secret-text") {
			t.Fatalf("%+v: %v", o, err)
		}
	}
}

// Exercise actual auth, validation, store mutations and reporting through the
// daemon's handler; no mock store edits stand in for the operator commands.
func TestRealAdminAPI(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "")
	dir := t.TempDir()
	cfgPath := writeFile(t, "guardian.yaml", "store: {backend: memory}\ndefaults:\n  waf:\n    ip_behaviour: {enabled: true, thresholds: {pow_fail: 3/min}}\n")
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	defer st.Close()
	keyPath := filepath.Join(dir, "key")
	key, err := pow.LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine, err := core.NewEngine(cfg, st, pow.NewManager(key, st), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	hc := health.New(st, "memory", nil, logger)
	hc.Start(context.Background())
	defer hc.Close()
	engine.SetHealth(hc)
	reloads := 0
	admin := httptransport.NewAdminServer(engine, cfg, nil, "test-secret", keyPath, "", func() error { reloads++; return nil }, logger)
	admin.SetPreflight(func() ([]string, error) { return nil, nil })
	srv := httptest.NewServer(admin)
	defer srv.Close()
	base := apiArgs(t, srv.URL)
	for _, ip := range []string{"203.0.113.9", "2001:db8::9"} {
		for step, cmd := range [][]string{{"block", ip, "--ttl", "2d", "--reason", "manual abuse"}, {"status", ip}, {"list", "--limit", "1"}, {"unblock", ip}, {"status", ip}} {
			code, out, err := invoke(append(append([]string{}, base...), append(cmd, "--json")...)...)
			if code != 0 {
				t.Fatalf("%v: %d %s %s", cmd, code, out, err)
			}
			if cmd[0] == "status" {
				var result map[string]any
				if err := json.Unmarshal([]byte(out), &result); err != nil {
					t.Fatal(err)
				}
				if result["blocked"] != (step == 1) {
					t.Fatal(out)
				}
			}
		}
	}
	// Produce a real behavioural ban, then verify both reset modes through CLI.
	for _, keep := range []bool{true, false} {
		ip := "198.51.100.44"
		if !keep {
			ip = "198.51.100.45"
		}
		for range 3 {
			engine.ReportEvent(context.Background(), "shop.test", ip, core.EventPoWFail, "bad nonce")
		}
		detail, err := engine.BlockDetailFor(context.Background(), ip)
		if err != nil || !detail.Blocked || detail.Offenses == nil {
			t.Fatalf("behavioural ban: %+v %v", detail, err)
		}
		cmd := []string{"unblock", ip, "--json"}
		if keep {
			cmd = append(cmd, "--keep-backoff")
		}
		code, out, errText := invoke(append(append([]string{}, base...), cmd...)...)
		if code != 0 {
			t.Fatalf("reset: %d %s %s", code, out, errText)
		}
		var result struct {
			Reset core.UnblockReset `json:"reset"`
		}
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.Reset.BackoffReset == keep || result.Reset.EventKeys == 0 || result.Reset.Incomplete {
			t.Fatalf("reset: %+v", result)
		}
		detail, err = engine.BlockDetailFor(context.Background(), ip)
		if err != nil || detail.Blocked || (!keep && detail.Offenses != nil) || (keep && detail.Offenses == nil) {
			t.Fatalf("after reset: %+v %v", detail, err)
		}
	}
	for _, cmd := range [][]string{{"health"}, {"stats"}, {"decisions"}, {"offenders"}, {"config", "show"}, {"reload", "--check"}, {"reload"}} {
		code, out, err := invoke(append(append([]string{}, base...), cmd...)...)
		if code != 0 || strings.Contains(out, "test-secret") {
			t.Fatalf("%v: %d %s %s", cmd, code, out, err)
		}
	}
	if reloads != 1 {
		t.Fatalf("reloads %d", reloads)
	}
}

func TestUnconfirmedOperations(t *testing.T) {
	for _, cmd := range [][]string{{"block", "203.0.113.9"}, {"unblock", "203.0.113.9"}, {"status", "203.0.113.9"}, {"reload"}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin/reload/preflight" {
				io.WriteString(w, `{"reloadable":true}`)
			} else {
				io.WriteString(w, `{}`)
			}
		}))
		code, out, err := invoke(append(apiArgs(t, srv.URL), cmd...)...)
		srv.Close()
		if code != 1 || out != "" || err == "" {
			t.Fatalf("%v: %d %s %s", cmd, code, out, err)
		}
	}
}

func TestDefaultBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			t.Error(err)
		}
		if body["ttl"] != "" || body["reason"] != "" {
			t.Errorf("defaults overridden: %v", body)
		}
		io.WriteString(w, `{"ip":"203.0.113.9","blocked":true,"reason":"admin","ttl":"24h0m0s"}`)
	}))
	defer srv.Close()
	code, out, err := invoke(append(apiArgs(t, srv.URL), "block", "203.0.113.9")...)
	if code != 0 || !strings.Contains(out, "24h0m0s") || !strings.Contains(out, "admin") {
		t.Fatalf("%d %s %s", code, out, err)
	}
}

func TestTerminalOutput(t *testing.T) {
	var out bytes.Buffer
	render(&out, false, "stats", map[string]any{"evil\x1b[2J": "value\n\x1b[2J"})
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "value\n") {
		t.Fatal(out.String())
	}
}
