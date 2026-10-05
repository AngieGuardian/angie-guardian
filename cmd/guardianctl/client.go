// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/melroy89/angie-guardian/internal/safefile"
	"gopkg.in/yaml.v3"
)

type client struct {
	ctx             context.Context
	http            *http.Client
	endpoint, token string
}

func newClient(o options, authenticated bool) (*client, error) {
	var cfg struct {
		Admin struct {
			Listen, Token string
			TokenFile     string `yaml:"token_file"`
		} `yaml:"admin"`
	}
	// Recovery must not validate unrelated WAF/model/store configuration. Fully
	// specified overrides also work when the on-disk config cannot be parsed.
	needsConfig := o.endpoint == "" || (authenticated && o.tokenFile == "" && os.Getenv("ADMIN_TOKEN") == "")
	if needsConfig {
		raw, err := safefile.Read(o.config, 4<<20)
		if err != nil {
			return nil, fail(2, "cannot read Guardian configuration; check --config or supply --endpoint and --token-file")
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return nil, fail(2, "cannot parse Guardian configuration; supply --endpoint and --token-file for recovery")
		}
	} else if o.tokenFile == "" && authenticated {
		// Match daemon precedence: an available admin.token beats ADMIN_TOKEN.
		raw, err := safefile.Read(o.config, 4<<20)
		if err == nil {
			if yaml.Unmarshal(raw, &cfg) != nil {
				cfg.Admin.Token = ""
			}
		}
	}
	endpoint := o.endpoint
	if endpoint == "" {
		if cfg.Admin.Listen == "" {
			return nil, fail(2, "admin.listen is not configured; supply --endpoint")
		}
		host, port, err := net.SplitHostPort(cfg.Admin.Listen)
		if err != nil {
			return nil, fail(2, "invalid admin.listen; supply --endpoint")
		}
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		} else if host == "::" {
			host = "::1"
		}
		endpoint = "http://" + net.JoinHostPort(host, port)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fail(2, "endpoint must be an http(s) origin for the direct admin listener, without credentials, path, query or fragment")
	}
	token := ""
	if authenticated {
		file := o.tokenFile
		if file == "" {
			token = cfg.Admin.Token
			if token == "" {
				token = os.Getenv("ADMIN_TOKEN")
			}
			if token == "" {
				file = cfg.Admin.TokenFile
			}
		}
		if file != "" {
			raw, err := safefile.Read(file, 64<<10)
			if err != nil {
				return nil, fail(2, "cannot read admin token file; check permissions (installed files usually require sudo)")
			}
			token = strings.TrimSpace(string(raw))
		}
		if token == "" {
			return nil, fail(2, "no admin credential found; configure admin.token_file or supply --token-file / ADMIN_TOKEN")
		}
		if strings.ContainsFunc(token, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
			return nil, fail(2, "admin token contains invalid whitespace or control characters")
		}
	}
	// Never send recovery credentials through environment HTTP proxies or follow
	// a redirect to another listener (including the public protected route).
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &client{ctx: context.Background(), http: &http.Client{Transport: transport, Timeout: o.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: strings.TrimSuffix(endpoint, "/"), token: token}, nil
}

func (c *client) request(method, path string, body any) (map[string]any, error) {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return nil, fail(1, "cannot encode request")
		}
	}
	req, err := http.NewRequestWithContext(c.ctx, method, c.endpoint+path, bytes.NewReader(data))
	if err != nil {
		return nil, fail(2, "invalid admin request")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fail(4, "cannot reach admin listener (connection, TLS or timeout failure); check --endpoint and daemon status")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil {
		return nil, fail(4, "cannot finish reading admin response (connection or timeout failure)")
	}
	if len(raw) > 8<<20 {
		return nil, fail(1, "admin response exceeds 8 MiB size limit")
	}
	result := map[string]any{}
	parseErr := json.Unmarshal(raw, &result)
	if path == "/healthz" && resp.StatusCode == http.StatusOK && strings.TrimSpace(string(raw)) == "ok" {
		result = map[string]any{"alive": true}
		parseErr = nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, c.apiError(resp, path, result)
	}
	if parseErr != nil || result == nil {
		return nil, fail(1, "admin API returned an invalid JSON object")
	}
	return result, nil
}

// Keep API failures consistent across JSON reports and binary downloads.
func (c *client) apiError(resp *http.Response, path string, result map[string]any) error {
	code := 1
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		code = 3
	}
	message, _ := result["error"].(string)
	if message == "" {
		message, _ = result["reason"].(string)
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusUnprocessableEntity && (path == "/admin/reload" || path == "/admin/reload/preflight") {
		message = "configuration rejected; inspect daemon logs locally"
	}
	if path == diagnosticsPath {
		switch resp.StatusCode {
		case http.StatusNotFound:
			if resp.Request != nil && resp.Request.Method == "GET" {
				message = "daemon does not provide the diagnostics API; upgrade Guardian"
			} else {
				message = "diagnostics disabled; set admin.diagnostics_enabled: true and restart Guardian"
			}
		case http.StatusConflict:
			message = "a diagnostic capture or download is already active"
		case http.StatusTooManyRequests:
			message = "diagnostic capture is cooling down"
			if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds >= 0 {
				message += fmt.Sprintf("; retry in %d seconds", seconds)
			}
		}
	}
	if c.token != "" {
		message = strings.ReplaceAll(message, c.token, "[redacted]")
	}
	return fail(code, "admin API HTTP %d: %s", resp.StatusCode, terminalSafe(message))
}

func (c *client) health(out io.Writer, asJSON bool) error {
	live, liveErr := c.request("GET", "/healthz", nil)
	ready, readyErr := c.request("GET", "/readyz", nil)
	result := map[string]any{"liveness": map[string]any{"ok": liveErr == nil, "response": live}, "readiness": map[string]any{"ok": readyErr == nil && ready["ready"] == true, "response": ready}}
	if liveErr != nil {
		result["liveness"].(map[string]any)["error"] = liveErr.Error()
	}
	if readyErr != nil {
		result["readiness"].(map[string]any)["error"] = readyErr.Error()
	}
	if err := render(out, asJSON, "health", result); err != nil {
		return err
	}
	if liveErr != nil {
		return liveErr
	}
	if readyErr != nil {
		return readyErr
	}
	if ready["ready"] != true {
		return fail(1, "store readiness is not established")
	}
	return nil
}
