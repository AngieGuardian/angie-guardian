// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const auditJSONPath = "/var/log/angie/e2e-all.json"
const auditNormalPath = "/var/log/angie/e2e-normal.log"

var accessInvocation atomic.Uint64

func uniqueAuditURI(path string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%s_audit=%d-%d-%d", path, separator, os.Getpid(), time.Now().UnixNano(), accessInvocation.Add(1))
}

func assertAngieConfig(t *testing.T, ctr testcontainers.Container) {
	t.Helper()
	code, out, err := ctr.Exec(t.Context(), []string{"angie", "-t"}, tcexec.Multiplexed())
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.Contains(string(b), "test is successful") {
		t.Fatalf("angie -t: %s", b)
	}
}

// Mount the unmodified production endpoints and limit zones, independently of
// the reduced-capacity runtime fixture. No DNS dependency is needed for -t.
func TestGuardianProductionLoggingConfiguration(t *testing.T) {
	ctr, err := stack.ServiceContainer(t.Context(), "angie")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, name := range []string{"angie-guardian.conf", "angie-guardian-location.conf", "angie-guardian-limits.conf", "angie-json-log.conf"} {
		b, err := os.ReadFile("../../deploy/" + name)
		if err != nil {
			t.Fatal(err)
		}
		target := "/tmp/production-" + name
		if err := ctr.CopyToContainer(t.Context(), b, target, 0644); err != nil {
			t.Fatal(err)
		}
		files[name] = target
	}
	config := fmt.Sprintf(`events {} http {
        include %s;
        include %s;
        upstream guardian { server 127.0.0.1:8071; keepalive 64; }
        server { listen 8089; include %s; include %s;
            access_log /tmp/production-access.log guardian_json;
            location / { proxy_pass http://127.0.0.1:8080; }
        }
    }`, files["angie-guardian-limits.conf"], files["angie-json-log.conf"], files["angie-guardian.conf"], files["angie-guardian-location.conf"])
	if err := ctr.CopyToContainer(t.Context(), []byte(config), "/tmp/production-logging.conf", 0644); err != nil {
		t.Fatal(err)
	}
	code, out, err := ctr.Exec(t.Context(), []string{"angie", "-t", "-c", "/tmp/production-logging.conf"}, tcexec.Multiplexed())
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.Contains(string(b), "test is successful") {
		t.Fatalf("unmodified production configuration: %s", b)
	}
}

type accessRecord struct {
	Time               string  `json:"time"`
	IP                 string  `json:"remote_addr"`
	Host               string  `json:"host"`
	Method             string  `json:"method"`
	URI                string  `json:"uri"`
	Status             int     `json:"status"`
	Bytes              int     `json:"bytes_sent"`
	Duration           float64 `json:"request_time"`
	Referer            string  `json:"referer"`
	UA                 string  `json:"user_agent"`
	Action             string  `json:"guardian_action"`
	Reason             string  `json:"guardian_reason"`
	AuthStatus         string  `json:"guardian_auth_status"`
	AuthUpstreamStatus string  `json:"guardian_auth_upstream_status"`
	Exemption          string  `json:"guardian_pow_exemption"`
}

func angieFile(t *testing.T, ctr testcontainers.Container, path string) string {
	t.Helper()
	code, output, err := ctr.Exec(context.Background(), []string{"cat", path}, tcexec.Multiplexed())
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("read %s: exit %d: %s", path, code, b)
	}
	return string(b)
}

// Read completed, unbuffered records; bounded polling handles the brief gap
// between the client receiving the body and Angie's log phase completing.
func accessLogRecord(t *testing.T, ctr testcontainers.Container, uri string) (accessRecord, []byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var found []byte
		var record accessRecord
		for line := range strings.SplitSeq(angieFile(t, ctr, auditJSONPath), "\n") {
			if line == "" {
				continue
			}
			var r accessRecord
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("invalid rendered JSON: %v: %s", err, line)
			}
			if r.URI == uri {
				if found != nil {
					t.Fatalf("duplicate access record for %s", uri)
				}
				found, record = []byte(line), r
			}
		}
		if found != nil {
			return record, found
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access record for %s", uri)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertAccessDecision(t *testing.T, ctr testcontainers.Container, uri, action, reason, authStatus, upstreamStatus string, status int, normal bool) accessRecord {
	t.Helper()
	r, line := accessLogRecord(t, ctr, uri)
	if r.Action != action || r.Reason != reason || r.AuthStatus != authStatus || r.AuthUpstreamStatus != upstreamStatus || r.Status != status {
		t.Fatalf("access decision: %s; want action=%q reason=%q auth=%q upstream=%q status=%d", line, action, reason, authStatus, upstreamStatus, status)
	}
	if _, err := time.Parse(time.RFC3339, r.Time); err != nil {
		t.Errorf("invalid timestamp: %v", err)
	}
	if net.ParseIP(r.IP) == nil || r.Bytes < 0 || r.Duration < 0 {
		t.Errorf("invalid response metadata: %s", line)
	}
	wantCount := 0
	if normal {
		wantCount = 1
	}
	deadline := time.Now().Add(3 * time.Second)
	// A JSON write does not synchronize the independent combined destination.
	// Positive membership waits for that destination; negative membership is
	// observed over a short bounded settling interval after the JSON record.
	if !normal {
		deadline = time.Now().Add(50 * time.Millisecond)
	}
	for {
		count := strings.Count(angieFile(t, ctr, auditNormalPath), uri+" HTTP/")
		if count > wantCount {
			t.Fatalf("normal stream count for %s = %d, want %d", uri, count, wantCount)
		}
		if normal && count == wantCount {
			break
		}
		if time.Now().After(deadline) {
			if count != wantCount {
				t.Fatalf("normal stream count for %s = %d, want %d", uri, count, wantCount)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err := anomaly.ParseLogRecord(line)
	if action == "" {
		if err == nil {
			t.Error("trainer accepted unevaluated request; strict policy must remain unchanged")
		}
	} else if err != nil {
		t.Errorf("trainer rejected rendered extended record: %v", err)
	}
	return r
}

func TestGuardianAccessLogging(t *testing.T) {
	clearGatewayBlocks()
	t.Cleanup(clearGatewayBlocks)
	ctr, err := stack.ServiceContainer(context.Background(), "angie")
	if err != nil {
		t.Fatal(err)
	}
	assertAngieConfig(t, ctr)
	transport := &http.Transport{MaxConnsPerHost: 1, DisableCompression: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	const escapedUA = "Mozilla/5.0 audit\"\\\t café"
	const escapedReferer = "https://example.test/audit?quoted=\"\\\tend"
	for i, tc := range []struct {
		name, uri, host, ua, accept, action, reason, auth string
		status                                            int
		normal                                            bool
	}{
		{"allow", "/audit-status/?status=200&case=allow&value=%22%5C", wafOnlyHost, escapedUA, "text/html", "allow", "default", "200", 200, true},
		{"public", "/audit-public/after-allow", wafOnlyHost, browserUA, "text/html", "", "", "", 200, true},
		{"challenge", "/audit-challenge?original=%22%5C", powHost, browserUA, "text/html", "challenge", "pow:no_token", "401", 200, true},
		{"public-after-challenge", "/audit-public/after-challenge", powHost, browserUA, "text/html", "", "", "", 200, true},
		{"deny", "/wp-login.php?audit=deny", powHost, browserUA, "text/html", "deny", "waf:wp-cms-probe", "403", 403, false},
		{"refuse", "/audit-refuse", powHost, browserUA, "application/json", "refuse", "pow:unchallengeable", "401", 403, false},
		{"app401", "/audit-status/?status=401&case=app401", wafOnlyHost, browserUA, "text/html", "allow", "default", "200", 401, true},
		{"app403", "/audit-status/?status=403&case=app403", wafOnlyHost, browserUA, "text/html", "allow", "default", "200", 403, true},
		{"app404", "/audit-status/?status=404&case=app404", wafOnlyHost, browserUA, "text/html", "allow", "default", "200", 404, true},
		{"basic", "/basic/?audit=basic", powHost, browserUA, "text/html", "", "", "", 401, true},
		{"exemption", "/audit-exempt", "ua-exempt.localhost", "FixtureMachine/1.0", "text/html", "allow", "default", "200", 200, true},
		{"exemption-deny", "/ordered/secret?audit=exemption-deny", "ua-exempt.localhost", "FixtureMachine/1.0", "text/html", "deny", "waf:fixture-deny", "403", 403, false},
		{"named-redirect", "/audit-redirect/original?audit=named", wafOnlyHost, browserUA, "text/html", "allow", "default", "200", 200, true},
		{"uri-redirect", "/audit-error/original?audit=uri-redirect", wafOnlyHost, browserUA, "text/html", "allow", "default", "200", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.uri = uniqueAuditURI(tc.uri)
			request, err := http.NewRequest(http.MethodPost, site+tc.uri, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = strings.ToUpper(tc.host) + ":80"
			request.Header.Set("User-Agent", tc.ua)
			request.Header.Set("Referer", escapedReferer)
			request.Header.Set("Accept", tc.accept)
			request.Header.Set("X-Guardian-Action", "shed")
			request.Header.Set("X-Guardian-Reason", "forged:client")
			request.Header.Set("X-Guardian-PoW-Exemption", "forged:client")
			request.Header.Set("X-Forwarded-For", "2001:db8::bad")
			reused := false
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("response=%d, want %d: %s", response.StatusCode, tc.status, body)
			}
			if i > 0 && !reused {
				t.Fatal("request did not reuse the previous connection")
			}
			r := assertAccessDecision(t, ctr, tc.uri, tc.action, tc.reason, tc.auth, tc.auth, tc.status, tc.normal)
			wantExemption := ""
			if strings.HasPrefix(tc.name, "exemption") {
				wantExemption = "allowlist:ua"
			}
			if r.Exemption != wantExemption {
				t.Errorf("PoW classification = %q, want %q", r.Exemption, wantExemption)
			}
			if r.Method != "POST" || r.Host != tc.host || r.UA != tc.ua || r.Referer != escapedReferer || (response.ContentLength >= 0 && int64(r.Bytes) != response.ContentLength) || r.Bytes < len(body) || r.IP == "2001:db8::bad" {
				t.Errorf("original request/response metadata changed: %+v, body bytes %d", r, len(body))
			}
		})
	}
}

// A separate Angie uses the actual shipped handlers with only the concurrency
// literal scaled to one. One incomplete body occupies the zone deterministically;
// the auth subrequest of the next request must shed before contacting upstream.
// A synthetic auth peer additionally exercises overload headers and closed hops
// without timing-dependent saturation of the real daemon.
func newAccessLoggingFixture(t *testing.T, closedAuth bool) (testcontainers.Container, string) {
	t.Helper()
	dir := t.TempDir()
	endpoints, err := os.ReadFile("../../deploy/angie-guardian.conf")
	if err != nil {
		t.Fatal(err)
	}
	endpoints = []byte(strings.ReplaceAll(string(endpoints), "limit_conn guardian_control_plane 512;", "limit_conn guardian_control_plane 1;"))
	if err := os.WriteFile(filepath.Join(dir, "endpoints.conf"), endpoints, 0600); err != nil {
		t.Fatal(err)
	}
	config := `worker_processes 1;
events { worker_connections 128; }
http {
    include /etc/angie/angie-json-log.conf;
    log_format peer escape=json '{"uri":"$request_uri"}';
    limit_conn_zone $server_name zone=guardian_control_plane:1m;
    limit_req_zone $binary_remote_addr zone=guardian_challenge_ip:1m rate=1000r/s;
    limit_req_zone $binary_remote_addr zone=guardian_pass_ip:1m rate=1000r/s;
    limit_req_zone $binary_remote_addr zone=guardian_assets_ip:1m rate=1000r/s;
    map $guardian_action $normal_access_log { default 1; deny 0; refuse 0; shed 0; }
    upstream guardian { server 127.0.0.1:90; }
    map $http_x_e2e_auth_outcome $peer_action { default allow; shed shed; }
    map $http_x_e2e_auth_outcome $peer_reason { default default; shed admission:max_inflight; }
    server {
        listen 80;
        server_name logging.example;
        set_real_ip_from 127.0.0.0/8;
        set_real_ip_from 10.0.0.0/8;
        set_real_ip_from 172.16.0.0/12;
        set_real_ip_from 192.168.0.0/16;
        real_ip_header X-E2E-Client-IP;
        include /etc/angie/endpoints.conf;
        include /etc/angie/angie-guardian-location.conf;
        access_log /var/log/angie/e2e-all.json guardian_json;
        access_log /var/log/angie/e2e-normal.log combined if=$normal_access_log;
        location = /ready { auth_request off; return 200 ready; }
        location /hold { auth_request off; limit_conn guardian_control_plane 1; proxy_pass http://127.0.0.1:90; }
        location / { proxy_pass http://127.0.0.1:90; }
    }
    server {
        listen 90;
        access_log /var/log/angie/e2e-peer.log peer;
        location = /auth {
            add_header X-Guardian-Action $peer_action always;
            add_header X-Guardian-Reason $peer_reason always;
            if ($peer_action = shed) { return 403; }
            return 200;
        }
        location / { return 200 origin; }
    }
}`
	if closedAuth {
		config = strings.Replace(config, "upstream guardian { server 127.0.0.1:90; }", "upstream guardian { server 127.0.0.1:1; }", 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "angie.conf"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	files := []testcontainers.ContainerFile{
		{HostFilePath: filepath.Join(dir, "angie.conf"), ContainerFilePath: "/etc/angie/angie.conf", FileMode: 0644},
		{HostFilePath: filepath.Join(dir, "endpoints.conf"), ContainerFilePath: "/etc/angie/endpoints.conf", FileMode: 0644},
	}
	for _, name := range []string{"angie-json-log.conf", "angie-guardian-location.conf"} {
		files = append(files, testcontainers.ContainerFile{HostFilePath: "../../deploy/" + name, ContainerFilePath: "/etc/angie/" + name, FileMode: 0644})
	}
	ctr, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "docker.angie.software/angie:1.12.1@sha256:c9b84be14a2a584891a1ef6678d44e6d7740127e6ceddc8f2f237491ff369ce0",
			ExposedPorts: []string{"80/tcp"}, Files: files,
			WaitingFor: wait.ForHTTP("/ready").WithPort("80/tcp"),
		}, Started: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })
	assertAngieConfig(t, ctr)
	host, err := ctr.Host(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	port, err := ctr.MappedPort(context.Background(), "80/tcp")
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort(host, port.Port())
	return ctr, addr
}

func TestGuardianAccessLoggingAdmissionAndRealIP(t *testing.T) {
	ctr, addr := newAccessLoggingFixture(t, false)
	client := &http.Client{Timeout: 3 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	probe := func(uri, ip, outcome string) *http.Response {
		r, err := http.NewRequest("POST", "http://"+addr+uri, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "Logging.Example:80"
		r.Header.Set("X-E2E-Client-IP", ip)
		r.Header.Set("X-E2E-Auth-Outcome", outcome)
		r.Header.Set("X-Guardian-Action", "deny")
		r.Header.Set("X-Guardian-Reason", "forged:client")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response
	}
	for i, ip := range []string{"198.51.100.69", "2001:db8::69"} {
		uri := uniqueAuditURI(fmt.Sprintf("/real-ip?case=%d", i))
		probe(uri, ip, "")
		r := assertAccessDecision(t, ctr, uri, "allow", "default", "200", "200", 200, true)
		if r.IP != ip || r.Host != "logging.example" || r.Method != "POST" {
			t.Fatalf("real-IP/original host/method: %+v", r)
		}
	}
	sidecarShedURI := uniqueAuditURI("/sidecar-shed")
	probe(sidecarShedURI, "198.51.100.69", "shed")
	assertAccessDecision(t, ctr, sidecarShedURI, "shed", "admission:max_inflight", "403", "403", 503, false)

	held, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_, err = fmt.Fprint(held, "POST /hold HTTP/1.1\r\nHost: logging.example\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	// 100 Continue is sent after limit_conn has admitted the request, before
	// reading its unfinished body. This is a synchronization barrier, not a sleep.
	_ = held.SetReadDeadline(time.Now().Add(time.Second))
	continueResponse := make([]byte, len("HTTP/1.1 100 Continue\r\n\r\n"))
	if _, err := io.ReadFull(held, continueResponse); err != nil {
		t.Fatal(err)
	}
	if string(continueResponse) != "HTTP/1.1 100 Continue\r\n\r\n" {
		t.Fatalf("hold admission: %q", continueResponse)
	}
	peerCounts := func() (int, int) {
		auth, application := 0, 0
		for line := range strings.SplitSeq(angieFile(t, ctr, "/var/log/angie/e2e-peer.log"), "\n") {
			if line == "" {
				continue
			}
			var record struct {
				URI string `json:"uri"`
			}
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatal(err)
			}
			if record.URI == "/auth" {
				auth++
			} else {
				application++
			}
		}
		return auth, application
	}
	beforeAuth, beforeApplication := peerCounts()
	localShedURI := uniqueAuditURI("/local-shed")
	response := probe(localShedURI, "198.51.100.69", "")
	if response.Header.Get("Retry-After") != "2" {
		t.Fatal("local shed missing Retry-After")
	}
	assertAccessDecision(t, ctr, localShedURI, "shed", "admission:control_plane", "403", "", 503, false)
	afterShedURI := uniqueAuditURI("/ready?after=shed")
	probe(afterShedURI, "198.51.100.69", "")
	assertAccessDecision(t, ctr, afterShedURI, "", "", "", "", 200, true)
	afterAuth, afterApplication := peerCounts()
	if afterAuth != beforeAuth || afterApplication != beforeApplication {
		t.Fatalf("admission rejection reached upstream: auth %d→%d application %d→%d", beforeAuth, afterAuth, beforeApplication, afterApplication)
	}
	_ = held.Close()
}

// A reachable closed port guarantees connect() refusal (502), whereas stopping
// a Docker sidecar can instead blackhole its old IP and produce a timeout (504).
// Both retain empty decisions, and neither may leak state to a reused connection.
func TestGuardianAccessLoggingFailedAuthIsolation(t *testing.T) {
	ctr, addr := newAccessLoggingFixture(t, true)
	transport := &http.Transport{MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for i, path := range []string{"/closed-auth", "/ready", "/closed-auth-again", "/ready"} {
		uri := uniqueAuditURI(path)
		request, err := http.NewRequest(http.MethodGet, "http://"+addr+uri, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Guardian-Action", "allow")
		request.Header.Set("X-Guardian-Reason", "forged:client")
		reused := false
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body := bodyOf(t, response)
		if response.StatusCode != 200 {
			t.Fatalf("failed hop did not resume original handler: %d %s", response.StatusCode, body)
		}
		if i > 0 && !reused {
			t.Fatal("failed auth requests did not share one connection")
		}
		authStatus, upstreamStatus := "204", "502"
		if path == "/ready" {
			authStatus, upstreamStatus = "", ""
		} else if body != "origin" {
			t.Fatalf("fail-open body = %q, want original backend", body)
		}
		r := assertAccessDecision(t, ctr, uri, "", "", authStatus, upstreamStatus, 200, true)
		if r.Exemption != "" {
			t.Fatalf("failed hop inherited PoW exemption: %q", r.Exemption)
		}
	}
}
