// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	angieClientLimit = 20
	h2StreamLimit    = 64
)

func protocolTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    tlsRoots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

func protocolHTTP2Client(t *testing.T) *http.Client {
	t.Helper()
	transport := &http2.Transport{TLSClientConfig: protocolTLSConfig()}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestAngieHardeningTarget(t *testing.T) {
	ctr, err := stack.ServiceContainer(context.Background(), "angie")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cmd  []string
		want []string
	}{
		{
			name: "configuration",
			cmd:  []string{"angie", "-t"},
			want: []string{"syntax is ok", "test is successful"},
		},
		{
			name: "version and modules",
			cmd:  []string{"angie", "-V"},
			want: []string{"Angie version: Angie/1.12.1", "--with-http_ssl_module", "--with-http_v2_module", "--with-http_v3_module"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exitCode, output, err := ctr.Exec(context.Background(), tc.cmd, tcexec.Multiplexed())
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(output)
			if err != nil {
				t.Fatal(err)
			}
			if exitCode != 0 {
				t.Fatalf("%v exited %d:\n%s", tc.cmd, exitCode, body)
			}
			for _, want := range tc.want {
				if !bytes.Contains(body, []byte(want)) {
					t.Errorf("%v output is missing %q:\n%s", tc.cmd, want, body)
				}
			}
		})
	}
}

func TestTLSVersionsAndHTTP2ALPN(t *testing.T) {
	for _, version := range []struct {
		name string
		id   uint16
	}{
		{name: "TLS 1.2", id: tls.VersionTLS12},
		{name: "TLS 1.3", id: tls.VersionTLS13},
	} {
		t.Run(version.name, func(t *testing.T) {
			cfg := protocolTLSConfig()
			cfg.MinVersion = version.id
			cfg.MaxVersion = version.id
			cfg.NextProtos = []string{"http/1.1"}
			conn, err := tls.Dial("tcp", tlsAddr, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if got := conn.ConnectionState().Version; got != version.id {
				t.Fatalf("negotiated TLS version %#x, want %#x", got, version.id)
			}
		})
	}

	client := protocolHTTP2Client(t)
	req, err := http.NewRequest(http.MethodGet, tlsSite+"/h2-alpn", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = wafOnlyHost
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 request status = %d, want 200", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("protocol = %s, ALPN = %q; want HTTP/2 with h2", resp.Proto, resp.TLS.NegotiatedProtocol)
	}
}

func TestTLSHandshakeTimeoutReleasesResources(t *testing.T) {
	baseline := angieFDCount(t)
	var conns []net.Conn
	for i := 0; i < 8; i++ {
		conn, err := net.DialTimeout("tcp", tlsAddr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		if i%2 == 1 {
			// A TLS record claiming a body that never arrives exercises partial,
			// rather than completely silent, handshake cleanup.
			if _, err := conn.Write([]byte{0x16, 0x03, 0x01, 0x10, 0x00, 0x01}); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	started := time.Now()
	for _, conn := range conns {
		_ = conn.SetReadDeadline(time.Now().Add(14 * time.Second))
		_, err := conn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("incomplete TLS handshake unexpectedly remained readable")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("Angie did not close an incomplete TLS handshake: %v", err)
		}
	}
	if elapsed := time.Since(started); elapsed < 8*time.Second || elapsed > 14*time.Second {
		t.Fatalf("handshake cleanup took %s; want the configured 10s timeout with tolerance", elapsed)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := angieFDCount(t); got <= baseline+8 {
			assertHTTPSHealthy(t)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("Angie file descriptors did not recover: baseline %d, now %d", baseline, angieFDCount(t))
}

func TestHTTP1IncompleteHeadersAndBodyAreReaped(t *testing.T) {
	t.Run("headers", func(t *testing.T) {
		before := backendCount(t)
		var conns []net.Conn
		for i := 0; i < 6; i++ {
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, conn)
			_, err = fmt.Fprintf(conn, "GET /slow-header HTTP/1.1\r\nHost: %s\r\nX-Incomplete: ", wafOnlyHost)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for _, conn := range conns {
				_ = conn.Close()
			}
		}()
		for _, conn := range conns {
			_ = conn.SetReadDeadline(time.Now().Add(13 * time.Second))
			_, err := conn.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("incomplete header connection unexpectedly remained readable")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("Angie did not reap an incomplete header: %v", err)
			}
		}
		if after := backendCount(t); after != before {
			t.Fatalf("incomplete headers reached the origin: delta %d", after-before)
		}
	})

	t.Run("body", func(t *testing.T) {
		before := backendCount(t)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, err = fmt.Fprintf(conn, "POST /slow-body HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: 1024\r\nConnection: close\r\n\r\nx", wafOnlyHost, browserUA)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(18 * time.Second))
		resp, readErr := http.ReadResponse(bufio.NewReader(conn), nil)
		if readErr == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusRequestTimeout {
				t.Fatalf("slow body status = %d, want 408 or a reset", resp.StatusCode)
			}
		} else if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("Angie did not reap a stalled body: %v", readErr)
		}
		if after := backendCount(t); after != before {
			t.Fatalf("incomplete body reached the origin: delta %d", after-before)
		}
	})

	t.Run("per-client active requests", func(t *testing.T) {
		before := backendCount(t)
		const attempted = angieClientLimit + 4
		conns := make([]net.Conn, 0, attempted)
		for i := 0; i < attempted; i++ {
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, conn)
			_, err = fmt.Fprintf(conn, "GET /held-response?id=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", i, wafOnlyHost, browserUA)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for _, conn := range conns {
				_ = conn.Close()
			}
		}()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && backendCount(t) < before+angieClientLimit {
			time.Sleep(50 * time.Millisecond)
		}
		if admitted := backendCount(t) - before; admitted != angieClientLimit {
			t.Fatalf("origin concurrency = %d, want exactly %d", admitted, angieClientLimit)
		}

		readDeadline := time.Now().Add(4 * time.Second)
		results := make(chan int, len(conns))
		for _, conn := range conns {
			go func(conn net.Conn) {
				_ = conn.SetReadDeadline(readDeadline)
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					results <- 0 // admitted request still waiting on the origin
					return
				}
				resp.Body.Close()
				results <- resp.StatusCode
			}(conn)
		}
		rejected := 0
		statuses := make(map[int]int)
		for range conns {
			status := <-results
			if status == 0 {
				continue
			}
			statuses[status]++
			if status == http.StatusTooManyRequests {
				rejected++
			}
		}
		if rejected < attempted-angieClientLimit {
			t.Fatalf("per-client limit rejected %d of %d held requests, want at least %d; received statuses: %v", rejected, attempted, attempted-angieClientLimit, statuses)
		}
		if after := backendCount(t); after != before+angieClientLimit {
			t.Fatalf("origin concurrency changed to %d, want exactly %d", after-before, angieClientLimit)
		}
	})
}

func TestHTTP1BodySizeAbortAndKeepaliveBounds(t *testing.T) {
	t.Run("oversized body", func(t *testing.T) {
		before := backendCount(t)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(conn, "POST /too-large HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", wafOnlyHost, (1<<20)+1)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized request status = %d, want 413", resp.StatusCode)
		}
		if after := backendCount(t); after != before {
			t.Fatalf("oversized request reached the origin: delta %d", after-before)
		}
	})

	t.Run("aborted upload", func(t *testing.T) {
		before := backendCount(t)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "POST /aborted HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: %d\r\n\r\n%s", wafOnlyHost, browserUA, 1<<20, strings.Repeat("x", 32<<10))
		_ = conn.Close()
		time.Sleep(500 * time.Millisecond)
		if after := backendCount(t); after != before {
			t.Fatalf("aborted buffered upload reached the origin: delta %d", after-before)
		}
		assertHTTPHealthy(t)
	})

	t.Run("idle keepalive", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, _ = fmt.Fprintf(conn, "GET /keepalive HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", wafOnlyHost, browserUA)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(17 * time.Second)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintf(conn, "GET /keepalive-again HTTP/1.1\r\nHost: %s\r\n\r\n", wafOnlyHost); err == nil {
			if second, err := http.ReadResponse(reader, nil); err == nil {
				second.Body.Close()
				t.Fatalf("idle connection survived the configured 15s keepalive timeout with status %d", second.StatusCode)
			}
		}
	})

	t.Run("slow response reader", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(site, "http://"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if tcp, ok := conn.(*net.TCPConn); ok {
			if err := tcp.SetReadBuffer(1024); err != nil {
				t.Fatal(err)
			}
		}
		_, _ = fmt.Fprintf(conn, "GET /large-response HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", wafOnlyHost, browserUA)
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.ContentLength != 64<<20 {
			resp.Body.Close()
			t.Fatalf("large response length = %d, want %d", resp.ContentLength, 64<<20)
		}
		// Docker's network path can retain bytes already written after Angie
		// closes its side. Angie's own timeout event is the authoritative signal.
		deadline := time.Now().Add(22 * time.Second)
		for time.Now().Before(deadline) {
			logs := angieLogs(t)
			if strings.Contains(logs, "client timed out") && strings.Contains(logs, `request_line: "GET /large-response HTTP/1.1"`) {
				resp.Body.Close()
				assertHTTPHealthy(t)
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		resp.Body.Close()
		t.Fatalf("Angie did not report send_timeout for the stalled response reader\nAngie logs:\n%s", angieLogs(t))
	})
}

func TestHTTP2SettingsHeadersAndRapidResetRecovery(t *testing.T) {
	t.Run("advertised stream limit", func(t *testing.T) {
		conn, framer := openH2(t)
		defer conn.Close()
		settings := readServerSettings(t, framer)
		if got := settings[http2.SettingMaxConcurrentStreams]; got != h2StreamLimit {
			t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS = %d, want %d", got, h2StreamLimit)
		}
	})

	t.Run("oversized decoded headers", func(t *testing.T) {
		before := backendCount(t)
		client := protocolHTTP2Client(t)
		req, err := http.NewRequest(http.MethodGet, tlsSite+"/oversized-hpack", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = wafOnlyHost
		req.Header.Set("X-Oversized", strings.Repeat("x", 40<<10))
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatalf("oversized HTTP/2 header status = %d, want rejection", resp.StatusCode)
			}
		}
		if after := backendCount(t); after != before {
			t.Fatalf("oversized HTTP/2 headers reached the origin: delta %d", after-before)
		}
	})

	t.Run("per-client active streams", func(t *testing.T) {
		before := backendCount(t)
		conn, framer := openH2(t)
		defer conn.Close()
		_ = readServerSettings(t, framer)
		for i := 0; i < angieClientLimit+4; i++ {
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			for _, field := range []hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: wafOnlyHost},
				{Name: ":path", Value: fmt.Sprintf("/held-h2-%d", i)},
				{Name: "user-agent", Value: browserUA},
				{Name: "content-length", Value: strconv.Itoa(1 << 20)},
			} {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      uint32(i*2 + 1),
				BlockFragment: block.Bytes(),
				EndHeaders:    true,
			}); err != nil {
				t.Fatal(err)
			}
		}

		framer.ReadMetaHeaders = hpack.NewDecoder(32<<10, nil)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		rejected := 0
		for rejected < 4 {
			frame, err := framer.ReadFrame()
			if err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					break
				}
				t.Fatal(err)
			}
			meta, ok := frame.(*http2.MetaHeadersFrame)
			if !ok {
				continue
			}
			for _, field := range meta.Fields {
				if field.Name == ":status" && field.Value == strconv.Itoa(http.StatusTooManyRequests) {
					rejected++
				}
			}
		}
		if rejected < 4 {
			t.Fatalf("HTTP/2 per-client limit rejected %d held streams, want at least 4", rejected)
		}
		if after := backendCount(t); after != before {
			t.Fatalf("incomplete or rejected HTTP/2 streams reached origin: delta %d", after-before)
		}
	})

	t.Run("rapid reset", func(t *testing.T) {
		before := backendCount(t)
		for round := 0; round < 4; round++ {
			if sent := rapidResetRound(t, 128); sent < 16 {
				t.Fatalf("round %d sent only %d reset streams before Angie closed it", round+1, sent)
			}
		}
		time.Sleep(500 * time.Millisecond)
		if after := backendCount(t); after != before {
			t.Fatalf("reset incomplete-body streams reached the origin: delta %d", after-before)
		}
		assertHTTPSHealthy(t)
	})
}

func TestAngieHardeningSoak(t *testing.T) {
	if os.Getenv("ANGIE_HARDENING_SOAK") != "1" {
		t.Skip("set ANGIE_HARDENING_SOAK=1 or run make e2e-angie-soak")
	}
	duration := 30 * time.Second
	if raw := os.Getenv("ANGIE_HARDENING_SOAK_DURATION"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid ANGIE_HARDENING_SOAK_DURATION %q", raw)
		}
		duration = parsed
	}
	baselineFDs := angieFDCount(t)
	before := backendCount(t)
	deadline := time.Now().Add(duration)
	rounds := 0
	streams := 0
	for time.Now().Before(deadline) {
		streams += rapidResetRound(t, 64)
		rounds++
	}
	if after := backendCount(t); after != before {
		t.Fatalf("soak reset streams reached the origin: delta %d", after-before)
	}
	waitForHTTPSHealthy(t, 5*time.Second)
	t.Logf("completed %d bounded Rapid Reset rounds (%d streams); Angie FDs baseline=%d final=%d", rounds, streams, baselineFDs, angieFDCount(t))
}

func openH2(t *testing.T) (*tls.Conn, *http2.Framer) {
	t.Helper()
	cfg := protocolTLSConfig()
	cfg.NextProtos = []string{"h2"}
	conn, err := tls.Dial("tcp", tlsAddr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		conn.Close()
		t.Fatalf("ALPN = %q, want h2", got)
	}
	framer := http2.NewFramer(conn, conn)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := framer.WriteSettings(); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn, framer
}

func readServerSettings(t *testing.T, framer *http2.Framer) map[http2.SettingID]uint32 {
	t.Helper()
	settings := make(map[http2.SettingID]uint32)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		s, ok := frame.(*http2.SettingsFrame)
		if !ok || s.IsAck() {
			continue
		}
		if err := s.ForeachSetting(func(setting http2.Setting) error {
			settings[setting.ID] = setting.Val
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := framer.WriteSettingsAck(); err != nil {
			t.Fatal(err)
		}
		return settings
	}
}

func rapidResetRound(t *testing.T, count int) int {
	t.Helper()
	conn, framer := openH2(t)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = readServerSettings(t, framer)
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: wafOnlyHost},
		{Name: ":path", Value: "/rapid-reset"},
		{Name: "user-agent", Value: browserUA},
		{Name: "content-length", Value: strconv.Itoa(1 << 20)},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	sent := 0
	for i := 0; i < count; i++ {
		streamID := uint32(i*2 + 1)
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block.Bytes(),
			EndHeaders:    true,
		}); err != nil {
			break
		}
		if err := framer.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
			break
		}
		sent++
	}
	return sent
}

func angieFDCount(t *testing.T) int {
	t.Helper()
	ctr, err := stack.ServiceContainer(context.Background(), "angie")
	if err != nil {
		t.Fatal(err)
	}
	exitCode, output, err := ctr.Exec(context.Background(), []string{"sh", "-c", "find /proc/[0-9]*/fd -type l 2>/dev/null | wc -l"}, tcexec.Multiplexed())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 0 {
		t.Fatalf("count Angie file descriptors exited %d: %s", exitCode, body)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("parse Angie file descriptor count %q: %v", body, err)
	}
	return n
}

func angieLogs(t *testing.T) string {
	t.Helper()
	ctr, err := stack.ServiceContainer(context.Background(), "angie")
	if err != nil {
		t.Fatal(err)
	}
	output, err := ctr.Logs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	body, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func assertHTTPHealthy(t *testing.T) {
	t.Helper()
	resp := get(t, "/angie-recovery", wafOnlyHost, browserUA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP recovery status = %d, want 200", resp.StatusCode)
	}
}

func assertHTTPSHealthy(t *testing.T) {
	t.Helper()
	client := protocolHTTP2Client(t)
	req, err := http.NewRequest(http.MethodGet, tlsSite+"/angie-recovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = wafOnlyHost
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("HTTPS recovery = %d over %s, want 200 over HTTP/2", resp.StatusCode, resp.Proto)
	}
}

func waitForHTTPSHealthy(t *testing.T, timeout time.Duration) {
	t.Helper()
	client := protocolHTTP2Client(t)
	deadline := time.Now().Add(timeout)
	last := "no response"
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, tlsSite+"/angie-recovery", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = wafOnlyHost
		req.Header.Set("User-Agent", browserUA)
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			last = fmt.Sprintf("status %d over %s", resp.StatusCode, resp.Proto)
			if resp.StatusCode == http.StatusOK && resp.ProtoMajor == 2 {
				return
			}
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("HTTPS did not recover within %s: %s", timeout, last)
}
