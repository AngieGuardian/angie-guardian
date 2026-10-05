// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise both compiled binaries from this revision using private files and
// disposable listeners. An explicit daemon override also supports qualification.
func TestDiagnosticsDaemon(t *testing.T) {
	dir := t.TempDir()
	daemon := os.Getenv("GUARDIANCTL_TEST_DAEMON")
	if daemon == "" {
		daemon = filepath.Join(dir, "guardiand")
		if output, err := exec.Command("go", "build", "-o", daemon, "../guardiand").CombinedOutput(); err != nil {
			t.Fatalf("build daemon: %s %v", output, err)
		}
	}
	daemon, err := filepath.Abs(daemon)
	if err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(dir, "guardianctl")
	if output, err := exec.Command("go", "build", "-o", ctl, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %s %v", output, err)
	}
	// Reuse this fixture to exercise actual parser, client timeout defaults,
	// signal handling and publication using the two separately built binaries.
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			runtimeDir := t.TempDir()
			ports := make([]string, 2)
			for i := range ports {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ports[i] = ln.Addr().String()
				ln.Close()
			}
			config := filepath.Join(runtimeDir, "guardian.yaml")
			tokenFile := filepath.Join(runtimeDir, "admin.token")
			raw := fmt.Sprintf("listen: %s\nstore: {backend: memory}\nsigning_key_file: %s\nadmin:\n  listen: %s\n  token_file: %s\n  diagnostics_enabled: %v\n", ports[0], filepath.Join(runtimeDir, "key"), ports[1], tokenFile, enabled)
			if err := os.WriteFile(config, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(runtimeDir, "daemon.log")
			log, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			proc := exec.Command(daemon, "-config", config)
			proc.Dir = runtimeDir
			proc.Stdout = log
			proc.Stderr = log
			// Do not inherit an operator's bearer token into the throwaway instance.
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "ADMIN_TOKEN=") {
					proc.Env = append(proc.Env, entry)
				}
			}
			if err := proc.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- proc.Wait() }()
			t.Cleanup(func() {
				proc.Process.Signal(os.Interrupt)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					proc.Process.Kill()
					<-done
				}
			})
			probe := &http.Client{Timeout: 100 * time.Millisecond}
			ready := false
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				resp, err := probe.Get("http://" + ports[1] + "/readyz")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						ready = true
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				data, _ := os.ReadFile(logPath)
				t.Fatalf("daemon not ready: %s", data)
			}
			invokeBinary := func(expected int, args ...string) string {
				t.Helper()
				cmd := exec.Command(ctl, append([]string{"--config", config}, args...)...)
				cmd.Env = proc.Env
				output, err := cmd.CombinedOutput()
				actual := 0
				if err != nil {
					if exit, ok := err.(*exec.ExitError); ok {
						actual = exit.ExitCode()
					} else {
						t.Fatal(err)
					}
				}
				if actual != expected {
					t.Fatalf("%v: exit %d want %d: %s", args, actual, expected, output)
				}
				token, _ := os.ReadFile(tokenFile)
				if strings.Contains(string(output), strings.TrimSpace(string(token))) {
					t.Fatal("credential exposed")
				}
				return string(output)
			}
			statusJSON := invokeBinary(0, "diagnostics", "status", "--json")
			var status map[string]any
			if err := json.Unmarshal([]byte(statusJSON), &status); err != nil || status["enabled"] != enabled {
				t.Fatalf("status %s %v", statusJSON, err)
			}
			dst := filepath.Join(runtimeDir, "profiles.tar")
			if !enabled {
				invokeBinary(1, "diagnostics", "capture", "--out", dst)
				if _, err := os.Lstat(dst); !os.IsNotExist(err) {
					t.Fatal("disabled capture created output")
				}
				return
			}
			metadata := invokeBinary(0, "diagnostics", "capture", "--out", dst, "--json")
			var saved map[string]any
			if err := json.Unmarshal([]byte(metadata), &saved); err != nil || saved["path"] != dst {
				t.Fatalf("metadata %s %v", metadata, err)
			}
			f, err := os.Open(dst)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || info.Mode().Perm() != 0600 || saved["bytes"] != float64(info.Size()) {
				t.Fatalf("saved archive %v %v", info, err)
			}
			tr := tar.NewReader(f)
			for _, name := range []string{"goroutineleak.pprof", "goroutine.pprof"} {
				h, err := tr.Next()
				if err != nil || h.Name != name {
					t.Fatalf("entry %v %v", h, err)
				}
				data, err := io.ReadAll(tr)
				if err != nil || len(data) == 0 {
					t.Fatalf("profile %s: %v", name, err)
				}
			}
			invokeBinary(2, "diagnostics", "capture", "--out", dst)
			coolingJSON := invokeBinary(0, "diagnostics", "status", "--json")
			json.Unmarshal([]byte(coolingJSON), &status)
			if status["retry_after_seconds"].(float64) <= 0 {
				t.Fatalf("no cooldown: %s", coolingJSON)
			}
			second := filepath.Join(runtimeDir, "second.tar")
			failure := invokeBinary(1, "diagnostics", "capture", "--out", second)
			if !strings.Contains(failure, "cooling down") {
				t.Fatal(failure)
			}
			if _, err := os.Lstat(second); !os.IsNotExist(err) {
				t.Fatal("cooldown created output")
			}
			partials, _ := filepath.Glob(filepath.Join(runtimeDir, ".guardianctl-profiles-*"))
			if len(partials) != 0 {
				t.Fatal(partials)
			}
		})
	}
}
