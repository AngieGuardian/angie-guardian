// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package diagnostics_test

import (
	"archive/tar"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/pprof/profile"
	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/internal/diagnostics"
)

var reachableChannel = make(chan struct{})

//go:noinline
func detectorLeakedWorker() { select {} }

//go:noinline
func detectorReachableWorker() { <-reachableChannel }

func TestDetectorSubprocess(t *testing.T) {
	for _, mode := range []string{"clean", "leaked", "reachable", "lifecycle"} {
		t.Run(mode, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "snapshot.tar")
			cmd := exec.Command(os.Args[0], "-test.run=^TestDetectorHelper$")
			cmd.Env = append(os.Environ(), "GUARDIAN_DETECTOR_HELPER="+mode, "GUARDIAN_DETECTOR_OUTPUT="+target)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("helper: %v\n%s", err, out)
			}
			f, err := os.Open(target)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			tr := tar.NewReader(f)
			profiles := make(map[string]*profile.Profile)
			for _, name := range []string{"goroutineleak.pprof", "goroutine.pprof"} {
				h, err := tr.Next()
				if err != nil {
					t.Fatal(err)
				}
				if h.Name != name {
					t.Fatalf("entry=%s", h.Name)
				}
				data, err := io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
				p, err := profile.ParseData(data)
				if err != nil {
					t.Fatal(err)
				}
				if err := p.CheckValid(); err != nil {
					t.Fatal(err)
				}
				profiles[name] = p
			}
			if _, err := tr.Next(); err != io.EOF {
				t.Fatalf("extra entry: %v", err)
			}
			leaks := profiles["goroutineleak.pprof"]
			all := profiles["goroutine.pprof"]
			if mode == "leaked" {
				if !hasFunction(leaks, "detectorLeakedWorker") {
					t.Fatal("leak worker missing")
				}
			} else if len(leaks.Sample) != 0 {
				t.Fatalf("unexpected leaks: %+v", leaks.Sample)
			}
			if mode == "reachable" && (!hasFunction(all, "detectorReachableWorker") || hasFunction(leaks, "detectorReachableWorker")) {
				t.Fatal("reachable blocker classification incorrect")
			}
		})
	}
}

func hasFunction(p *profile.Profile, part string) bool {
	for _, s := range p.Sample {
		for _, l := range s.Location {
			for _, line := range l.Line {
				if line.Function != nil && strings.Contains(line.Function.Name, part) {
					return true
				}
			}
		}
	}
	return false
}

func TestDetectorHelper(t *testing.T) {
	mode := os.Getenv("GUARDIAN_DETECTOR_HELPER")
	if mode == "" {
		return
	}
	runtime.GOMAXPROCS(1)
	switch mode {
	case "leaked":
		go detectorLeakedWorker()
	case "reachable":
		go detectorReachableWorker()
	case "lifecycle":
		exerciseLifecycles(t)
	case "clean":
	default:
		t.Fatal(mode)
	}
	for range 20 {
		runtime.Gosched()
	}
	a, err := diagnostics.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	f, err := os.OpenFile(os.Getenv("GUARDIAN_DETECTOR_OUTPUT"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(f, a.File)
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func exerciseLifecycles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	rulesPath := filepath.Join(filepath.Dir(path), "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("store: { backend: memory }\nsigning_key_file: test.key\ndefaults:\n  waf:\n    rules: { enabled: true, files: [%q] }\n", rulesPath)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for range 10 {
		cfg, err := core.LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		st := store.NewMemory()
		e, err := core.NewEngine(cfg, st, nil, log)
		if err != nil {
			st.Close()
			t.Fatal(err)
		}
		for range 3 {
			next, err := core.LoadConfig(path)
			if err != nil {
				e.Close()
				st.Close()
				t.Fatal(err)
			}
			if err := e.Reload(next); err != nil {
				e.Close()
				st.Close()
				t.Fatal(err)
			}
		}
		e.Close()
		st.Close()
	}
}
