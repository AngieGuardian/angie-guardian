// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package diagnostics

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareArchive(t *testing.T) {
	root := t.TempDir()
	var calls []string
	a, err := prepare(t.Context(), root, MaxBytes, func(name string, w io.Writer) error {
		calls = append(calls, name)
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		info, err := entries[0].Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("directory mode=%o", info.Mode().Perm())
		}
		_, err = io.WriteString(w, name)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"goroutineleak", "goroutine"}) {
		t.Fatal(calls)
	}
	if !strings.HasPrefix(a.Name, "guardian-goroutines-") || !strings.HasSuffix(a.Name, "Z.tar") {
		t.Fatal(a.Name)
	}
	info, err := a.File.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != a.Size || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive size/mode=%v", info)
	}
	tr := tar.NewReader(a.File)
	for _, name := range calls {
		h, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name != name+".pprof" || h.Mode != 0o600 || string(data) != name {
			t.Fatalf("entry=%+v data=%s", h, data)
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("extra entry: %v", err)
	}
	dir := filepath.Dir(a.File.Name())
	for _, name := range calls {
		info, err := os.Stat(filepath.Join(dir, name+".pprof"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("profile mode=%o", info.Mode().Perm())
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory retained: %v", err)
	}
}

func TestPrepareFailureCleanup(t *testing.T) {
	sentinel := errors.New("capture failed")
	for _, tc := range []struct {
		name     string
		limit    int64
		failAt   int
		cancelAt int
		size     int
	}{
		{name: "first capture error", limit: MaxBytes, failAt: 1},
		{name: "second capture error", limit: MaxBytes, failAt: 2},
		{name: "cancel first", limit: MaxBytes, cancelAt: 1},
		{name: "cancel second", limit: MaxBytes, cancelAt: 2},
		{name: "combined profiles exceed", limit: 8, size: 5},
		{name: "archive overhead exceeds", limit: 16, size: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			a, err := prepare(ctx, root, tc.limit, func(_ string, w io.Writer) error {
				calls++
				if calls == tc.cancelAt {
					cancel()
				}
				if calls == tc.failAt {
					return sentinel
				}
				_, err := w.Write(bytes.Repeat([]byte{'x'}, tc.size))
				return err
			})
			if a != nil || err == nil {
				t.Fatalf("archive=%v err=%v", a, err)
			}
			if tc.failAt != 0 && !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			if tc.cancelAt != 0 && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if tc.cancelAt == 1 && calls != 1 {
				t.Fatalf("capture continued after cancel: %d", calls)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cleanup entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestPrepareAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	root := t.TempDir()
	if _, err := prepare(ctx, root, MaxBytes, func(string, io.Writer) error { t.Fatal("capture called"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}

func TestWriteUnknownProfile(t *testing.T) {
	if err := WriteProfile("guardian-unknown", io.Discard); err == nil {
		t.Fatal("accepted unknown profile")
	}
}

func TestPrepareActualProfileLimit(t *testing.T) {
	root := t.TempDir()
	if a, err := prepare(t.Context(), root, 1, WriteProfile); a != nil || err == nil {
		t.Fatalf("archive=%v error=%v", a, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup entries=%v error=%v", entries, err)
	}
}
