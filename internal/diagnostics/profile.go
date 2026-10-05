// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package diagnostics prepares bounded, private, on-demand goroutine snapshots.
package diagnostics

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"time"
)

const MaxBytes int64 = 32 << 20

// WriteProfile writes the named runtime profile in binary pprof format.
// A goroutineleak capture runs a GC cycle that cannot be interrupted by context.
func WriteProfile(name string, w io.Writer) error {
	p := pprof.Lookup(name)
	if p == nil {
		return fmt.Errorf("unknown runtime profile %q", name)
	}
	return p.WriteTo(w, 0)
}

// Archive owns its private temporary directory until Close is called.
type Archive struct {
	File     *os.File
	Name     string
	Size     int64
	dir      string
	once     sync.Once
	closeErr error
}

func (a *Archive) Close() error {
	a.once.Do(func() { a.closeErr = errors.Join(a.File.Close(), os.RemoveAll(a.dir)) })
	return a.closeErr
}

// Prepare captures leak-only evidence followed by all goroutines. It enables
// no other profiling and checks cancellation around each synchronous capture.
func Prepare(ctx context.Context) (*Archive, error) {
	return prepare(ctx, "", MaxBytes, WriteProfile)
}

type boundedWriter struct {
	ctx       context.Context
	w         io.Writer
	remaining *int64
}

func (w boundedWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > *w.remaining {
		return 0, fmt.Errorf("diagnostic output exceeds size limit")
	}
	n, err := w.w.Write(p)
	*w.remaining -= int64(n)
	return n, err
}

func prepare(ctx context.Context, root string, limit int64, capture func(string, io.Writer) error) (_ *Archive, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(root, "guardian-goroutines-")
	if err != nil {
		return nil, err
	}
	var archive *Archive
	defer func() {
		if err != nil {
			if archive != nil {
				err = errors.Join(err, archive.Close())
			} else {
				err = errors.Join(err, os.RemoveAll(dir))
			}
		}
	}()
	remaining := limit
	names := []string{"goroutineleak", "goroutine"}
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var f *os.File
		f, err = os.OpenFile(filepath.Join(dir, name+".pprof"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		captureErr := capture(name, boundedWriter{ctx, f, &remaining})
		closeErr := f.Close()
		if err = errors.Join(captureErr, closeErr, ctx.Err()); err != nil {
			return nil, err
		}
	}
	name := "guardian-goroutines-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".tar"
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	archive = &Archive{File: f, Name: name, dir: dir}
	remaining = limit
	tw := tar.NewWriter(boundedWriter{ctx, f, &remaining})
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		filename := name + ".pprof"
		input, openErr := os.Open(filepath.Join(dir, filename))
		if openErr != nil {
			return nil, openErr
		}
		info, statErr := input.Stat()
		if statErr != nil {
			_ = input.Close()
			return nil, statErr
		}
		headerErr := tw.WriteHeader(&tar.Header{Name: filename, Mode: 0o600, Size: info.Size(), ModTime: time.Now().UTC()})
		var copyErr error
		if headerErr == nil {
			_, copyErr = io.Copy(tw, input)
		}
		if err = errors.Join(headerErr, copyErr, input.Close()); err != nil {
			return nil, err
		}
	}
	if err = errors.Join(tw.Close(), ctx.Err()); err != nil {
		return nil, err
	}
	archive.Size, err = f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return archive, nil
}
