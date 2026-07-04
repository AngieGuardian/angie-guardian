// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// ModelCache serves the current model for each configured artifact path and
// hot-swaps it when guardian-train writes a new version (mtime change, same
// approach as the WAF rule cache). A model that fails to load keeps the
// previous one active.
type ModelCache struct {
	files map[string]*modelFile
	log   *slog.Logger
	stop  chan struct{}
}

type modelFile struct {
	path  string
	mtime atomic.Int64
	model atomic.Pointer[Model]
}

// NewModelCache loads every artifact eagerly. A missing or invalid model
// fails startup for the same reason bad WAF rules do: silently running
// without a configured protection is worse than refusing to start.
func NewModelCache(paths []string, log *slog.Logger) (*ModelCache, error) {
	c := &ModelCache{files: make(map[string]*modelFile, len(paths)), log: log, stop: make(chan struct{})}
	for _, path := range paths {
		f := &modelFile{path: path}
		if err := f.load(); err != nil {
			return nil, err
		}
		c.files[path] = f
	}
	return c, nil
}

func (f *modelFile) load() error {
	fi, err := os.Stat(f.path)
	if err != nil {
		return err
	}
	m, err := Load(f.path)
	if err != nil {
		return err
	}
	f.model.Store(m)
	f.mtime.Store(fi.ModTime().UnixNano())
	return nil
}

// Get returns the current model for a configured path, or nil.
func (c *ModelCache) Get(path string) *Model {
	f, ok := c.files[path]
	if !ok {
		return nil
	}
	return f.model.Load()
}

func (c *ModelCache) Start(interval time.Duration) {
	if len(c.files) == 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-t.C:
				c.reloadChanged()
			}
		}
	}()
}

func (c *ModelCache) reloadChanged() {
	for _, f := range c.files {
		fi, err := os.Stat(f.path)
		if err != nil {
			c.log.Warn("model unreadable, keeping loaded model", "file", f.path, "err", err)
			continue
		}
		if fi.ModTime().UnixNano() == f.mtime.Load() {
			continue
		}
		if err := f.load(); err != nil {
			c.log.Error("model reload failed, keeping previous model", "file", f.path, "err", err)
			f.mtime.Store(fi.ModTime().UnixNano())
			continue
		}
		c.log.Info("anomaly model reloaded", "file", f.path,
			"domains", len(f.model.Load().Domains), "trained_at", f.model.Load().TrainedAt)
	}
}

func (c *ModelCache) Close() {
	close(c.stop)
}
