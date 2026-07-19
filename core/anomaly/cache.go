// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"hash/fnv"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/internal/safefile"
)

const maxModelBytes = 64 << 20

// ModelCache serves the current model for each configured artifact path and
// hot-swaps it when guardian-train writes a new version. Change detection is
// content-based (a hash of the file bytes), so it never depends on filesystem
// mtime resolution. A model that fails to load keeps the previous one active.
type ModelCache struct {
	files map[string]*modelFile
	log   *slog.Logger
	stop  chan struct{}
}

type modelFile struct {
	path  string
	hash  atomic.Uint64 // FNV-64a of the last loaded file contents
	model atomic.Pointer[Model]
}

func contentHash(raw []byte) uint64 {
	h := fnv.New64a()
	h.Write(raw)
	return h.Sum64()
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
	raw, err := safefile.Read(f.path, maxModelBytes)
	if err != nil {
		return err
	}
	m, err := ParseModel(raw, f.path)
	if err != nil {
		return err
	}
	f.model.Store(m)
	f.hash.Store(contentHash(raw))
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
		raw, err := safefile.Read(f.path, maxModelBytes)
		if err != nil {
			c.log.Warn("model unreadable, keeping loaded model", "file", f.path, "err", err)
			continue
		}
		hash := contentHash(raw)
		if hash == f.hash.Load() {
			continue
		}
		m, err := ParseModel(raw, f.path)
		if err != nil {
			c.log.Error("model reload failed, keeping previous model", "file", f.path, "err", err)
			f.hash.Store(hash)
			continue
		}
		f.model.Store(m)
		f.hash.Store(hash)
		c.log.Info("anomaly model reloaded", "file", f.path,
			"domains", len(m.Domains), "trained_at", m.TrainedAt)
	}
}

func (c *ModelCache) Close() {
	close(c.stop)
}
