// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/internal/safefile"
)

type ModelSpec struct {
	Path          string
	RequiredHosts []string
}

type ModelStatus struct {
	Path      string         `json:"path"`
	TrainedAt time.Time      `json:"trained_at"`
	Domains   map[string]int `json:"domains"`
}

// ModelCache serves the current model for each configured artifact path and
// hot-swaps it when guardian-train writes a new version. Change detection is
// content-based (a hash of the file bytes), so it never depends on filesystem
// mtime resolution. A model that fails to load keeps the previous one active.
type ModelCache struct {
	files   map[string]*modelFile
	log     *slog.Logger
	stop    chan struct{}
	metrics atomic.Pointer[metrics.Metrics] // nil until SetMetrics; nil-safe methods
}

// SetMetrics attaches the metrics sink and immediately publishes the trained
// timestamp of every loaded artifact, so the model-age gauge exists from the
// first scrape rather than the first hot swap. Atomic because the engine
// attaches metrics after Start, when the poller may already be reloading.
func (c *ModelCache) SetMetrics(m *metrics.Metrics) {
	if c == nil {
		return
	}
	c.metrics.Store(m)
	for _, f := range c.files {
		if model := f.model.Load(); model != nil {
			m.AnomalyModelTrainedAt(f.path, model.TrainedAt.Unix())
		}
	}
}

// Paths lists the configured artifact paths. The files map is immutable after
// construction, so this is safe without locking; reload uses it to diff the
// old cache against the new one.
func (c *ModelCache) Paths() []string {
	if c == nil {
		return nil
	}
	paths := make([]string, 0, len(c.files))
	for p := range c.files {
		paths = append(paths, p)
	}
	return paths
}

type modelFile struct {
	path          string
	requiredHosts []string
	hash          atomic.Uint64 // FNV-64a of the last loaded file contents
	model         atomic.Pointer[Model]
}

func contentHash(raw []byte) uint64 {
	h := fnv.New64a()
	h.Write(raw)
	return h.Sum64()
}

// NewModelCache loads every artifact eagerly. A missing or invalid model
// fails startup for the same reason bad WAF rules do: silently running
// without a configured protection is worse than refusing to start.
func NewModelCache(specs []ModelSpec, log *slog.Logger) (*ModelCache, error) {
	c := &ModelCache{files: make(map[string]*modelFile, len(specs)), log: log, stop: make(chan struct{})}
	for _, spec := range specs {
		f := &modelFile{path: spec.Path, requiredHosts: spec.RequiredHosts}
		if err := f.load(); err != nil {
			return nil, err
		}
		c.files[spec.Path] = f
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
	if err := f.validateRequired(m); err != nil {
		return err
	}
	f.model.Store(m)
	f.hash.Store(contentHash(raw))
	return nil
}

func (f *modelFile) validateRequired(m *Model) error {
	for _, host := range f.requiredHosts {
		if !m.HasDomain(host) {
			return fmt.Errorf("model %s: required domain %q has no baseline", f.path, host)
		}
	}
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
		if err := f.validateRequired(m); err != nil {
			c.log.Error("model reload failed, keeping previous model", "file", f.path, "err", err)
			f.hash.Store(hash)
			continue
		}
		f.model.Store(m)
		f.hash.Store(hash)
		c.metrics.Load().AnomalyModelTrainedAt(f.path, m.TrainedAt.Unix())
		c.log.Info("anomaly model reloaded", "file", f.path,
			"domains", len(m.Domains), "trained_at", m.TrainedAt)
	}
}

func (c *ModelCache) Status() []ModelStatus {
	out := make([]ModelStatus, 0, len(c.files))
	for _, f := range c.files {
		m := f.model.Load()
		if m == nil {
			continue
		}
		out = append(out, ModelStatus{Path: f.path, TrainedAt: m.TrainedAt, Domains: m.DomainSummary()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (c *ModelCache) Close() {
	close(c.stop)
}
