// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"time"
)

// OpRecorder receives store operation timings; *metrics.Metrics satisfies it.
// Kept as an interface here so the store package doesn't import metrics
// (which would pull the prometheus client into every store user).
type OpRecorder interface {
	StoreOp(op string, seconds float64, err error)
}

// Instrumented wraps a Store and records op latency + error counts. The
// wrapped backend does the real work; this only times it.
type Instrumented struct {
	inner Store
	recs  []OpRecorder
}

// Instrument wraps inner so every op is reported to each non-nil recorder
// (e.g. Prometheus metrics plus the attack-mode store-degradation signal).
func Instrument(inner Store, recs ...OpRecorder) Store {
	var live []OpRecorder
	for _, r := range recs {
		if r != nil {
			live = append(live, r)
		}
	}
	if len(live) == 0 {
		return inner
	}
	return &Instrumented{inner: inner, recs: live}
}

func (s *Instrumented) observe(op string, start time.Time, err error) {
	secs := time.Since(start).Seconds()
	for _, r := range s.recs {
		r.StoreOp(op, secs, err)
	}
}

func (s *Instrumented) Get(ctx context.Context, key string) ([]byte, bool, error) {
	start := time.Now()
	v, ok, err := s.inner.Get(ctx, key)
	s.observe("get", start, err)
	return v, ok, err
}

func (s *Instrumented) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	start := time.Now()
	err := s.inner.Set(ctx, key, value, ttl)
	s.observe("set", start, err)
	return err
}

func (s *Instrumented) Delete(ctx context.Context, key string) error {
	start := time.Now()
	err := s.inner.Delete(ctx, key)
	s.observe("delete", start, err)
	return err
}

func (s *Instrumented) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	start := time.Now()
	n, err := s.inner.Incr(ctx, key, ttl)
	s.observe("incr", start, err)
	return n, err
}

func (s *Instrumented) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	n, err := s.inner.IncrBy(ctx, key, delta, ttl)
	s.observe("incr", start, err)
	return n, err
}

func (s *Instrumented) IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (int64, bool, error) {
	start := time.Now()
	n, applied, err := s.inner.IncrByDeadline(ctx, key, delta, deadline)
	s.observe("incr", start, err)
	return n, applied, err
}

func (s *Instrumented) CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	start := time.Now()
	ok, err := s.inner.CompareAndSwap(ctx, key, old, new, ttl)
	s.observe("cas", start, err)
	return ok, err
}

func (s *Instrumented) Scan(ctx context.Context, prefix string) ([]KV, error) {
	start := time.Now()
	kvs, err := s.inner.Scan(ctx, prefix)
	s.observe("scan", start, err)
	return kvs, err
}

func (s *Instrumented) ScanLimit(ctx context.Context, prefix string, limit int) ([]KV, bool, error) {
	start := time.Now()
	if inner, ok := s.inner.(LimitedScanner); ok {
		kvs, complete, err := inner.ScanLimit(ctx, prefix, limit)
		s.observe("scan", start, err)
		return kvs, complete, err
	}
	kvs, err := s.inner.Scan(ctx, prefix)
	s.observe("scan", start, err)
	if err != nil || limit <= 0 || len(kvs) <= limit {
		return kvs, true, err
	}
	return kvs[:limit], false, nil
}

func (s *Instrumented) ScanActiveBlocks(ctx context.Context, prefix string, limit int) ([]KV, bool, error) {
	start := time.Now()
	inner, ok := s.inner.(ActiveBlockScanner)
	if !ok {
		s.observe("block_index_scan", start, ErrCapabilityUnsupported)
		return nil, false, ErrCapabilityUnsupported
	}
	kvs, complete, err := inner.ScanActiveBlocks(ctx, prefix, limit)
	s.observe("block_index_scan", start, err)
	return kvs, complete, err
}

func (s *Instrumented) SetPostureVote(ctx context.Context, instanceID string, level int, ttl time.Duration) error {
	start := time.Now()
	inner, ok := s.inner.(PostureVotes)
	if !ok {
		s.observe("posture_set", start, ErrCapabilityUnsupported)
		return ErrCapabilityUnsupported
	}
	err := inner.SetPostureVote(ctx, instanceID, level, ttl)
	s.observe("posture_set", start, err)
	return err
}

func (s *Instrumented) DeletePostureVote(ctx context.Context, instanceID string) error {
	start := time.Now()
	inner, ok := s.inner.(PostureVotes)
	if !ok {
		s.observe("posture_delete", start, ErrCapabilityUnsupported)
		return ErrCapabilityUnsupported
	}
	err := inner.DeletePostureVote(ctx, instanceID)
	s.observe("posture_delete", start, err)
	return err
}

func (s *Instrumented) MaxPostureVote(ctx context.Context, excludeInstanceID string) (int, error) {
	start := time.Now()
	inner, ok := s.inner.(PostureVotes)
	if !ok {
		s.observe("posture_max", start, ErrCapabilityUnsupported)
		return 0, ErrCapabilityUnsupported
	}
	level, err := inner.MaxPostureVote(ctx, excludeInstanceID)
	s.observe("posture_max", start, err)
	return level, err
}

func (s *Instrumented) Close() error { return s.inner.Close() }
