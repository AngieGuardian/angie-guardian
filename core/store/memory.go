// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Memory is an in-process Store for development, testing and single-instance
// setups that can afford to lose state on restart.
type Memory struct {
	mu           sync.Mutex
	m            map[string]entry
	activeBlocks map[string]struct{}
	postureVotes map[string]postureVote
	done         chan struct{}
}

type entry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

type postureVote struct {
	level     int
	expiresAt time.Time
}

func (e entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

func NewMemory() *Memory {
	s := &Memory{
		m:            make(map[string]entry),
		activeBlocks: make(map[string]struct{}),
		postureVotes: make(map[string]postureVote),
		done:         make(chan struct{}),
	}
	go s.janitor()
	return s
}

func (s *Memory) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			for k, e := range s.m {
				if e.expired(now) {
					delete(s.m, k)
					delete(s.activeBlocks, k)
				}
			}
			for id, vote := range s.postureVotes {
				if !vote.expiresAt.IsZero() && now.After(vote.expiresAt) {
					delete(s.postureVotes, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Memory) get(key string) (entry, bool) {
	e, ok := s.m[key]
	if !ok || e.expired(time.Now()) {
		delete(s.m, key)
		delete(s.activeBlocks, key)
		return entry{}, false
	}
	return e, true
}

func expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}

func (s *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.get(key)
	if !ok {
		return nil, false, nil
	}
	return bytes.Clone(e.value), true, nil
}

func (s *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = entry{value: bytes.Clone(value), expiresAt: expiry(ttl)}
	if strings.HasPrefix(key, "block:") {
		s.activeBlocks[key] = struct{}{}
	}
	return nil
}

func (s *Memory) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	delete(s.activeBlocks, key)
	return nil
}

func (s *Memory) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.IncrBy(ctx, key, 1, ttl)
}

func (s *Memory) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	var deadline int64
	if ttl > 0 {
		deadline = time.Now().Add(ttl).UnixNano()
	}
	n, _, err := s.IncrByDeadline(ctx, key, delta, deadline)
	return n, err
}

func (s *Memory) IncrByDeadline(_ context.Context, key string, delta, deadline int64) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	// (2) A flush delayed past its window's deadline is a no-op: it must not
	// create or extend a record for a window that has already ended.
	if deadline != 0 && now.UnixNano() >= deadline {
		if e, ok := s.get(key); ok {
			n, err := strconv.ParseInt(string(e.value), 10, 64)
			return n, false, err
		}
		return 0, false, nil
	}
	e, ok := s.get(key)
	if !ok {
		// (3) Fresh key: create at delta expiring exactly at the deadline.
		var exp time.Time
		if deadline != 0 {
			exp = time.Unix(0, deadline)
		}
		s.m[key] = entry{value: []byte(strconv.FormatInt(delta, 10)), expiresAt: exp}
		return delta, true, nil
	}
	// (4) Existing live key: add delta, keep the original expiry.
	n, err := strconv.ParseInt(string(e.value), 10, 64)
	if err != nil {
		return 0, false, err
	}
	n += delta
	e.value = []byte(strconv.FormatInt(n, 10))
	s.m[key] = e
	return n, true, nil
}

func (s *Memory) CompareAndSwap(_ context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.get(key)
	if old == nil {
		if ok {
			return false, nil
		}
	} else if !ok || !bytes.Equal(e.value, old) {
		return false, nil
	}
	s.m[key] = entry{value: bytes.Clone(new), expiresAt: expiry(ttl)}
	return true, nil
}

func (s *Memory) Scan(ctx context.Context, prefix string) ([]KV, error) {
	out, _, err := s.ScanLimit(ctx, prefix, 0)
	return out, err
}

func (s *Memory) ScanLimit(_ context.Context, prefix string, limit int) ([]KV, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []KV
	for k, e := range s.m {
		if !strings.HasPrefix(k, prefix) || e.expired(now) {
			continue
		}
		out = append(out, KV{Key: k, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
			slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
			return out, false, nil
		}
	}
	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	return out, true, nil
}

// ScanActiveBlocks walks only the block index, so its cost is independent of
// unrelated keys in the in-memory store.
func (s *Memory) ScanActiveBlocks(_ context.Context, prefix string, limit int) ([]KV, bool, error) {
	if prefix != "block:" {
		return nil, false, ErrCapabilityUnsupported
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]KV, 0, min(len(s.activeBlocks), max(limit, 0)))
	complete := true
	for key := range s.activeBlocks {
		e, ok := s.m[key]
		if !ok || e.expired(now) {
			delete(s.activeBlocks, key)
			delete(s.m, key)
			continue
		}
		out = append(out, KV{Key: key, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
			complete = false
			break
		}
	}
	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	return out, complete, nil
}

func (s *Memory) SetPostureVote(_ context.Context, instanceID string, level int, ttl time.Duration) error {
	if level < 1 || level > 2 || ttl <= 0 {
		return fmt.Errorf("invalid posture vote level=%d ttl=%v", level, ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postureVotes[instanceID] = postureVote{level: level, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *Memory) DeletePostureVote(_ context.Context, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.postureVotes, instanceID)
	return nil
}

func (s *Memory) MaxPostureVote(_ context.Context, excludeInstanceID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	maxLevel := 0
	for id, vote := range s.postureVotes {
		if !vote.expiresAt.IsZero() && now.After(vote.expiresAt) {
			delete(s.postureVotes, id)
			continue
		}
		if id != excludeInstanceID && vote.level > maxLevel {
			maxLevel = vote.level
		}
	}
	return maxLevel, nil
}

func (s *Memory) Close() error {
	close(s.done)
	return nil
}

// ExpiresAt returns the expiry of a live key and whether it exists. A zero
// time means "no expiry" (permanent). Exposed for tests that need to assert on
// the TTL a caller stored, which the Store interface otherwise hides.
func (s *Memory) ExpiresAt(key string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.get(key)
	if !ok {
		return time.Time{}, false
	}
	return e.expiresAt, true
}
