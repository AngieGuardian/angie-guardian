// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Memory is an in-process Store for development, testing and single-instance
// setups that can afford to lose state on restart.
type Memory struct {
	mu   sync.Mutex
	m    map[string]entry
	done chan struct{}
}

type entry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

func (e entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

func NewMemory() *Memory {
	s := &Memory{m: make(map[string]entry), done: make(chan struct{})}
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
	return nil
}

func (s *Memory) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *Memory) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.IncrBy(ctx, key, 1, ttl)
}

func (s *Memory) IncrBy(_ context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.get(key)
	if !ok {
		s.m[key] = entry{value: []byte(strconv.FormatInt(delta, 10)), expiresAt: expiry(ttl)}
		return delta, nil
	}
	n, err := strconv.ParseInt(string(e.value), 10, 64)
	if err != nil {
		return 0, err
	}
	n += delta
	e.value = []byte(strconv.FormatInt(n, 10))
	s.m[key] = e
	return n, nil
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

func (s *Memory) Scan(_ context.Context, prefix string) ([]KV, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []KV
	for k, e := range s.m {
		if !strings.HasPrefix(k, prefix) || e.expired(now) {
			continue
		}
		out = append(out, KV{Key: k, Value: bytes.Clone(e.value), ExpiresAt: e.expiresAt})
	}
	slices.SortFunc(out, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
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
