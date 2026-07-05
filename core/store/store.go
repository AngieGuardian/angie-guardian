// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store provides the TTL'd shared state Guardian needs to survive
// restarts and (later) to be shared across instances: behavioural IP
// scoreboards, active blocks, issued-challenge records with spent flags.
package store

import (
	"context"
	"time"
)

// KV is one live key returned by Scan, with its value and expiry.
type KV struct {
	Key       string
	Value     []byte
	ExpiresAt time.Time // zero = no expiry
}

// Store is the shared-state interface. All values are TTL-based so nothing
// grows without bound; ttl <= 0 means no expiry.
type Store interface {
	// Get returns the value for key, or ok=false if absent or expired.
	Get(ctx context.Context, key string) (value []byte, ok bool, err error)

	// Set writes value under key, replacing any previous value and TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes key. Deleting an absent key is not an error.
	Delete(ctx context.Context, key string) error

	// Incr atomically increments the decimal counter at key and returns the
	// new value. A missing or expired key starts at 1 with the given TTL;
	// an existing key keeps its original expiry, so time-bucketed keys form
	// cheap sliding-window counters.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)

	// CompareAndSwap atomically replaces the current value with new if it
	// equals old. old == nil requires the key to be absent (create-only).
	// This is what makes spent-challenge marking replay-safe.
	CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (swapped bool, err error)

	// Scan returns every live key with the given literal prefix, sorted by
	// key. An admin/reporting read (listing active blocks), NOT for the auth
	// hot path: it may walk a large keyspace on some backends.
	Scan(ctx context.Context, prefix string) ([]KV, error)

	Close() error
}
