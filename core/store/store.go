// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store provides the TTL'd shared state Guardian needs to survive
// restarts and (later) to be shared across instances: behavioural IP
// scoreboards, active blocks, issued-challenge records with spent flags.
package store

import (
	"context"
	"errors"
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

	// IncrBy atomically adds delta to the decimal counter at key and returns
	// the new value. Semantics match Incr with delta 1: a missing or expired
	// key starts at delta with the given TTL; an existing key keeps its
	// original expiry. It lets a caller that coalesced several events flush
	// the whole batch in one round instead of losing all but one. delta may be
	// zero (a no-op that still reports the current value) but should not be
	// negative for the counter use cases here.
	IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)

	// IncrByDeadline is IncrBy against an absolute window deadline (unix nanos,
	// 0 = no expiry) instead of a relative TTL, enforced atomically. Each
	// backend, under its own lock/transaction/script, must:
	//   1. compare its current clock against deadline;
	//   2. if the deadline has passed, make no write and return applied=false
	//      (value is the current stored count, or 0 if absent);
	//   3. if the key is absent, create it at delta expiring exactly at the
	//      deadline (not now+something), so a late create cannot outlive its
	//      window, and return applied=true;
	//   4. if the key exists and is live, add delta preserving its existing
	//      expiry, and return applied=true.
	// This lets a caller coalescing per-window counters flush a whole batch in
	// one round without a delayed flush polluting the next window. Incr and
	// IncrBy are defined in terms of this.
	IncrByDeadline(ctx context.Context, key string, delta, deadline int64) (value int64, applied bool, err error)

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

// LimitedScanner is an optional Store capability used by bounded background
// reconciliation. complete is false when more live matching keys exist beyond
// limit. A non-positive limit requests the full result, like Store.Scan.
type LimitedScanner interface {
	ScanLimit(ctx context.Context, prefix string, limit int) (kvs []KV, complete bool, err error)
}

// ErrCapabilityUnsupported lets callers safely fall back when a wrapper or
// third-party Store has not implemented one of the bounded, backend-native
// indexes below.
var ErrCapabilityUnsupported = errors.New("store capability unsupported")

// PostureVotes is the bounded fleet-posture primitive. Implementations keep
// votes outside the general keyspace so a detector tick never scans unrelated
// challenge, scoreboard, or bot-verification keys. MaxPostureVote excludes the
// caller's own vote, which prevents a replica feeding its previous level back
// into its hysteresis state machine.
type PostureVotes interface {
	SetPostureVote(ctx context.Context, instanceID string, level int, ttl time.Duration) error
	DeletePostureVote(ctx context.Context, instanceID string) error
	MaxPostureVote(ctx context.Context, excludeInstanceID string) (level int, err error)
}

// ActiveBlockScanner enumerates the active-block index without walking the
// store's general keyspace. complete is false when the caller's limit omitted
// entries, matching LimitedScanner's safety contract. The reserved block:*
// namespace is indexed when callers mutate it through Store.Set/Delete (the
// production Scoreboard contract); CompareAndSwap/Incr are not block mutation
// APIs and must not be used to create or remove active blocks.
type ActiveBlockScanner interface {
	ScanActiveBlocks(ctx context.Context, prefix string, limit int) (kvs []KV, complete bool, err error)
}

// ServerClock is an optional capability of stores that run on a remote host
// with its own clock (redis/valkey). IncrByDeadline compares caller-computed
// absolute deadlines against the server's clock, so skew between the two
// silently shifts every counter window: a server running ahead by more than a
// window makes every flush return applied=false and deltas are discarded with
// zero errors. The health checker probes this to expose skew as a gauge and a
// warning. Embedded backends share the process clock and do not implement it.
type ServerClock interface {
	ServerTime(ctx context.Context) (time.Time, error)
}

// Every shipping backend must implement the full Store contract plus all the
// optional capabilities, so the enforcement mirror (block index) and attack-mode
// fleet posture work on any configured backend. These assertions fail the build
// if a backend regresses one of them. ServerClock is deliberately not in this
// list: it only makes sense for remote backends.
var (
	_ = []Store{(*ShardedMemory)(nil), (*BuntDB)(nil), (*Pebble)(nil), (*Redis)(nil)}
	_ = []LimitedScanner{(*ShardedMemory)(nil), (*BuntDB)(nil), (*Pebble)(nil), (*Redis)(nil)}
	_ = []ActiveBlockScanner{(*ShardedMemory)(nil), (*BuntDB)(nil), (*Pebble)(nil), (*Redis)(nil)}
	_ = []PostureVotes{(*ShardedMemory)(nil), (*BuntDB)(nil), (*Pebble)(nil), (*Redis)(nil)}
	_ = []ServerClock{(*Redis)(nil)}
)
