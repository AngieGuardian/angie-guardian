// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store provides the TTL'd shared state Guardian needs to survive
// restarts and (later) to be shared across instances: behavioural IP
// scoreboards, active blocks, issued-challenge records with spent flags.
package store

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"strconv"
	"time"
)

// KV is one live key returned by Scan, with its value and expiry.
type KV struct {
	Key       string
	Value     []byte
	ExpiresAt time.Time // zero = no expiry
}

// BlockCommit is the complete conditional mutation behind one automatic
// behavioural block. GuardValue and ExpectedBlock use the same nil spelling:
// nil requires the corresponding key to be absent.
//
// The guard is the IP's unblock generation. Coupling it to the block CAS and
// offense increment means an unblock is ordered wholly before or wholly after
// this write; there is no successful block followed by a counter increment
// that can leak across an already-completed reset.
type BlockCommit struct {
	BlockKey      string
	ExpectedBlock []byte
	NewBlock      []byte
	BaseTTL       time.Duration
	MaxTTL        time.Duration
	CounterKey    string
	CounterTTL    time.Duration
	HoldKey       string
	GuardKey      string
	GuardValue    []byte
}

// BlockCommitResult reports whether the comparisons succeeded and, when they
// did, the offense count and TTL committed atomically with the block. When
// they did not, Refusal says which one stopped it: the three causes mean
// different things to an operator asking why an IP was not blocked, and only
// the backend that ran them inside its transaction can tell them apart.
type BlockCommitResult struct {
	Committed bool
	Offenses  int64
	TTL       time.Duration
	Refusal   BlockRefusal
}

// BlockRefusal identifies the comparison that stopped a CommitBlock.
type BlockRefusal uint8

const (
	BlockRefusalNone       BlockRefusal = iota // committed
	BlockRefusalHold                           // an unblock of this IP is in flight
	BlockRefusalGeneration                     // an unblock completed since the caller was admitted
	BlockRefusalBlock                          // another writer replaced the block this caller observed
)

func (r BlockRefusal) String() string {
	switch r {
	case BlockRefusalNone:
		return "none"
	case BlockRefusalHold:
		return "unblock_in_flight"
	case BlockRefusalGeneration:
		return "unblock_completed"
	case BlockRefusalBlock:
		return "newer_block"
	}
	return "unknown"
}

// EventCommit is one behaviour-event increment admitted under an unblock
// generation. CounterKey already contains that generation, so a late write
// cannot refill a newer generation. The backend checks that HoldKey is absent
// in the same mutation that increments it.
type EventCommit struct {
	CounterKey string
	CounterTTL time.Duration
	HoldKey    string
}

type EventCommitResult struct {
	Committed bool
	Value     int64
}

// UnblockCommit is the final, atomic boundary of an operator unblock. It
// publishes a fresh suppression hold and generation while removing the active
// block and, when ResetBackoff is true, its repeat-offender counter.
type UnblockCommit struct {
	HoldKey       string
	HoldValue     []byte
	HoldTTL       time.Duration
	GenerationKey string
	Generation    []byte
	GenerationTTL time.Duration
	BlockKey      string
	CounterKey    string
	ResetBackoff  bool
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
	// zero (a no-op that still reports the current value) or negative (plain
	// arithmetic). A negative delta on an absent key creates it at that
	// negative value like any other.
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
	// This is what makes spent-challenge marking replay-safe, and it is how a
	// writer fences a write against state it has not observed.
	CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (swapped bool, err error)

	// CompareAndDelete atomically removes key if its current value is exactly
	// old, and reports whether it did. It is the counterpart CompareAndSwap
	// needs: a writer that has to take back a write it made, without removing
	// whatever somebody else has put there since. old == nil is not the
	// create-only spelling it is on CompareAndSwap and never deletes anything,
	// because an absent key has nothing to take back.
	CompareAndDelete(ctx context.Context, key string, old []byte) (deleted bool, err error)

	// CommitBlock atomically:
	//   1. requires HoldKey to be absent and GuardKey and BlockKey to equal
	//      their expected values;
	//   2. increments CounterKey, preserving a live counter's expiry;
	//   3. derives the exponential block TTL from the resulting count; and
	//   4. writes NewBlock and the counter together.
	// A failed comparison changes nothing. This is intentionally one store
	// primitive: splitting any of these effects lets an unblock or newer block
	// take ownership between them.
	CommitBlock(ctx context.Context, commit BlockCommit) (BlockCommitResult, error)

	// CommitUnblock atomically rotates the generation and suppression hold,
	// removes BlockKey, and optionally removes CounterKey. Automatic block
	// commits compare that generation in the same transaction, so they land
	// entirely before this reset (and are removed) or entirely after it (and
	// fail their stale guard).
	CommitUnblock(ctx context.Context, commit UnblockCommit) error

	// CommitEvent atomically requires an absent unblock hold, then increments
	// the generation-scoped counter. It replaces a racy presence-check followed
	// by Incr without adding another store round trip to the scored-event path.
	CommitEvent(ctx context.Context, commit EventCommit) (EventCommitResult, error)

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

// blockValueSep separates a block's reason from the owner token that follows
// it. A NUL cannot occur in a reason (they are built from config identifiers
// and event names), so a value written before this existed, or by an operator
// poking the store, reads back as a reason with no owner and cannot be claimed
// by anyone.
const blockValueSep = 0

// BlockValue is what goes under a block:<ip> key: the reason an operator
// reads, plus a token identifying this one write.
//
// The token lets a delayed enforcement notification verify that its own block
// is still authoritative instead of publishing an unblock's predecessor or
// overwriting a newer mirror entry. Reasons cannot serve as identity, since
// two blocks of the same IP for the same threshold are byte for byte the same.
// The token need only be unlikely to repeat, not unguessable: nobody outside
// the process ever sees it.
func BlockValue(reason string) []byte {
	b := make([]byte, 0, len(reason)+17)
	b = append(b, reason...)
	b = append(b, blockValueSep)
	return strconv.AppendUint(b, rand.Uint64(), 16)
}

// BlockReason recovers the operator-facing reason from a stored block value,
// dropping the owner token. Everything that shows a block to a human, feeds
// one to Angie, or mirrors one goes through here.
func BlockReason(v []byte) string {
	if i := bytes.IndexByte(v, blockValueSep); i >= 0 {
		return string(v[:i])
	}
	return string(v)
}

// Degenerate block bounds are normalized rather than obeyed: a zero or
// negative TTL means "no expiry" to Set, which for a block is a permanent one
// only an admin can lift. A caller that passes one has a broken config, not an
// intent to block forever.
const (
	defaultBlockBaseTTL = time.Minute
	defaultBlockMaxTTL  = 30 * 24 * time.Hour
)

// BackoffBounds normalizes CommitBlock's TTL bounds. Every backend must apply
// it before deriving a TTL, including the ones that compute the ladder outside
// blockBackoffTTL (Redis does it in Lua), or the same commit would produce a
// different block depending on the store behind it.
func BackoffBounds(base, cap time.Duration) (time.Duration, time.Duration) {
	if base <= 0 {
		base = defaultBlockBaseTTL
	}
	if cap <= 0 {
		cap = defaultBlockMaxTTL
	}
	return base, cap
}

// blockBackoffTTL applies the scoreboard's exponential repeat-offender ladder
// without iterating a corrupt/untrusted counter billions of times. Once the
// cap is reached, further offenses cannot change the result.
func blockBackoffTTL(base, cap time.Duration, offenses int64) time.Duration {
	base, cap = BackoffBounds(base, cap)
	ttl := base
	for n := int64(1); n < offenses && ttl < cap; n++ {
		if ttl > cap/2 {
			return cap
		}
		ttl *= 2
	}
	if ttl > cap || ttl <= 0 {
		return cap
	}
	return ttl
}

func counterValue(v []byte) int64 {
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
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
// namespace is indexed when callers mutate it through Store.Set, Delete,
// CompareAndSwap, CompareAndDelete, CommitBlock or CommitUnblock. A conditional
// block mutation is still a block mutation, so it maintains the index exactly
// as its unconditional counterpart does. Incr is not a block mutation API and
// must not be used to create or remove active blocks.
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
