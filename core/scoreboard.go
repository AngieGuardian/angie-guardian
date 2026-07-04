// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// BlockKey is the store key holding an active behavioural block for an IP.
// Written by the scoreboard, read by the behaviour-block pipeline stage.
func BlockKey(ip string) string { return "block:" + ip }

func blockCountKey(ip string) string { return "blkct:" + ip }

// Scoreboard counts bad-behaviour events per IP in time-bucketed windows and
// places TTL'd blocks when a per-domain threshold is crossed. Only discrete
// bad events are counted (signature hits, PoW failures, tamper, honeypot):
// they are rare, so a store write per event is affordable. It is inherently
// stateful (needs the shared store), so it lives with the sidecar, not in the
// store-free stateless package.
type Scoreboard struct {
	store store.Store
	log   *slog.Logger
	now   func() time.Time
}

func NewScoreboard(st store.Store, log *slog.Logger) *Scoreboard {
	return &Scoreboard{store: st, log: log, now: time.Now}
}

// RecordEvent counts one occurrence of evtype for ip within window. When the
// bucket reaches limit the IP is blocked. Returns whether a block was placed.
func (s *Scoreboard) RecordEvent(ctx context.Context, ip, evtype string, limit int, window, blockTTL, maxBlockTTL time.Duration) (bool, error) {
	if limit <= 0 || window <= 0 {
		return false, nil
	}
	bucket := s.now().Unix() / max(int64(window/time.Second), 1)
	key := fmt.Sprintf("ev:%s:%s:%d", evtype, ip, bucket)
	n, err := s.store.Incr(ctx, key, 2*window)
	if err != nil {
		return false, err
	}
	if n < int64(limit) {
		return false, nil
	}
	return true, s.Block(ctx, ip, "threshold:"+evtype, blockTTL, maxBlockTTL)
}

// hardMaxBlockTTL caps a block TTL when the config leaves maxBlockTTL
// unset/non-positive, so the exponential backoff can never overflow
// time.Duration (which wraps negative around ~2^63ns ≈ 292 years and, being
// ≤ 0, is stored as "no expiry" — a permanent, only-admin-removable block).
const hardMaxBlockTTL = 30 * 24 * time.Hour // 30 days

// Block places a behavioural block with exponential backoff: each block of
// the same IP within 24h doubles the TTL, capped at maxBlockTTL (or a hard
// 30-day ceiling when no cap is configured).
func (s *Scoreboard) Block(ctx context.Context, ip, reason string, ttl, maxBlockTTL time.Duration) error {
	cap := maxBlockTTL
	if cap <= 0 {
		cap = hardMaxBlockTTL
	}
	if ttl <= 0 {
		ttl = time.Minute // degenerate base config; never let the block be permanent
	}
	offenses, err := s.store.Incr(ctx, blockCountKey(ip), 24*time.Hour)
	if err != nil {
		offenses = 1 // still place the base block
	}
	for i := int64(1); i < offenses && ttl < cap; i++ {
		ttl *= 2
	}
	if ttl > cap || ttl <= 0 { // ttl <= 0 guards a doubling that overflowed
		ttl = cap
	}
	s.log.Info("blocking ip", "ip", ip, "reason", reason, "ttl", ttl, "offenses", offenses)
	return s.store.Set(ctx, BlockKey(ip), []byte(reason), ttl)
}

// Unblock lifts an active block (admin action; does not reset backoff).
func (s *Scoreboard) Unblock(ctx context.Context, ip string) error {
	return s.store.Delete(ctx, BlockKey(ip))
}
