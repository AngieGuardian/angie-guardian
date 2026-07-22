// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"sync"
	"time"
)

// RecentDecision is one terminal non-allow decision, kept in a small
// in-process ring buffer so the admin API (and the dashboard built on it) can
// answer "what did the guardian just act on?" without a store write on the
// decision path. Allows are deliberately not recorded: they are the
// overwhelming common case and carry no report value.
//
// The buffer is per-instance and cleared on restart: a live operator view,
// not an audit log (that role belongs to the structured decision log).
type RecentDecision struct {
	Time   time.Time `json:"time"`
	Host   string    `json:"host"`
	IP     string    `json:"ip"`
	Method string    `json:"method"`
	URI    string    `json:"uri"`
	UA     string    `json:"ua"`
	Action string    `json:"action"`
	Reason string    `json:"reason"`
}

// The recent-decision ring is deliberately a bounded, per-instance live view,
// not a historical store. The default and cap are validated by Config.finalize;
// keep the zero-value fallback here so recentRing remains useful in tests and
// embedded code that constructs one directly.
const (
	defaultRecentSize = 4096
	maxRecentSize     = 16384
)

// RecentDecisionSnapshot is one consistent copy of the live ring plus the
// retention state needed to describe its coverage honestly.
type RecentDecisionSnapshot struct {
	Decisions []RecentDecision
	Capacity  int
	Full      bool
	StartedAt time.Time
}

// recentRing is a fixed-size overwrite-oldest buffer. Only challenged/denied
// requests pass through it, so the mutex sees a tiny fraction of traffic and
// never the allow fast path. Per-instance by design: replicas each report
// their own recent feed (cross-instance aggregation is a metrics concern).
type recentRing struct {
	mu    sync.Mutex
	buf   []RecentDecision
	next  int  // index the next entry is written at
	count int  // initialized entries, up to len(buf)
	full  bool // at least one older entry has been overwritten
	// startedAt is when this ring began observing decisions. It distinguishes
	// an empty covered interval from time before this process existed.
	startedAt time.Time
}

func newRecentRing(size int) *recentRing {
	if size <= 0 {
		size = defaultRecentSize
	}
	return &recentRing{buf: make([]RecentDecision, size), startedAt: time.Now()}
}

func (r *recentRing) add(d RecentDecision) {
	r.mu.Lock()
	if len(r.buf) == 0 {
		r.buf = make([]RecentDecision, defaultRecentSize)
		r.startedAt = time.Now()
	}
	if r.count == len(r.buf) {
		r.full = true
	} else {
		r.count++
	}
	r.buf[r.next] = d
	r.next++
	if r.next == len(r.buf) {
		r.next = 0
	}
	r.mu.Unlock()
}

// snapshot returns up to limit entries, newest first, together with retention
// metadata captured under the same lock. limit <= 0 means all.
func (r *recentRing) snapshot(limit int) RecentDecisionSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	capacity := len(r.buf)
	if capacity == 0 {
		capacity = defaultRecentSize
	}
	n := r.count
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]RecentDecision, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, r.buf[(r.next-i+len(r.buf))%len(r.buf)])
	}
	return RecentDecisionSnapshot{
		Decisions: out,
		Capacity:  capacity,
		Full:      r.full,
		StartedAt: r.startedAt,
	}
}

// list returns up to limit entries, newest first. limit <= 0 means all.
func (r *recentRing) list(limit int) []RecentDecision { return r.snapshot(limit).Decisions }
