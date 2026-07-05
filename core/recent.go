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

// recentSize bounds the ring. 512 entries × ~200 bytes ≈ 100 KiB, fixed.
const recentSize = 512

// recentRing is a fixed-size overwrite-oldest buffer. Only challenged/denied
// requests pass through it, so the mutex sees a tiny fraction of traffic and
// never the allow fast path. Per-instance by design: replicas each report
// their own recent feed (cross-instance aggregation is a metrics concern).
type recentRing struct {
	mu   sync.Mutex
	buf  [recentSize]RecentDecision
	next int  // index the next entry is written at
	full bool // buf has wrapped at least once
}

func (r *recentRing) add(d RecentDecision) {
	r.mu.Lock()
	r.buf[r.next] = d
	r.next++
	if r.next == recentSize {
		r.next = 0
		r.full = true
	}
	r.mu.Unlock()
}

// list returns up to limit entries, newest first. limit <= 0 means all.
func (r *recentRing) list(limit int) []RecentDecision {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = recentSize
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]RecentDecision, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, r.buf[(r.next-i+recentSize)%recentSize])
	}
	return out
}
