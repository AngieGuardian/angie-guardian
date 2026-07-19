// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package enforce pushes active behavioural blocks onto enforcement layers
// cheaper than a per-request store lookup: an always-on in-process mirror
// consulted by the pipeline's behaviour-block stage, plus optional external
// sinks (an nftables set) that stop blocked traffic before it reaches the
// daemon at all. The package is wired through the Engine only, so the WASM
// guest transport is unaffected by construction.
//
// Fail-open contract: nothing in this package may surface an error into the
// request path. A broken sink, a full mirror or a failed indexed reconcile only
// ever degrades enforcement back to the store-backed lookup.
package enforce

import (
	"net/netip"
	"time"
)

// Mirror consistency modes. "auto" is resolved by the config layer before
// this package sees it: authoritative for single-writer backends (memory,
// bbolt), read_through when the store is shared (redis) so a block placed by
// another replica bites before the next indexed reconcile.
const (
	ModeAuthoritative = "authoritative"
	ModeReadThrough   = "read_through"
)

// Config is the resolved enforcement configuration (core.Config translates
// the YAML surface into this, so the package stays free of the core import).
type Config struct {
	// KeyPrefix is the store prefix holding active blocks ("block:").
	KeyPrefix string
	// ReconcileInterval is the cadence of the active-block index read that
	// seeds the mirror, repairs sink drift and picks up remote block changes.
	ReconcileInterval time.Duration
	// MaxEntries bounds the mirror. Overflow drops the newest insert (with a
	// metric); enforcement for the dropped IP falls back to the store path.
	MaxEntries int
	// Mode is ModeAuthoritative or ModeReadThrough (never "auto" here).
	Mode string

	NFTables NFTConfig
}

// NFTConfig configures the optional kernel sink (Linux only, CAP_NET_ADMIN).
type NFTConfig struct {
	Enabled bool
	// Mode "managed" owns a table with a drop rule scoped to Ports; a crashed
	// daemon's elements expire kernel-side via per-element timeouts.
	// "sets_only" populates the sets and leaves ruleset wiring to the operator.
	Mode  string
	Table string
	Hook  string // managed only: input | prerouting
	Ports []uint16
	// NetNS is a network namespace file to act in; empty means the daemon's
	// own namespace (in docker-compose that is usually NOT where client
	// traffic arrives; see the block-offload guide).
	NetNS      string
	MaxEntries int
	// MinTTL skips offloading blocks shorter than this; 0 offloads all.
	MinTTL time.Duration
	// NeverBlock is the pre-resolved union of the operator's never_block
	// CIDRs and every configured allowlist prefix. Loopback and link-local
	// are excluded unconditionally on top of this.
	NeverBlock []netip.Prefix
}

// BlockEvent is one change to the active block set, fanned out to the mirror
// synchronously and to external sinks via a bounded queue.
type BlockEvent struct {
	IP     netip.Addr    // unmapped, mirroring core.BlockKey semantics
	Reason string        // mirror/admin only; never exported to the kernel
	TTL    time.Duration // remaining lifetime; <= 0 means no expiry
	Remove bool
}

// ActiveBlock is one authoritative block as seen by an indexed reconcile.
type ActiveBlock struct {
	Addr      netip.Addr
	Reason    string
	ExpiresAt time.Time // zero = no expiry
}

// Sink receives block-set changes. Apply must be fast or internally bounded;
// it runs on a dedicated worker goroutine, never on the request path.
// Reconcile receives the full authoritative set and must converge on it,
// re-attempting its own initialization if it previously failed.
type Sink interface {
	Name() string
	Apply(ev BlockEvent) error
	Reconcile(active []ActiveBlock) error
	Status() SinkStatus
	Close() error
}

// SinkStatus is one sink's health snapshot for the admin API and metrics.
type SinkStatus struct {
	Name      string `json:"name"`
	Mode      string `json:"mode,omitempty"`
	Healthy   bool   `json:"healthy"`
	Elements  int    `json:"elements"`
	LastError string `json:"last_error,omitempty"`
}

// MirrorStatus reports the in-process mirror for the admin API.
type MirrorStatus struct {
	Entries         int       `json:"entries"`
	Mode            string    `json:"mode"`
	Seeded          bool      `json:"seeded"`
	Complete        bool      `json:"complete"`
	LastReconcile   time.Time `json:"last_reconcile"`
	ReconcileErrors uint64    `json:"reconcile_errors"`
	Dropped         uint64    `json:"dropped"`
}

// Status is the manager snapshot served by GET /admin/offload.
type Status struct {
	Mirror MirrorStatus `json:"mirror"`
	Sinks  []SinkStatus `json:"sinks"`
}
