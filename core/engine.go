// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// RequestContext carries only primitives so it can be populated from an HTTP
// request (Path A), a cgo struct (Path B) or WASM host calls (Path C).
type RequestContext struct {
	Host       string
	Method     string
	URI        string // path with query string, as received
	RemoteAddr string // client IP, no port
	UserAgent  string
	Cookie     string // raw Cookie header
}

type Action string

const (
	ActionAllow     Action = "allow"
	ActionChallenge Action = "challenge"
	ActionDeny      Action = "deny"
)

// Event is a behaviour observation emitted alongside a decision; the
// behavioural scoreboard (P2) consumes these to learn.
type Event struct {
	Type   string
	Detail string
}

// Decision is the outcome of evaluating one request.
type Decision struct {
	Action     Action
	Difficulty int // PoW difficulty when Action == ActionChallenge
	Reason     string
	Events     []Event
}

// Engine runs the ordered decision pipeline. This is THE seam: every
// transport wraps Evaluate and nothing else.
type Engine struct {
	cfg    *Config
	store  store.Store
	pow    *pow.Manager // nil when no signing key is configured: PoW stages inert
	stages []Stage
	log    *slog.Logger
}

func NewEngine(cfg *Config, st store.Store, powMgr *pow.Manager, log *slog.Logger) *Engine {
	return &Engine{
		cfg:   cfg,
		store: st,
		pow:   powMgr,
		log:   log,
		stages: []Stage{
			// Pipeline order per plan §3; first terminal decision wins.
			allowlistStage{},      // 0. static allowlist
			denylistStage{},       // 1. static denylist
			behaviourBlockStage{}, // 2. behavioural IP block (store-backed)
			powTokenStage{},       // 3. valid PoW token → allow
			// 4. WAF signatures              (P2)
			// 5. anomaly score               (P3)
			powChallengeStage{}, // 6. suspicion decision (P1: challenge unvouched browsers)
		},
	}
}

// Evaluate resolves the domain config for the request's host and runs the
// pipeline. Stage errors fail open: Guardian degrades to "allow" rather than
// taking a site down with it.
func (e *Engine) Evaluate(ctx context.Context, req *RequestContext) Decision {
	dcfg := e.cfg.DomainFor(req.Host)
	env := &stageEnv{store: e.store, domain: dcfg, pow: e.pow}
	for _, s := range e.stages {
		d, err := s.Evaluate(ctx, req, env)
		if err != nil {
			e.log.Warn("stage error, failing open",
				"stage", s.Name(), "host", req.Host, "ip", req.RemoteAddr, "err", err)
			continue
		}
		if d != nil {
			return *d
		}
	}
	return Decision{Action: ActionAllow, Reason: "default"}
}

// BlockIP records a temporary behavioural block for an IP. Used by the
// behavioural scoreboard (P2) and the admin API (P4); exposed now so
// operators and tests can exercise pipeline stage 2.
func (e *Engine) BlockIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	return e.store.Set(ctx, blockKey(ip), []byte(reason), ttl)
}

// UnblockIP clears a behavioural block.
func (e *Engine) UnblockIP(ctx context.Context, ip string) error {
	return e.store.Delete(ctx, blockKey(ip))
}

func blockKey(ip string) string { return fmt.Sprintf("block:%s", ip) }
