// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/core/waf"
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
// behavioural scoreboard consumes these to learn. Types matching a key in
// waf.ip_behaviour.thresholds are rate-counted; EventInstantBlock blocks
// immediately.
type Event struct {
	Type   string
	Detail string
}

const (
	EventSignature    = "signature"
	EventPoWFail      = "pow_fail"
	EventTamper       = "tamper"
	EventInstantBlock = "instant_block"
)

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
	rules  *waf.RuleCache
	board  *waf.Scoreboard
	stages []Stage
	log    *slog.Logger
}

// rulesReloadInterval is how often WAF rules files are polled for changes.
const rulesReloadInterval = 10 * time.Second

func NewEngine(cfg *Config, st store.Store, powMgr *pow.Manager, log *slog.Logger) (*Engine, error) {
	rules, err := waf.NewRuleCache(cfg.RuleFiles(), log)
	if err != nil {
		return nil, err
	}
	rules.Start(rulesReloadInterval)
	return &Engine{
		cfg:   cfg,
		store: st,
		pow:   powMgr,
		rules: rules,
		board: waf.NewScoreboard(st, log),
		log:   log,
		stages: []Stage{
			// Pipeline order per plan §3; first terminal decision wins.
			// Signatures run before the token stage so vouched clients keep
			// passing the cheap WAF checks (stage "4-lite" from the plan).
			allowlistStage{},      // 0. static allowlist
			denylistStage{},       // 1. static denylist
			behaviourBlockStage{}, // 2. behavioural IP block (store-backed)
			honeypotStage{},       //    trap paths: one hit blocks
			wafSignatureStage{},   // 4. keyword/regex signatures
			powTokenStage{},       // 3. valid PoW token → allow
			// 5. anomaly score (P3)
			powChallengeStage{}, // 6. suspicion decision (challenge unvouched browsers)
		},
	}, nil
}

// Close stops background work (rules hot-reload polling).
func (e *Engine) Close() {
	e.rules.Close()
}

// Evaluate resolves the domain config for the request's host and runs the
// pipeline. Stage errors fail open: Guardian degrades to "allow" rather than
// taking a site down with it.
func (e *Engine) Evaluate(ctx context.Context, req *RequestContext) Decision {
	dcfg := e.cfg.DomainFor(req.Host)
	env := &stageEnv{store: e.store, domain: dcfg, pow: e.pow, rules: e.rules}
	for _, s := range e.stages {
		d, err := s.Evaluate(ctx, req, env)
		if err != nil {
			e.log.Warn("stage error, failing open",
				"stage", s.Name(), "host", req.Host, "ip", req.RemoteAddr, "err", err)
			continue
		}
		if d != nil {
			e.recordEvents(ctx, req.RemoteAddr, dcfg, d.Events)
			return *d
		}
	}
	return Decision{Action: ActionAllow, Reason: "default"}
}

// recordEvents feeds behaviour events into the scoreboard. Bad events are
// rare by construction, so the store writes stay off the common path.
func (e *Engine) recordEvents(ctx context.Context, ip string, dcfg *DomainConfig, events []Event) {
	if len(events) == 0 {
		return
	}
	ib := &dcfg.WAF.IPBehaviour
	if !ib.Enabled {
		return
	}
	for _, ev := range events {
		var err error
		switch ev.Type {
		case EventInstantBlock:
			err = e.board.Block(ctx, ip, ev.Detail, ib.BlockTTL.Std(), ib.MaxBlockTTL.Std())
		default:
			if rate, ok := ib.Thresholds[ev.Type]; ok {
				_, err = e.board.RecordEvent(ctx, ip, ev.Type, rate.Count, rate.Per,
					ib.BlockTTL.Std(), ib.MaxBlockTTL.Std())
			}
		}
		if err != nil {
			e.log.Warn("event recording failed", "type", ev.Type, "ip", ip, "err", err)
		}
	}
}

// ReportEvent lets transports feed behaviour events observed outside the
// pipeline (failed PoW redemptions, forged IDs). Allowlisted IPs are never
// scored, so a shared office NAT can't block itself.
func (e *Engine) ReportEvent(ctx context.Context, host, ip, evtype, detail string) {
	dcfg := e.cfg.DomainFor(host)
	if evtype == EventTamper && !dcfg.WAF.UUIDTamper.Enabled {
		return
	}
	if addr, err := netip.ParseAddr(ip); err == nil && dcfg.Allowlist.MatchIP(addr) {
		return
	}
	e.recordEvents(ctx, ip, dcfg, []Event{{Type: evtype, Detail: detail}})
}

// BlockIP places a temporary behavioural block with an explicit TTL (no
// backoff): an operator/admin-API primitive.
func (e *Engine) BlockIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	return e.store.Set(ctx, waf.BlockKey(ip), []byte(reason), ttl)
}

// UnblockIP clears a behavioural block.
func (e *Engine) UnblockIP(ctx context.Context, ip string) error {
	return e.board.Unblock(ctx, ip)
}
