// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/melroy89/angie-guardian/core/botverify"
	"github.com/melroy89/angie-guardian/core/intel"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/stateless"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/core/waf"
)

// The request/decision value types and the store-free WAF checks live in the
// leaf package core/stateless, so the WASM guest can reuse them without
// dragging in the store/pow/anomaly dependencies. core aliases them here so
// all existing core.RequestContext / core.Decision / core.Action references
// (and the sidecar's stateless stages) keep working against one definition.
type (
	RequestContext = stateless.RequestContext
	Decision       = stateless.Decision
	Action         = stateless.Action
	Event          = stateless.Event
)

const (
	ActionAllow     = stateless.ActionAllow
	ActionChallenge = stateless.ActionChallenge
	ActionDeny      = stateless.ActionDeny
)

const (
	EventSignature    = stateless.EventSignature
	EventPoWFail      = stateless.EventPoWFail
	EventTamper       = stateless.EventTamper
	EventAnomaly      = stateless.EventAnomaly
	EventInstantBlock = stateless.EventInstantBlock
	EventBotSpoof     = stateless.EventBotSpoof
)

// Engine runs the ordered decision pipeline. This is THE seam: every
// transport wraps Evaluate and nothing else.
type Engine struct {
	snap    atomic.Pointer[engineSnapshot]
	store   store.Store
	pow     *pow.Manager // nil when no signing key is configured: PoW stages inert
	bots    *botverify.Verifier
	board   *Scoreboard
	metrics *metrics.Metrics // nil = instrumentation disabled (no-op)
	recent  recentRing       // last non-allow decisions, for the admin API
	stages  []Stage
	log     *slog.Logger
}

// engineSnapshot bundles the config with the caches derived from it (rules
// and model files to watch, GeoIP databases, reputation feeds), so a hot
// reload swaps all of them together in one atomic pointer store and a request
// never sees a new config paired with old caches or vice versa.
type engineSnapshot struct {
	cfg    *Config
	rules  *waf.RuleCache
	models *anomaly.ModelCache
	intel  *intel.Provider // nil when no geoip/reputation is configured: intel stages inert
}

func (s *engineSnapshot) close() {
	s.rules.Close()
	s.models.Close()
	s.intel.Close()
}

// SetMetrics attaches a metrics sink. Call once at startup before serving.
func (e *Engine) SetMetrics(m *metrics.Metrics) {
	e.metrics = m
	e.snap.Load().intel.SetMetrics(m)
}

// reloadInterval is how often WAF rules files and anomaly model artifacts
// are polled for changes.
const reloadInterval = 10 * time.Second

// loadSnapshot constructs the config-derived caches without starting their
// background watchers. On error nothing is left open or running.
func loadSnapshot(cfg *Config, log *slog.Logger) (*engineSnapshot, error) {
	rules, err := waf.NewRuleCache(cfg.RuleFiles(), log)
	if err != nil {
		return nil, err
	}
	models, err := anomaly.NewModelCache(cfg.ModelFiles(), log)
	if err != nil {
		rules.Close()
		return nil, err
	}
	itl, err := intel.New(cfg.IntelConfig(), log)
	if err != nil {
		rules.Close()
		models.Close()
		return nil, err
	}
	return &engineSnapshot{cfg: cfg, rules: rules, models: models, intel: itl}, nil
}

// buildSnapshot loads and starts the caches used by a live engine.
func buildSnapshot(cfg *Config, log *slog.Logger) (*engineSnapshot, error) {
	snap, err := loadSnapshot(cfg, log)
	if err != nil {
		return nil, err
	}
	snap.rules.Start(reloadInterval)
	snap.models.Start(reloadInterval)
	snap.intel.Start()
	return snap, nil
}

// ValidateConfigArtifacts eagerly loads every local artifact required to
// construct an engine (rules, anomaly models, GeoIP databases and file-based
// reputation feeds), then immediately releases it. It is the artifact half of
// `guardiand -t`: no listeners or stores are opened and URL feeds are not
// fetched, but anything that would make engine startup fail is reported.
func ValidateConfigArtifacts(cfg *Config, log *slog.Logger) error {
	snap, err := loadSnapshot(cfg, log)
	if err != nil {
		return err
	}
	snap.close()
	return nil
}

func NewEngine(cfg *Config, st store.Store, powMgr *pow.Manager, log *slog.Logger) (*Engine, error) {
	snap, err := buildSnapshot(cfg, log)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		store: st,
		pow:   powMgr,
		bots:  botverify.New(st, log),
		board: NewScoreboard(st, log),
		log:   log,
		stages: []Stage{
			// Pipeline order per plan §3; first terminal decision wins.
			// Signatures run before the token stage so vouched clients keep
			// passing the cheap WAF checks (stage "4-lite" from the plan).
			allowlistStage{},      // 0. static allowlist
			denylistStage{},       // 1. static denylist
			verifiedBotStage{},    //    rDNS-verified crawler allow / impostor deny
			intelDenyStage{},      //    geo scoping + reputation feeds (deny half)
			behaviourBlockStage{}, // 2. behavioural IP block (store-backed)
			honeypotStage{},       //    trap paths: one hit blocks
			wafSignatureStage{},   // 4. keyword/regex signatures
			powTokenStage{},       // 3. valid PoW token → allow
			intelChallengeStage{}, //    geo scoping + reputation feeds (challenge half)
			anomalyStage{},        // 5. anomaly score: deny / scaled challenge
			powChallengeStage{},   // 6. challenge unvouched requests (mode "always")
		},
	}
	e.snap.Store(snap)
	return e, nil
}

// retireGrace is how long a replaced snapshot keeps its caches alive before
// closing them. In-flight requests hold the old snapshot for at most one
// Evaluate (milliseconds, or ~1s when a first-sight bot verification runs a
// DNS lookup), and closing the intel provider unmaps its mmdb readers, so the
// old snapshot must outlive every request that could still be reading it.
const retireGrace = 30 * time.Second

// Reload swaps in a freshly loaded config, rebuilding the caches derived from
// it (WAF rules files, anomaly models, GeoIP databases, reputation feeds).
// Behavioural state (blocks, scoreboard, PoW escalation, bot verdicts) lives
// in the store and is untouched. On error the running config stays active.
func (e *Engine) Reload(cfg *Config) error {
	snap, err := buildSnapshot(cfg, e.log)
	if err != nil {
		return err
	}
	snap.intel.SetMetrics(e.metrics)
	old := e.snap.Swap(snap)
	time.AfterFunc(retireGrace, old.close)
	return nil
}

// Close stops background work (rules/model/geoip/feed refresh).
func (e *Engine) Close() {
	e.snap.Load().close()
}

// Evaluate resolves the domain config for the request's host and runs the
// pipeline. Stage errors fail open: Guardian degrades to "allow" rather than
// taking a site down with it.
func (e *Engine) Evaluate(ctx context.Context, req *RequestContext) Decision {
	start := time.Now()
	snap := e.snap.Load() // one load: the whole request sees one consistent config+caches
	dcfg := snap.cfg.DomainFor(req.Host)
	label := snap.cfg.DomainLabel(req.Host)
	env := &stageEnv{store: e.store, domain: dcfg, domainLabel: label, pow: e.pow, rules: snap.rules, models: snap.models, intel: snap.intel, metrics: e.metrics, bots: e.bots}
	d := Decision{Action: ActionAllow, Reason: "default"}
	for _, s := range e.stages {
		sd, err := s.Evaluate(ctx, req, env)
		if err != nil {
			e.log.Warn("stage error, failing open",
				"stage", s.Name(), "host", req.Host, "ip", req.RemoteAddr, "err", err)
			continue
		}
		if sd != nil {
			e.recordEvents(ctx, req.RemoteAddr, dcfg, sd.Events)
			d = *sd
			break
		}
	}
	e.metrics.EvaluateLatency(time.Since(start).Seconds())
	e.metrics.Decision(string(d.Action), reasonCategory(d.Reason), label)
	if d.Action != ActionAllow {
		e.recent.add(RecentDecision{
			Time: start, Host: req.Host, IP: req.RemoteAddr,
			Method: req.Method, URI: req.URI, UA: req.UserAgent,
			Action: string(d.Action), Reason: d.Reason,
		})
	}
	return d
}

// RecentDecisions returns the last non-allow decisions, newest first, up to
// limit (<= 0 for all). Backed by a bounded in-process ring: per-instance,
// lost on restart. A live operator view, not an audit log (that's the
// structured decision log).
func (e *Engine) RecentDecisions(limit int) []RecentDecision {
	return e.recent.list(limit)
}

// reasonCategory collapses a full reason string ("waf:dotfile-probe",
// "behaviour_block:threshold:signature") to its leading token so the metric
// label stays low-cardinality regardless of rule IDs and detail suffixes.
func reasonCategory(reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		return reason[:i]
	}
	return reason
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
		var blocked bool
		switch ev.Type {
		case EventInstantBlock:
			blocked = true
			err = e.board.Block(ctx, ip, ev.Detail, ib.BlockTTL.Std(), ib.MaxBlockTTL.Std())
		default:
			if rate, ok := ib.Thresholds[ev.Type]; ok {
				blocked, err = e.board.RecordEvent(ctx, ip, ev.Type, rate.Count, rate.Per,
					ib.BlockTTL.Std(), ib.MaxBlockTTL.Std())
			}
		}
		if err != nil {
			e.log.Warn("event recording failed", "type", ev.Type, "ip", ip, "err", err)
		}
		if blocked {
			e.metrics.BlockPlaced(ev.Type)
		}
	}
}

// ReportEvent lets transports feed behaviour events observed outside the
// pipeline (failed PoW redemptions, forged/replayed challenge IDs).
// Allowlisted IPs are never scored, so a shared office NAT can't block itself.
// The event is recorded only if its type has a configured threshold in
// waf.ip_behaviour.thresholds (tamper and pow_fail are on by default), so PoW
// redemption tampering is scored out of the box rather than gated behind a
// separate feature toggle.
func (e *Engine) ReportEvent(ctx context.Context, host, ip, evtype, detail string) {
	dcfg := e.Config().DomainFor(host)
	if addr, err := netip.ParseAddr(ip); err == nil && dcfg.Allowlist.MatchIP(addr) {
		return
	}
	e.recordEvents(ctx, ip, dcfg, []Event{{Type: evtype, Detail: detail}})
}

// BlockIP places a temporary behavioural block with an explicit TTL (no
// backoff): an operator/admin-API primitive.
func (e *Engine) BlockIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	return e.store.Set(ctx, BlockKey(ip), []byte(reason), ttl)
}

// UnblockIP clears a behavioural block.
func (e *Engine) UnblockIP(ctx context.Context, ip string) error {
	return e.board.Unblock(ctx, ip)
}

// BlockStatus reports whether an IP is currently blocked and why (admin API).
func (e *Engine) BlockStatus(ctx context.Context, ip string) (reason string, blocked bool, err error) {
	v, ok, err := e.store.Get(ctx, BlockKey(ip))
	return string(v), ok, err
}

// BlockEntry is one active behavioural block, as listed by the admin API.
type BlockEntry struct {
	IP        string     `json:"ip"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = no expiry
}

// ListBlocks returns every currently active block (admin API / dashboard).
// It scans the store, so it is an occasional admin read, not a hot-path call.
func (e *Engine) ListBlocks(ctx context.Context) ([]BlockEntry, error) {
	kvs, err := e.store.Scan(ctx, blockKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]BlockEntry, 0, len(kvs))
	for _, kv := range kvs {
		b := BlockEntry{IP: kv.Key[len(blockKeyPrefix):], Reason: string(kv.Value)}
		if !kv.ExpiresAt.IsZero() {
			exp := kv.ExpiresAt
			b.ExpiresAt = &exp
		}
		out = append(out, b)
	}
	return out, nil
}

// ScoreRequest runs the anomaly scorer for a hypothetical request against the
// domain's model, for admin inspection ("why would this be challenged?").
// Returns -1 when the domain has no anomaly model loaded.
func (e *Engine) ScoreRequest(host, uri, ua string) float64 {
	snap := e.snap.Load()
	dcfg := snap.cfg.DomainFor(host)
	if !dcfg.WAF.Anomaly.Enabled {
		return -1
	}
	m := snap.models.Get(dcfg.WAF.Anomaly.Model)
	if m == nil {
		return -1
	}
	return m.Score(host, decodePath(requestPath(uri)), decodeQuery(requestQuery(uri)), ua)
}

// PoWManager exposes the PoW manager for admin key rotation (may be nil).
func (e *Engine) PoWManager() *pow.Manager { return e.pow }

// BotVerifier exposes the crawler rDNS verifier (tests swap its resolver).
func (e *Engine) BotVerifier() *botverify.Verifier { return e.bots }

// Intel exposes the intel provider for admin inspection (may be nil; its
// methods are nil-safe).
func (e *Engine) Intel() *intel.Provider { return e.snap.Load().intel }

// Config exposes the currently active configuration. Callers must treat it as
// a point-in-time snapshot: a hot reload swaps it, so hold the returned
// pointer for one request, never across requests.
func (e *Engine) Config() *Config { return e.snap.Load().cfg }
