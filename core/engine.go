// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/botverify"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/health"
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
	ActionRefuse    = stateless.ActionRefuse
)

const (
	EventRuleMatch     = stateless.EventRuleMatch
	EventPoWFail       = stateless.EventPoWFail
	EventTamper        = stateless.EventTamper
	EventAnomaly       = stateless.EventAnomaly
	EventInstantBlock  = stateless.EventInstantBlock
	EventBotSpoof      = stateless.EventBotSpoof
	EventChallengeFarm = stateless.EventChallengeFarm
)

// Engine runs the ordered decision pipeline. This is THE seam: every
// transport wraps Evaluate and nothing else.
type Engine struct {
	snap atomic.Pointer[engineSnapshot]
	// lastCfg mirrors the active snapshot's config and is never nil'd, so the
	// per-request Config() accessor stays panic-free for straggler requests
	// racing Close during shutdown (they fail open like Evaluate does).
	lastCfg  atomic.Pointer[Config]
	store    store.Store
	pow      *pow.Manager // nil when no signing key is configured: PoW stages inert
	bots     *botverify.Verifier
	board    *Scoreboard
	metrics  *metrics.Metrics     // nil = instrumentation disabled (no-op)
	enforcer *enforce.Manager     // nil = mirror/offload disabled (store-only enforcement)
	attack   *attackmode.Detector // nil = attack mode disabled (always Normal)
	health   *health.Checker      // nil = no store probe (readiness reports unavailable)
	recent   *recentRing          // last non-allow decisions + PoW outcomes, for the admin API
	stages   []Stage
	log      *slog.Logger
	lifeMu   sync.Mutex // serializes Reload and Close
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
	refs   atomic.Int64    // engine ownership + in-flight evaluators
}

func (s *engineSnapshot) acquire() bool {
	for {
		n := s.refs.Load()
		if n <= 0 {
			return false
		}
		if s.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (s *engineSnapshot) release() {
	if s.refs.Add(-1) == 0 {
		s.rules.Close()
		s.models.Close()
		s.intel.Close()
	}
}

// SetMetrics attaches a metrics sink. Call once at startup before serving.
func (e *Engine) SetMetrics(m *metrics.Metrics) {
	e.metrics = m
	snap := e.snap.Load()
	snap.intel.SetMetrics(m)
	snap.models.SetMetrics(m)
}

// SetEnforcer attaches the enforcement offload manager. Call once at startup
// before serving; a nil manager (the default) keeps the store-only block
// path, which is what unit tests and the config validator run with.
func (e *Engine) SetEnforcer(enf *enforce.Manager) {
	e.enforcer = enf
	e.board.enforcer = enf
}

// Enforcer exposes the offload manager for the admin API (may be nil; its
// methods are nil-safe).
func (e *Engine) Enforcer() *enforce.Manager { return e.enforcer }

// SetAttackDetector attaches the global attack-mode detector. Call once at
// startup before serving; nil (the default) keeps the posture at Normal.
func (e *Engine) SetAttackDetector(d *attackmode.Detector) { e.attack = d }

// AttackDetector exposes the detector for the admin API and the transport's
// signal feeds (may be nil; its methods are nil-safe).
func (e *Engine) AttackDetector() *attackmode.Detector { return e.attack }

// SetHealth attaches the background store-health checker. Call once at startup
// before serving; nil (the default) means no probe runs, which /readyz reports
// as unavailable rather than quietly degrading readiness to liveness.
func (e *Engine) SetHealth(hc *health.Checker) { e.health = hc }

// Health exposes the store-health checker for the admin API (may be nil; its
// methods are nil-safe).
func (e *Engine) Health() *health.Checker { return e.health }

// reloadInterval is how often WAF rules files and anomaly model artifacts
// are polled for changes.
const reloadInterval = 10 * time.Second

// loadSnapshot constructs the config-derived caches without starting their
// background watchers. On error nothing is left open or running.
func loadSnapshot(cfg *Config, log *slog.Logger) (*engineSnapshot, error) {
	rules, err := waf.NewRuleCacheVariants(cfg.RuleVariants(), log)
	if err != nil {
		return nil, err
	}
	models, err := anomaly.NewModelCache(cfg.ModelSpecs(), log)
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
	snap := &engineSnapshot{cfg: cfg, rules: rules, models: models, intel: itl}
	snap.refs.Store(1) // ownership held by the engine or validation caller
	return snap, nil
}

// buildSnapshot loads and starts the caches used by a live engine.
func buildSnapshot(cfg *Config, log *slog.Logger) (*engineSnapshot, error) {
	snap, err := loadSnapshot(cfg, log)
	if err != nil {
		return nil, err
	}
	startSnapshot(snap)
	return snap, nil
}

func startSnapshot(snap *engineSnapshot) {
	snap.rules.Start(reloadInterval)
	snap.models.Start(reloadInterval)
	snap.intel.Start()
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
	snap.release()
	return nil
}

func NewEngine(cfg *Config, st store.Store, powMgr *pow.Manager, log *slog.Logger) (*Engine, error) {
	snap, err := buildSnapshot(cfg, log)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		store:  st,
		pow:    powMgr,
		bots:   botverify.New(st, log),
		board:  NewScoreboard(st, log),
		recent: newRecentRing(cfg.Admin.RecentSize),
		log:    log,
		stages: []Stage{
			// Evaluated in this order; the first stage to return a terminal
			// decision wins and the rest are skipped. WAF rules run before the
			// token stage so vouched clients keep paying the cheap WAF checks,
			// which is what stops a stolen token riding past the WAF rules.
			allowlistStage{},      // 0. static allowlist
			denylistStage{},       // 1. static denylist
			verifiedBotStage{},    //    rDNS-verified crawler allow / impostor deny
			intelDenyStage{},      //    geo scoping + reputation feeds (deny half)
			behaviourBlockStage{}, // 2. behavioural IP block (store-backed)
			honeypotStage{},       //    trap paths: one hit blocks
			wafRulesStage{},       // 4. WAF rules (literal/regex matchers)
			powTokenStage{},       // 3. valid PoW token → allow
			intelChallengeStage{}, //    geo scoping + reputation feeds (challenge half)
			anomalyStage{},        // 5. anomaly score: deny / scaled challenge
			powChallengeStage{},   // 6. challenge unvouched requests (mode "always")
		},
	}
	e.snap.Store(snap)
	e.lastCfg.Store(snap.cfg)
	return e, nil
}

// Reload swaps in a freshly loaded config, rebuilding the caches derived from
// it (WAF rules files, anomaly models, GeoIP databases, reputation feeds).
// Behavioural state (blocks, scoreboard, PoW escalation, bot verdicts) lives
// in the store and is untouched. On error the running config stays active.
func (e *Engine) Reload(cfg *Config) error {
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	if e.snap.Load() == nil {
		return errors.New("engine is closed")
	}
	// Construct without starting URL fetchers, synchronously inherit the last
	// good state of unchanged remote feeds, then make background refresh live.
	// This preserves active deny/reputation protection across a reload even if
	// the remote feed is temporarily unavailable and no cache_dir is configured.
	snap, err := loadSnapshot(cfg, e.log)
	if err != nil {
		return err
	}
	old := e.snap.Load()
	snap.intel.SeedURLFeedsFrom(old.intel)
	startSnapshot(snap)
	snap.intel.SetMetrics(e.metrics)
	snap.models.SetMetrics(e.metrics)
	old = e.snap.Swap(snap)
	e.lastCfg.Store(snap.cfg)
	// Drop the age gauge of any model artifact this reload removed, or the
	// frozen series would eventually fire the staleness alert for a model the
	// process no longer loads.
	kept := make(map[string]bool)
	for _, p := range snap.models.Paths() {
		kept[p] = true
	}
	for _, p := range old.models.Paths() {
		if !kept[p] {
			e.metrics.AnomalyModelRemoved(p)
		}
	}
	old.release() // resources close after the final in-flight evaluator releases
	// attack_mode is hot-reloadable: push the new thresholds/effects into the
	// live detector (nil-safe).
	e.attack.SetConfig(cfg.AttackModeSettings())
	return nil
}

// Close stops background work (rules/model/geoip/feed refresh).
func (e *Engine) Close() {
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	if snap := e.snap.Swap(nil); snap != nil {
		snap.release()
	}
}

func (e *Engine) acquireSnapshot() *engineSnapshot {
	for {
		snap := e.snap.Load()
		if snap == nil {
			return nil
		}
		if snap.acquire() {
			return snap
		}
	}
}

// OriginASN returns the active snapshot's ASN for an address. It is used only
// on expensive redemption paths, where an ASN-wide admission bucket prevents
// an attacker rotating across many addresses from multiplying the no-script
// or Argon2id verification allowance. The lookup is in-memory and returns zero
// when no ASN database or record is available.
func (e *Engine) OriginASN(ip string) uint32 {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	snap := e.acquireSnapshot()
	if snap == nil {
		return 0
	}
	defer snap.release()
	return snap.intel.Lookup(addr).ASN
}

// Evaluate resolves the effective config for the request's host and path and
// runs the pipeline. Stage errors fail open: Guardian degrades to "allow"
// rather than taking a site down with it.
func (e *Engine) Evaluate(ctx context.Context, req *RequestContext) Decision {
	start := time.Now()
	snap := e.acquireSnapshot()
	if snap == nil {
		return Decision{Action: ActionAllow, Reason: "engine:closed"}
	}
	defer snap.release()
	e.attack.Evaluated() // one atomic add; nil-safe
	// One host normalization and one path normalization for the whole request:
	// the config lookup and the metric label share the former, and every
	// path-matching stage shares the latter through the request's memo. The
	// metric label stays host-scoped because paths are client-controlled and
	// unbounded, so they must never become a label value.
	dcfg := snap.cfg.scopeForRequest(req)
	// One posture load per request, shared by every stage so a mid-request
	// transition can't split the decision.
	env := &stageEnv{store: e.store, domain: dcfg, pow: e.pow, rules: snap.rules, models: snap.models, intel: snap.intel, metrics: e.metrics, bots: e.bots, enforcer: e.enforcer, attack: e.attack.State()}
	d := Decision{Action: ActionAllow, Reason: "default"}
	for _, s := range e.stages {
		sd, err := s.Evaluate(ctx, req, env)
		if err != nil {
			e.log.Warn("stage error, failing open",
				"stage", s.Name(), "host", req.Host, "ip", req.RemoteAddr, "err", err)
			continue
		}
		if sd != nil {
			e.recordEvents(ctx, req.RemoteAddr, dcfg, sd.Events, e.scoreboardFactor(snap.cfg))
			d = *sd
			break
		}
	}
	// A challenge aimed at a client classified as unable to complete one is
	// recorded as what it actually is. Wire behaviour is unchanged: the
	// transport answers a refusal exactly as it answers a challenge, so Angie
	// still routes to @guardian_challenge, which serves the terse 403 it
	// already served. The conversion itself scores nothing, and neither does
	// the refusal: escalation is bumped by the challenge handler, which
	// refuses before reaching it, so challenge_farm cannot follow. Events a
	// stage already emitted are a separate matter and stand, as recordEvents
	// above has by now recorded them; see the note below. What changes is that
	// /admin/decisions, the decision log and guardian_decisions_total stop
	// reporting an unsatisfiable refusal as an issued challenge, which is what
	// made a favicon poll read as a challenge storm. See
	// RequestContext.Unchallengeable.
	//
	// Deliberately after the stage loop rather than inside one stage: anomaly,
	// pow_challenge, a WAF challenge rule and attack mode can all reach the same
	// client with the same impossibility, so the conversion belongs at the one
	// point they all pass through. Events already recorded stand, since they
	// describe what the request looked like and that is still true.
	// Gated on the same resolved key the challenge handler reads, which is the
	// whole reason it is a config key and not a proxy_set_header: both hops
	// answer from one source for this host and path, so the recorded outcome
	// and the served response cannot disagree.
	//
	// Only a token-failure reason is replaced. ActionRefuse already carries the
	// "no puzzle was issued" half, so overwriting the reason as well would throw
	// away which policy asked for the challenge in the first place: a WAF rule,
	// the anomaly scorer, GeoIP or a reputation feed. That is the signal an
	// operator actually acts on, and folding it into pow:unchallengeable would
	// make guardian_decisions_total{reason="waf"} and every reason-based
	// dashboard undercount. The favicon case reaches here as one of the five
	// pow: reasons, which is exactly the one worth replacing, since naming a
	// missing cookie for a client that could never have sent one is what made
	// this misleading to begin with.
	if d.Action == ActionChallenge && req.Unchallengeable && dcfg.PoW.RefusesUnchallengeable() {
		reason := d.Reason
		if reasonCategory(reason) == "pow" {
			reason = reasonUnchallengeable
		}
		d = Decision{Action: ActionRefuse, Reason: reason}
	}
	e.metrics.EvaluateLatency(time.Since(start).Seconds())
	e.metrics.Decision(string(d.Action), reasonCategory(d.Reason), dcfg.label)
	if d.Action != ActionAllow {
		e.recent.add(RecentDecision{
			Time: start, Host: req.Host, IP: req.RemoteAddr,
			Method: req.Method, URI: req.URI, UA: req.UserAgent,
			Action: string(d.Action), Reason: d.Reason,
		})
	}
	return d
}

// RecentDecisions returns the last non-allow decisions and proof-of-work
// outcomes (solves, failed redemptions), newest first, up to limit (<= 0 for
// all). Backed by a bounded in-process ring: per-instance, lost on restart. A
// live operator view, not an audit log (that's the structured decision log).
func (e *Engine) RecentDecisions(limit int) []RecentDecision {
	return e.recent.list(limit)
}

// SolveRecord is one redeemed proof-of-work challenge, reported by the
// transport once Redeem has succeeded. SolveMS is the client's own
// (unauthenticated) hashing time, 0 when it was not reported or was rejected as
// impossible; RoundTripMS is this process measuring issue to redeem.
type SolveRecord struct {
	Host        string
	IP          string
	URI         string
	UA          string
	SolveMS     int64
	RoundTripMS int64
	Algorithm   string
	Bits        int
	MemoryKiB   uint32
	Iterations  uint32
	NoJS        bool
}

// RecordSolve puts a redeemed challenge into the same recent ring the dashboard
// reads, so the cost of a proof of work is attributable to the host, path, IP
// and User-Agent that paid it.
//
// Deliberately not routed through Evaluate: the pipeline never saw this
// request. Evaluate takes a config snapshot, runs every stage, records evaluate
// latency and increments guardian_decisions_total, and a redemption is none of
// those things; counting it as a decision would double-count the client journey
// the original challenge row already recorded. This is one ring append with no
// store write, exactly like the decision path's own.
//
// Method is left empty: the redemption itself is a POST to the pass endpoint,
// which is not what an operator is looking at, and the original request's
// method was never recorded at issue time. URI is the page the client was
// trying to reach.
func (e *Engine) RecordSolve(rec SolveRecord) {
	reason := ReasonSolved
	if rec.NoJS {
		reason = ReasonNoJS
	}
	algorithm := rec.Algorithm
	if algorithm == "" {
		algorithm = string(pow.AlgorithmSHA256)
	}
	e.recent.add(RecentDecision{
		Time: time.Now(), Host: rec.Host, IP: rec.IP, URI: rec.URI, UA: rec.UA,
		Action: ActionSolve, Reason: reason,
		SolveMS: clampMS(rec.SolveMS), RoundTripMS: clampMS(rec.RoundTripMS),
		PoWAlgorithm: algorithm, Bits: clampBits(rec.Bits),
		Argon2MemoryKiB: rec.MemoryKiB, Argon2Iterations: rec.Iterations,
	})
}

// RecordRedeemFailure puts a failed redemption attempt into the recent ring,
// reported by the transport alongside the funnel's "failed" count so the two
// stay in exact agreement while the ring row keeps what the metric drops: who
// failed, on which host, and why. Like RecordSolve it is deliberately not
// routed through Evaluate (the pipeline never saw this request) and is one
// ring append with no store write.
//
// URI, solve time and difficulty are absent by design: a failed redemption
// usually has no verified challenge record to read them from (an unknown ID
// has nothing at all), and the one case that does is not worth a special
// shape.
func (e *Engine) RecordRedeemFailure(host, ip, ua, reason string) {
	e.recent.add(RecentDecision{
		Time: time.Now(), Host: host, IP: ip, UA: ua,
		Action: ActionRedeemFail, Reason: reason,
	})
}

// RecentDecisionSnapshot returns recent decisions and their retention state
// from one locked point-in-time view. Admin responses use it so entries and
// coverage metadata cannot disagree during concurrent evaluation.
func (e *Engine) RecentDecisionSnapshot() RecentDecisionSnapshot {
	return e.recent.snapshot(0)
}

// reasonCategory collapses a full reason string ("waf:dotfile-probe",
// "behaviour_block:threshold:rule_match") to its leading token so the metric
// label stays low-cardinality regardless of rule IDs and detail suffixes.
func reasonCategory(reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		return reason[:i]
	}
	return reason
}

// scoreboardFactor resolves the attack-mode scoreboard tightening from a
// caller-supplied config (never a fresh e.Config() load, which could race a
// nil snapshot swap during shutdown). Returns 1 (unchanged) unless the posture
// is Attack and a factor is configured.
func (e *Engine) scoreboardFactor(cfg *Config) float64 {
	if e.attack.State().Level != attackmode.Attack {
		return 1
	}
	if f := cfg.AttackMode.Effects.ScoreboardFactor; f > 0 && f < 1 {
		return f
	}
	return 1
}

// recordEvents feeds behaviour events into the scoreboard. Bad events are
// rare by construction, so the store writes stay off the common path. factor
// (<1 under attack mode) tightens the thresholds so fewer bad events block.
func (e *Engine) recordEvents(ctx context.Context, ip string, dcfg *DomainConfig, events []Event, factor float64) {
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
			err = e.board.Block(ctx, ip, ev.Detail, ib.BlockTTL.Std(), ib.MaxBlockTTL.Std())
			blocked = err == nil
		default:
			// A zero rate is an explicit "off" for this event type; skip it
			// before the attack factor's max(1, …) could resurrect it.
			if rate, ok := ib.Thresholds[ev.Type]; ok && rate.Count > 0 {
				limit := rate.Count
				if factor > 0 && factor < 1 {
					limit = max(1, int(float64(rate.Count)*factor))
				}
				blocked, err = e.board.RecordEvent(ctx, ip, ev.Type, limit, rate.Per,
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
	snap := e.acquireSnapshot()
	if snap == nil {
		return // engine closing
	}
	defer snap.release()
	// Host-level config on purpose: callers report from contexts where only
	// the host is cheaply known (redeem failures), and events/blocks are
	// IP-scoped anyway.
	dcfg := snap.cfg.DomainFor(host)
	if addr, err := netip.ParseAddr(ip); err == nil && dcfg.Allowlist.MatchIP(addr) {
		return
	}
	e.recordEvents(ctx, ip, dcfg, []Event{{Type: evtype, Detail: detail}}, e.scoreboardFactor(snap.cfg))
}

// BlockIP places a temporary behavioural block with an explicit TTL (no
// backoff): an operator/admin-API primitive.
func (e *Engine) BlockIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	if err := e.store.Set(ctx, BlockKey(ip), store.BlockValue(reason), ttl); err != nil {
		return err
	}
	e.board.notifyEnforcer(ip, reason, ttl, false)
	return nil
}

// UnblockReset reports what an unblock cleared besides the block itself.
//
// The key counts are keys addressed, not keys that held a value: the store's
// Delete does not distinguish the two.
//
// Incomplete means specifically that state which can re-block the IP may have
// survived, not that every step reported success. The behaviour counters no
// longer qualify: the final commit rotates the generation their keys are named
// after, so failing to delete one leaves a key nothing will ever read again.
// What does qualify is the challenge escalation, which is not generation-
// scoped: a counter left pinned at the difficulty ceiling keeps producing
// challenge_farm events. Steps that merely tidy up log their failure instead,
// so incomplete stays a signal an operator should act on.
type UnblockReset struct {
	EventKeys      int  `json:"event_keys"`
	EscalationKeys int  `json:"escalation_keys"`
	BackoffReset   bool `json:"backoff_reset"`
	Incomplete     bool `json:"incomplete,omitempty"`
}

// UnblockIP lifts a behavioural block and clears the state that produced it.
//
// Lifting the block alone is worse than doing nothing. The ev: counter that
// crossed the threshold stays at or above it for the rest of its window, so
// the next scored event re-blocks the IP within seconds; the chesc: escalation
// stays pinned at the difficulty ceiling, so every further issuance reports a
// challenge_farm event; and blkct: makes each re-block twice as long as the
// last, laddering toward the 30-day ceiling. Clearing the event counters and
// the escalation is therefore unconditional: they are what makes an unblock
// mean anything.
//
// resetBackoff decides only the repeat-offender ladder (blkct:, 24h window).
// True treats the block as a mistake, so the offense it recorded goes with it;
// false keeps the history for an IP being given another chance rather than
// exonerated.
//
// The reset takes several store round trips against live traffic. It therefore
// has a preparatory phase and one atomic commit boundary:
//
//  1. Scoreboard.HoldUnblock holds the IP, which stops any instance sharing
//     the store from counting a behaviour event for it or placing an automatic
//     block on it during the normal case. The behaviour counters belonging to
//     the generation that was current before this hold are then deleted, along
//     with the separately keyed challenge-escalation counters.
//  2. CommitUnblock atomically publishes another fresh generation and hold,
//     removes the active block, and optionally resets its offense counter.
//
// Correctness does not depend on the first finite hold outliving the reset.
// Behaviour counters are generation-scoped, so a write admitted before the
// final boundary can finish late only in an obsolete key. Automatic blocks
// validate that same generation while atomically writing the block and offense,
// so they commit wholly before the final boundary (and are removed by it) or
// fail wholly after it. This is also why no verification loop is needed.
//
// The block itself is authoritative and its failure is returned. The resets
// are best-effort: a store that cannot clear a counter must not turn a
// successful unblock into an error, so it is reported through Incomplete and
// the log instead.
func (e *Engine) UnblockIP(ctx context.Context, ip string, resetBackoff bool) (UnblockReset, error) {
	ip = canonIP(ip)
	var out UnblockReset
	// Both of these are preparatory. The generation read only says which old
	// counter keys can be reclaimed early, and the hold only keeps ordinary
	// traffic off the IP while that runs; neither decides the outcome, because
	// CommitUnblock below rotates the generation whatever happened here. So a
	// failure is logged and does not make the result incomplete.
	resetGeneration, generationErr := e.board.unblockToken(ctx, ip)
	if generationErr != nil {
		e.log.Warn("unblock could not read the behaviour-counter generation, skipping their early cleanup",
			"ip", ip, "err", generationErr)
	}
	if err := e.board.HoldUnblock(ctx, ip); err != nil {
		e.log.Warn("unblock could not hold off concurrent scoring while it ran", "ip", ip, "err", err)
	}
	e.resetBlockCounters(ctx, ip, resetGeneration, generationErr == nil, &out)
	if err := e.board.CommitUnblock(ctx, ip, resetBackoff); err != nil {
		return out, err
	}
	if resetBackoff {
		out.BackoffReset = true
	}
	return out, nil
}

// maxEscalationResetHosts bounds how many host+IP escalation counters a single
// unblock clears. chesc: is not enumerable by prefix (the host sits before the
// IP in the key), so the set is reconstructed, and a config with hundreds of
// vhosts would otherwise turn one admin click into hundreds of store deletes.
const maxEscalationResetHosts = 128

func (e *Engine) resetBlockCounters(ctx context.Context, ip, generation string, resetEvents bool, out *UnblockReset) {
	snap := e.acquireSnapshot()
	if snap == nil {
		out.Incomplete = true
		return // engine closing: no config to rebuild keys from
	}
	defer snap.release()

	if resetEvents {
		// Reclamation, not correctness: these keys are named after the
		// generation CommitUnblock is about to replace, so one left behind is
		// unreachable and expires on its own window. A failure is therefore
		// worth a log line and not an incomplete result.
		keys, failed := e.board.ResetEventCounters(ctx, ip, generation, snap.cfg.BehaviourWindows())
		out.EventKeys = keys
		if failed > 0 {
			e.log.Warn("unblock could not clear every behaviour counter; they are already unreachable",
				"ip", ip, "keys", keys, "failed", failed)
		}
	}

	if e.pow != nil {
		hosts, truncated := e.escalationHosts(snap.cfg, ip)
		for _, host := range hosts {
			keys, err := e.pow.ResetEscalation(ctx, host, ip)
			out.EscalationKeys += keys
			if err != nil {
				out.Incomplete = true
				e.log.Warn("unblock could not clear a challenge escalation counter",
					"ip", ip, "host", host, "cleared", keys, "err", err)
			}
		}
		if truncated {
			out.Incomplete = true
			e.log.Warn("unblock cleared challenge escalation for only the first hosts",
				"ip", ip, "hosts", len(hosts), "limit", maxEscalationResetHosts)
		}
	}

}

// escalationHosts is the set of hosts whose chesc:<host>:<ip> counter an
// unblock of ip should clear, normalized the way the challenge path keys them.
//
// Hosts this IP was actually acted on come first: the decision ring records
// every non-allow decision with its Host, and a client only ever reaches the
// challenge page after one. The configured vhosts follow, covering an IP whose
// ring entries the bounded window has already overwritten. Neither source is
// complete on its own and the union still is not: an IP challenged on a host
// that is not configured (it falls through to defaults) and has since aged out
// of the ring keeps its escalation counter until the challenge TTL lapses.
func (e *Engine) escalationHosts(cfg *Config, ip string) (hosts []string, truncated bool) {
	seen := make(map[string]bool, 8)
	add := func(raw string) bool {
		host := normalizeHost(raw)
		if host == "" || seen[host] {
			return true
		}
		if len(hosts) >= maxEscalationResetHosts {
			return false
		}
		seen[host] = true
		hosts = append(hosts, host)
		return true
	}
	// The ring stores the address exactly as the transport delivered it, while
	// ip is already canonical, so a match compares parsed addresses rather than
	// strings. netip.Addr is comparable and ParseAddr does not allocate, which
	// keeps a full-ring walk cheap; the string compare short-circuits the
	// overwhelmingly common identical-form case first.
	target, targetErr := netip.ParseAddr(ip)
	sameIP := func(raw string) bool {
		if raw == ip {
			return true
		}
		if targetErr != nil {
			return false
		}
		addr, err := netip.ParseAddr(raw)
		return err == nil && addr.Unmap() == target
	}
	for _, d := range e.recent.list(0) {
		if sameIP(d.IP) && !add(d.Host) {
			return hosts, true
		}
	}
	// Sorted, so which hosts survive the cap does not depend on map order.
	configured := make([]string, 0, len(cfg.resolved))
	for host := range cfg.resolved {
		configured = append(configured, host)
	}
	sort.Strings(configured)
	for _, host := range configured {
		if !add(host) {
			return hosts, true
		}
	}
	return hosts, false
}

// BlockStatus reports whether an IP is currently blocked and why (admin API).
func (e *Engine) BlockStatus(ctx context.Context, ip string) (reason string, blocked bool, err error) {
	v, ok, err := e.store.Get(ctx, BlockKey(ip))
	return store.BlockReason(v), ok, err
}

// BlockDetail is the single-IP block view: BlockStatus plus the two things an
// operator needs before deciding whether to lift a block, namely when it
// expires and how many times this IP has been blocked before.
type BlockDetail struct {
	IP      string `json:"ip"`
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`
	// ExpiresAt is nil when the IP is not blocked, when the block has no
	// expiry, or when the store could not report one.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Offenses is the running block count behind the exponential backoff
	// (blkct:, 24h window), nil when unknown or never blocked. It is reported
	// even for an IP that is not currently blocked, because "blocked 4 times
	// today, currently clear" is exactly the state worth seeing.
	Offenses *int64 `json:"offenses,omitempty"`
}

// BlockDetailFor answers the enriched single-IP lookup.
//
// The block status itself is authoritative; the two enrichments are
// best-effort and are simply omitted on error, because a degraded extra field
// must never turn a working block-status query into a failure.
func (e *Engine) BlockDetailFor(ctx context.Context, ip string) (BlockDetail, error) {
	reason, blocked, err := e.BlockStatus(ctx, ip)
	if err != nil {
		return BlockDetail{}, err
	}
	out := BlockDetail{IP: canonIP(ip), Blocked: blocked, Reason: reason}
	if blocked {
		if exp, ok := e.blockExpiry(ctx, ip); ok {
			out.ExpiresAt = &exp
		}
	}
	// canonIP, because RecordEvent canonicalises before writing blkct:.
	if raw, ok, err := e.store.Get(ctx, blockCountKey(canonIP(ip))); err == nil && ok {
		if n, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
			out.Offenses = &n
		}
	}
	return out, nil
}

// blockExpiry finds the expiry of one active block. Store.Get returns only the
// value, while store.KV carries ExpiresAt, so this goes through the same
// scanner chain the list endpoint uses, narrowed to a single key's prefix.
//
// The exact-key comparison is load-bearing, not defensive: a prefix scan for
// "block:10.0.0.1" also matches "block:10.0.0.10" and "block:10.0.0.100",
// so taking the first row would report a different IP's expiry.
func (e *Engine) blockExpiry(ctx context.Context, ip string) (time.Time, bool) {
	key := BlockKey(ip)
	kvs, _, err := e.scanBlocks(ctx, key, blockExpiryScanLimit)
	if err != nil {
		return time.Time{}, false
	}
	for _, kv := range kvs {
		if kv.Key == key && !kv.ExpiresAt.IsZero() {
			return kv.ExpiresAt, true
		}
	}
	return time.Time{}, false
}

// blockExpiryScanLimit bounds the single-key expiry lookup. The matches are
// the target key plus any IP that has it as a string prefix, so a handful is
// generous; if the exact key somehow falls outside it, the expiry is reported
// as unknown rather than wrong.
const blockExpiryScanLimit = 64

// BlockEntry is one active behavioural block, as listed by the admin API.
type BlockEntry struct {
	IP        string     `json:"ip"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = no expiry
}

// ListBlocks returns every currently active block (admin API / dashboard).
// It scans the store, so it is an occasional admin read, not a hot-path call.
func (e *Engine) ListBlocks(ctx context.Context) ([]BlockEntry, error) {
	blocks, _, err := e.ListBlocksLimit(ctx, 0)
	return blocks, err
}

// ListBlocksLimit returns at most limit active blocks and reports whether the
// result contains the whole set. A non-positive limit requests the full set.
func (e *Engine) ListBlocksLimit(ctx context.Context, limit int) ([]BlockEntry, bool, error) {
	kvs, complete, err := e.scanBlocks(ctx, blockKeyPrefix, limit)
	if err != nil {
		return nil, false, err
	}
	out := make([]BlockEntry, 0, len(kvs))
	for _, kv := range kvs {
		b := BlockEntry{IP: kv.Key[len(blockKeyPrefix):], Reason: store.BlockReason(kv.Value)}
		if !kv.ExpiresAt.IsZero() {
			exp := kv.ExpiresAt
			b.ExpiresAt = &exp
		}
		out = append(out, b)
	}
	return out, complete, nil
}

// scanBlocks enumerates block keys under prefix, preferring the backend's
// dedicated active-block index and falling back to a bounded generic scan,
// then to a plain scan. Shared by the list endpoint and the single-key expiry
// lookup so both get the same capability handling.
func (e *Engine) scanBlocks(ctx context.Context, prefix string, limit int) ([]store.KV, bool, error) {
	var (
		kvs      []store.KV
		complete = true
		err      error
	)
	indexed, indexedOK := e.store.(store.ActiveBlockScanner)
	if indexedOK {
		kvs, complete, err = indexed.ScanActiveBlocks(ctx, prefix, limit)
	}
	if indexedOK && errors.Is(err, store.ErrCapabilityUnsupported) {
		indexedOK = false
		err = nil
	}
	if !indexedOK {
		if limited, ok := e.store.(store.LimitedScanner); ok {
			kvs, complete, err = limited.ScanLimit(ctx, prefix, limit)
		} else {
			kvs, err = e.store.Scan(ctx, prefix)
			if err == nil && limit > 0 && len(kvs) > limit {
				kvs, complete = kvs[:limit], false
			}
		}
	}
	return kvs, complete, err
}

// ScoreRequest runs the anomaly scorer for a hypothetical request against the
// domain's model, for admin inspection ("how anomalous is this request?").
func (e *Engine) ScoreRequest(host, method, uri, ua string) anomaly.ScoreResult {
	snap := e.acquireSnapshot()
	if snap == nil {
		return anomaly.ScoreResult{Level: "missing"}
	}
	defer snap.release()
	dcfg := snap.cfg.ConfigFor(host, uri)
	if !dcfg.WAF.Anomaly.Enabled {
		return anomaly.ScoreResult{Level: "missing"}
	}
	m := snap.models.Get(dcfg.WAF.Anomaly.Model)
	if m == nil {
		return anomaly.ScoreResult{Level: "missing"}
	}
	return m.Score(host, method, decodePath(requestPath(uri)), decodeQuery(requestQuery(uri)), ua)
}

// ShedVerdict is the outcome of the load-shedding fast path (see ShedDecision).
type ShedVerdict int

const (
	// ShedPass: admit without a full evaluation (allowlisted, or a valid token).
	ShedPass ShedVerdict = iota
	// ShedDeny: a cheap terminal check already rejects this request.
	ShedDeny
	// ShedReject: no cheap verdict; shed (503) rather than run a full eval.
	ShedReject
)

// ShedDecision is the load-shedding gate: it runs ONLY the cheap, store-free
// terminal checks that the full pipeline would run before the token stage, so
// a saturated daemon still enforces blocks, denylists, local IP-intel verdicts,
// honeypots and WAF rules while fast-passing clean vouched clients. It
// deliberately does not run store reads, verified-bot DNS, anomaly scoring or
// event-recording writes; those are what the shed exists to skip. Because it
// preserves the terminal pre-token checks, a token can never become a WAF or
// policy bypass just because the daemon is saturated.
func (e *Engine) ShedDecision(req *RequestContext) ShedVerdict {
	snap := e.acquireSnapshot()
	if snap == nil {
		return ShedReject
	}
	defer snap.release()
	dcfg := snap.cfg.scopeForRequest(req)
	env := &stageEnv{
		domain: dcfg, pow: e.pow, enforcer: e.enforcer,
		rules: snap.rules, intel: snap.intel, attack: e.attack.State(),
	}

	// Stage 0: static allowlist wins over everything (same as the pipeline).
	if stateless.CheckAllowlist(req, &dcfg.Allowlist) != nil {
		return ShedPass
	}
	// Stage 1: static denylist, through the stage's own implementation so the
	// two cannot drift. Matching only IPs here was exactly that drift: the
	// denylist grew uas and paths, CheckDenylist gained them, and this copy did
	// not, so a token holder reaching a denylisted path or sending a denylisted
	// User-Agent was fast-passed the moment the daemon saturated. A static
	// denylist that stops applying under load is the opposite of what an
	// operator adding one during an attack expects.
	//
	// The parse guard stays. An unparseable IP makes denylistStage return a
	// stage error before CheckDenylist runs at all, and Evaluate fails open on
	// that, so judging one here would make the shed stricter than the pipeline
	// it stands in for rather than merely faster.
	if _, err := netip.ParseAddr(req.RemoteAddr); err == nil {
		if stateless.CheckDenylist(req, &dcfg.Denylist) != nil {
			return ShedDeny
		}
	}
	// Stage 2: behavioural block, via the in-process mirror only (no store
	// read; a shared-store miss just falls through to shed, never to pass).
	if _, blocked := e.enforcer.Lookup(req.RemoteAddr); blocked {
		return ShedDeny
	}
	// A read-through (shared, unseeded, or capacity-incomplete) mirror cannot
	// prove that a miss is unblocked without consulting the store. Store I/O is
	// intentionally forbidden on the shed path, so reject the request instead
	// of letting a token bypass a block known only to another replica/the store.
	// The nil-enforcer check is a deliberate availability trade-off, not an
	// oversight: with no mirror at all (store-only embeddings, unit tests)
	// every block is unknowable here, and rejecting would strip the shed
	// fast-pass from every token holder; guardiand always attaches a mirror.
	if e.enforcer != nil && e.enforcer.ReadThrough() {
		return ShedReject
	}

	// A claimed verified-bot identity with spoof_action=deny cannot be safely
	// fast-passed without the stage's potentially blocking DNS verification.
	// Shed it instead. This is preferable to letting a token minted before a
	// config/DNS-state change bypass the bot-spoof policy under saturation.
	vb := &dcfg.VerifiedBots
	if vb.SpoofAction != "continue" && vb.match(req.LowerUA()) != nil {
		return ShedReject
	}

	// The remaining pre-token terminal stages are entirely local/store-free.
	// Reuse their implementations so shed behavior cannot drift from the normal
	// pipeline. No events are recorded here: that would put store writes back on
	// the overload path.
	if d, _ := (intelDenyStage{}).Evaluate(context.Background(), req, env); d != nil {
		return ShedDeny
	}
	if d, _ := (honeypotStage{}).Evaluate(context.Background(), req, env); d != nil {
		return ShedDeny
	}
	if d, _ := (wafRulesStage{}).Evaluate(context.Background(), req, env); d != nil {
		switch d.Action {
		case ActionDeny:
			return ShedDeny
		case ActionAllow:
			return ShedPass // valid token satisfied a challenge-only rule
		default:
			return ShedReject
		}
	}

	// A valid PoW token vouches after every retained terminal check. Cheap
	// stateless WAF rule check; no store I/O on a cache hit.
	if hasValidPoWToken(req, env) {
		return ShedPass
	}
	return ShedReject
}

// PoWManager exposes the PoW manager for admin key rotation (may be nil).
func (e *Engine) PoWManager() *pow.Manager { return e.pow }

// BotVerifier exposes the crawler rDNS verifier (tests swap its resolver).
func (e *Engine) BotVerifier() *botverify.Verifier { return e.bots }

// Intel exposes the intel provider for admin inspection (may be nil; its
// methods are nil-safe). Nil after Close.
func (e *Engine) Intel() *intel.Provider {
	if snap := e.snap.Load(); snap != nil {
		return snap.intel
	}
	return nil
}

// Config exposes the currently active configuration. Callers must treat it as
// a point-in-time snapshot: a hot reload swaps it, so hold the returned
// pointer for one request, never across requests. After Close it keeps
// returning the last active config, so straggler requests racing shutdown
// read stale-but-valid policy instead of panicking.
func (e *Engine) Config() *Config {
	if snap := e.snap.Load(); snap != nil {
		return snap.cfg
	}
	return e.lastCfg.Load()
}

// AnomalyModels returns immutable metadata for the currently loaded artifacts.
func (e *Engine) AnomalyModels() []anomaly.ModelStatus {
	snap := e.acquireSnapshot()
	if snap == nil {
		return nil
	}
	defer snap.release()
	return snap.models.Status()
}
