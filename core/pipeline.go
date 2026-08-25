// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/botverify"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/headerexempt"
	"github.com/melroy89/angie-guardian/core/intel"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/stateless"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/core/waf"
)

// Stage is one step of the decision pipeline. Returning a nil Decision means
// "no opinion, continue"; a non-nil Decision is terminal.
type Stage interface {
	Name() string
	Evaluate(ctx context.Context, req *RequestContext, env *stageEnv) (*Decision, error)
}

// stageEnv bundles what stages may consult besides the request itself.
// The bounded metric label for the resolved domain lives on domain itself
// (DomainConfig.label, never the raw Host), not as a field here: stageEnv is
// allocated once per request and a string header is 16 bytes on the hot path.
type stageEnv struct {
	store            store.Store
	domain           *DomainConfig
	pow              *pow.Manager
	rules            *waf.RuleCache
	models           *anomaly.ModelCache
	intel            *intel.Provider // nil when no geoip/reputation is configured
	headerExemptions *headerexempt.Cache
	metrics          *metrics.Metrics
	bots             *botverify.Verifier
	enforcer         *enforce.Manager  // nil = store-only block enforcement
	attack           *attackmode.State // never nil (Normal when attack mode is off)

	origin *intel.Info  // memoized geo lookup: both intel stages share one
	token  tokenVerdict // memoized PoW cookie check: up to three stages share one
	// 0 unchecked, 1 no match, 2 matched. Kept byte-sized on the hot path.
	headerExempt uint8
}

// effBits resolves the difficulty window for the resolved domain, shifted up
// by the fleet attack-mode raise (a no-op when the posture is Normal). Every
// challenge-issuing stage composes its difficulty from these, so per-IP
// escalation and anomaly scaling operate inside the shifted window.
func (env *stageEnv) effBits() (base, maxDiff int) {
	return attackmode.EffectiveBits(env.attack,
		env.domain.PoW.BaseBits(), env.domain.PoW.MaxBits(), env.attack.Cap(env.domain.PoW.MaxBits()))
}

// originInfo looks up the request origin (country/ASN) once per request; the
// deny and challenge stages both consult it.
func (env *stageEnv) originInfo(addr netip.Addr) intel.Info {
	if env.origin == nil {
		env.origin = new(env.intel.Lookup(addr))
	}
	return *env.origin
}

// These thin wrappers keep the many in-file callsites terse while the actual
// implementations live in the shared leaf package (used by the WASM guest too).
func requestPath(uri string) string  { return stateless.RequestPath(uri) }
func requestQuery(uri string) string { return stateless.RequestQuery(uri) }
func decodePath(p string) string     { return stateless.DecodePath(p) }
func decodeQuery(q string) string    { return stateless.DecodeQuery(q) }

// allowlistStage — pipeline stage 0. Trusted IPs/CIDRs, allowlisted UAs and
// well-known paths skip everything.
type allowlistStage struct{}

func (allowlistStage) Name() string { return "allowlist" }

func (allowlistStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	return stateless.CheckAllowlist(req, &env.domain.Allowlist), nil
}

// denylistStage — pipeline stage 1. Permanent admin-set IP/CIDR blocks.
type denylistStage struct{}

func (denylistStage) Name() string { return "denylist" }

func (denylistStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if _, err := netip.ParseAddr(req.RemoteAddr); err != nil {
		return nil, fmt.Errorf("unparseable client IP %q: %w", req.RemoteAddr, err)
	}
	return stateless.CheckDenylist(req, &env.domain.Denylist), nil
}

// verifiedBotStage — verified crawler allowlist. A UA allowlist entry like
// "Googlebot" is spoofable by anyone; this stage instead admits a client
// claiming a configured bot UA only after its IP reverse-DNS + forward-
// confirms to the bot's published domains (see core/botverify; results are
// cached in the shared store, so DNS is paid once per IP, not per request).
//
// It runs after the static lists but before the behavioural block stage:
// explicit operator config (allowlist, denylist) still wins, while a genuine
// crawler can't be locked out by a behavioural block it picked up crawling
// odd third-party URLs. A client that claims the UA but definitively fails
// verification is an impostor: denied and scored (spoof_action: deny), or
// merely stripped of the allowlist skip (spoof_action: continue). DNS errors
// prove nothing, so they just fall through unverified.
type verifiedBotStage struct{}

func (verifiedBotStage) Name() string { return "verified_bot" }

func (verifiedBotStage) Evaluate(ctx context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	vb := &env.domain.VerifiedBots
	bot := vb.match(req.LowerUA())
	if bot == nil || env.bots == nil {
		return nil, nil
	}
	res := env.bots.Verify(ctx, req.RemoteAddr, botverify.Options{
		Timeout:     vb.DNSTimeout.Std(),
		CacheTTL:    vb.CacheTTL.Std(),
		NegativeTTL: vb.NegativeTTL.Std(),
	})
	switch {
	case res.Status == botverify.StatusConfirmed && res.MatchesDomains(bot.domainsLower):
		env.metrics.BotVerification(bot.Name, "verified")
		return &Decision{Action: ActionAllow, Reason: "verified_bot:" + bot.Name}, nil
	case res.Status == botverify.StatusError:
		env.metrics.BotVerification(bot.Name, "error")
		return nil, nil
	default:
		// Definitive: the IP's rDNS identity is absent or is not the claimed
		// bot's (StatusNone, or confirmed under someone else's domain).
		env.metrics.BotVerification(bot.Name, "spoof")
		if vb.SpoofAction == "continue" {
			return nil, nil
		}
		return &Decision{
			Action: ActionDeny,
			Reason: "bot_spoof:" + bot.Name,
			Events: []Event{{Type: EventBotSpoof, Detail: bot.Name}},
		}, nil
	}
}

// behaviourBlockStage — pipeline stage 2. Enforces TTL'd blocks placed in the
// shared store by the behavioural scoreboard, a WAF block action, or the
// admin API. The block lookup always runs: the ip_behaviour.enabled toggle
// only gates automatic *scoring* (whether new blocks get placed), not whether
// an existing block — e.g. one an operator set by hand — is honoured.
//
// The in-process mirror is consulted first: a hit denies in nanoseconds with
// no store I/O, so a flood from an already-blocked IP cannot saturate the
// store, and blocks keep enforcing through a store outage. The store read
// runs only on a miss when the mirror is not authoritative (before its seed
// scan, or on a shared store where another replica may have placed the
// block); a hit found that way is cached back into the mirror.
type behaviourBlockStage struct{}

func (behaviourBlockStage) Name() string { return "behaviour_block" }

func (behaviourBlockStage) Evaluate(ctx context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if reason, ok := env.enforcer.Lookup(req.RemoteAddr); ok {
		env.metrics.BlockLookup("mirror", "hit")
		return &Decision{
			Action: ActionDeny,
			Reason: "behaviour_block:" + reason,
		}, nil
	}
	// The mirror only represents parseable addresses, so an authoritative
	// miss skips the store only for those; anything else (impossible from
	// the Angie transport) keeps the exact store semantics.
	if !env.enforcer.ReadThrough() {
		if _, err := netip.ParseAddr(req.RemoteAddr); err == nil {
			env.metrics.BlockLookup("mirror", "miss")
			return nil, nil
		}
	}
	reason, blocked, err := env.store.Get(ctx, BlockKey(req.RemoteAddr))
	if err != nil {
		return nil, err
	}
	if blocked {
		// Only reached once the IP is already blocked, so the owner token this
		// strips costs the allow path nothing.
		why := store.BlockReason(reason)
		env.metrics.BlockLookup("store", "hit")
		env.enforcer.Learn(req.RemoteAddr, why)
		return &Decision{
			Action: ActionDeny,
			Reason: "behaviour_block:" + why,
		}, nil
	}
	env.metrics.BlockLookup("store", "miss")
	return nil, nil
}

// intelDenyStage is the deny half of GeoIP/ASN scoping and IP reputation.
// It sits right after the static denylist (with only the verified-crawler
// stage between them, so a feed false positive can't cut off a genuine,
// rDNS-confirmed bot) because these are the same kind of verdict: policy
// says this origin is never served, regardless of tokens or behaviour. The
// challenge half lives in intelChallengeStage, after the PoW token stage, so
// a client that already proved work is not re-challenged.
type intelDenyStage struct{}

func (intelDenyStage) Name() string { return "intel_deny" }

func (intelDenyStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if env.intel == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(req.RemoteAddr)
	if err != nil {
		// The denylist stage already reported this request's unparseable IP.
		return nil, nil
	}
	if env.domain.Reputation.Enabled {
		if feed, ok := env.intel.FeedMatch(addr, intel.FeedActionDeny); ok {
			return &Decision{Action: ActionDeny, Reason: "reputation:" + feed}, nil
		}
	}
	if env.domain.Geo.Enabled {
		info := env.originInfo(addr)
		if action, reason := env.domain.Geo.Action(info.Country, info.ASN); action == "deny" {
			return &Decision{Action: ActionDeny, Reason: reason}, nil
		}
	}
	return nil, nil
}

// intelChallengeStage is the challenge half of GeoIP/ASN scoping and IP
// reputation, after the token stage: solve once, then browse normally until
// the token expires. Like the anomaly stage, it is inert on domains without
// PoW, because degrading a challenge to a deny would cut off whole countries
// over a "make them prove work" policy.
type intelChallengeStage struct{}

func (intelChallengeStage) Name() string { return "intel_challenge" }

func (intelChallengeStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if env.intel == nil || env.pow == nil || !env.domain.PoW.Enabled || env.headerPoWExempt(req) {
		return nil, nil
	}
	addr, err := netip.ParseAddr(req.RemoteAddr)
	if err != nil {
		return nil, nil
	}
	base, maxDiff := env.effBits()
	if env.domain.Reputation.Enabled {
		if feed, ok := env.intel.FeedMatch(addr, intel.FeedActionChallenge); ok {
			return &Decision{
				Action: ActionChallenge,
				// A reputation-listed client pays one full step (+4 bits =
				// 16x) more than a clean one, like a WAF rule hit.
				Difficulty: min(base+4, maxDiff),
				Reason:     "reputation:" + feed,
			}, nil
		}
	}
	if env.domain.Geo.Enabled {
		info := env.originInfo(addr)
		if action, reason := env.domain.Geo.Action(info.Country, info.ASN); action == "challenge" {
			return &Decision{
				Action:     ActionChallenge,
				Difficulty: base,
				Reason:     reason,
			}, nil
		}
	}
	return nil, nil
}

// honeypotStage covers trap paths. No legitimate client ever requests
// these (hidden links, robots.txt-disallowed URLs), so one hit is definitive:
// deny and block the IP immediately.
type honeypotStage struct{}

func (honeypotStage) Name() string { return "honeypot" }

func (honeypotStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	return stateless.CheckHoneypot(req, &env.domain.WAF.Honeypot), nil
}

// wafRulesStage is pipeline stage 4. It runs BEFORE the token stage on
// purpose: a vouched client keeps passing these cheap precompiled checks, so a
// stolen or borrowed token cannot ride past the WAF.
type wafRulesStage struct{}

func (wafRulesStage) Name() string { return "waf_rules" }

func (wafRulesStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	rules := &env.domain.WAF.Rules
	if !rules.Enabled || env.rules == nil {
		return nil, nil
	}
	// ruleKey resolves this scope's precompiled (files, disabled_ids)
	// variant; exclusions cost nothing here.
	rs := env.rules.Get(rules.ruleKey)
	if rs == nil {
		return nil, nil
	}
	in := stateless.BuildMatchInput(req, rs)
	rule := rs.Match(&in)
	if rule == nil {
		return nil, nil
	}
	reason := "waf:" + rule.ID
	switch rule.Action {
	case waf.ActionAllow:
		// An allow rule is a policy exception, not a bad-event observation. It
		// terminates at this stage without feeding the behavioural scoreboard.
		// Earlier hard-deny stages have already run; later challenge/anomaly/PoW
		// stages are deliberately skipped.
		return &Decision{Action: ActionAllow, Reason: reason}, nil
	case waf.ActionChallenge:
		if env.pow != nil && env.domain.PoW.Enabled {
			if env.headerPoWExempt(req) {
				return nil, nil
			}
			// A challenge-only WAF rule asks the client to prove work; a valid
			// bound token is that proof. Deny/block rules still terminate above
			// the ordinary token stage and can never be bypassed by a token.
			if hasValidPoWToken(req, env) {
				return decisionPoWToken, nil
			}
			base, maxDiff := env.effBits()
			return &Decision{
				Action: ActionChallenge,
				// A WAF rule hit pays one full difficulty step (+4 bits = 16x
				// the base work), capped at the (possibly attack-shifted)
				// domain ceiling.
				Difficulty: min(base+4, maxDiff),
				Reason:     reason,
				Events:     []Event{{Type: EventRuleMatch, Detail: rule.ID}},
			}, nil
		}
		fallthrough // no PoW on this domain: challenge degrades to deny
	case waf.ActionDeny:
		return &Decision{
			Action: ActionDeny,
			Reason: reason,
			Events: []Event{{Type: EventRuleMatch, Detail: rule.ID}},
		}, nil
	case waf.ActionBlock:
		return &Decision{
			Action: ActionDeny,
			Reason: reason,
			Events: []Event{{Type: EventInstantBlock, Detail: reason}},
		}, nil
	default:
		return nil, fmt.Errorf("WAF rule %q has unsupported action %q", rule.ID, rule.Action)
	}
}

// headerPoWExemptionStage classifies after WAF evaluation without returning a
// terminal allow. Later stages consult the request-local bit only to suppress
// PoW-cookie validation and challenge-only outcomes.
type headerPoWExemptionStage struct{}

func (headerPoWExemptionStage) Name() string { return "header_pow_exemption" }

func (headerPoWExemptionStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	env.headerPoWExempt(req)
	return nil, nil
}

func (env *stageEnv) headerPoWExempt(req *RequestContext) bool {
	if env.headerExempt != 0 {
		return env.headerExempt == 2
	}
	if !env.domain.PoW.Enabled || len(env.domain.PoW.HeaderExemptions) == 0 || env.headerExemptions == nil {
		env.headerExempt = 1
		return false
	}
	result := env.headerExemptions.Match(env.domain.PoW.headerExemptionKey, headerexempt.Request{
		Host: req.Host, Path: req.NormalizedPath(), Header: req.Header,
	})
	env.metrics.HeaderPoWExemption(string(result.Outcome), result.Verifier)
	if result.Matched {
		env.headerExempt = 2
		return true
	}
	env.headerExempt = 1
	return false
}

// powTokenStage — pipeline stage 3. A valid signed token vouches for the
// client and short-circuits the expensive stages; this is the common fast
// path. An invalid token is treated as absent for policy purposes: the client
// is simply re-challenged, and nothing is scored against it. Only the reason
// string records which of the failure modes it was.
type powTokenStage struct{}

func (powTokenStage) Name() string { return "pow_token" }

// decisionPoWToken is the vouched-client verdict. It carries no per-request
// data, and Evaluate copies a stage's decision by value before returning it, so
// one immutable shared value serves every request instead of an allocation on
// the single hottest path in the product. Never mutate it, and never take a
// mutable reference to it.
var decisionPoWToken = &Decision{Action: ActionAllow, Reason: "pow:token"}

func (powTokenStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if env.headerPoWExempt(req) {
		return nil, nil
	}
	if !hasValidPoWToken(req, env) {
		return nil, nil
	}
	return decisionPoWToken, nil
}

// tokenVerdict is one request's PoW cookie check, and its zero value means
// "not checked yet". Deliberately a byte rather than the {bool, string} pair it
// stands for: stageEnv is allocated once per request and sits exactly on a
// 112-byte size class, so widening it by a string header would round every
// request's allocation up two classes and cost more on the hot path than the
// diagnostic is worth. The reason string is materialized only when a challenge
// is actually being emitted.
type tokenVerdict uint8

const (
	tokenUnchecked tokenVerdict = iota
	tokenValid
	tokenAbsent          // no cookie at all
	tokenInvalid         // unparseable, unsigned, or structurally bad
	tokenExpired         // past exp, or older than this path's token_ttl
	tokenBinding         // valid, but bound to another host or client
	tokenUnderDifficulty // valid, but solved below this path's bits
)

// Failure reasons. These reach the client in X-Guardian-Reason, so they are
// static and config-independent by construction: an operator learns which of
// the six conditions fired, an attacker learns nothing it did not already know
// from being re-challenged. Never fold the underlying error text in here — that
// would leak host bindings and configured difficulty. All six keep the "pow:"
// prefix, so reasonCategory still collapses them to a single metric series.
//
// Five name a token that did not vouch. The sixth, reasonUnchallengeable, says
// no challenge was issued at all, and is the only one paired with an action
// other than ActionChallenge.
const (
	reasonNoToken        = "pow:no_token"
	reasonTokenInvalid   = "pow:token_invalid"
	reasonTokenExpired   = "pow:token_expired"
	reasonTokenBinding   = "pow:token_binding"
	reasonTokenUnderDiff = "pow:token_underdifficulty"
	// reasonUnchallengeable replaces whichever of the five above would have been
	// reported, when the client could not have completed the challenge in any
	// case. Naming the impossibility is strictly more useful than naming the
	// missing cookie: an anonymous favicon fetch reports "no_token" truthfully
	// and misleadingly at once, since no cookie was ever going to arrive.
	reasonUnchallengeable = "pow:unchallengeable"
)

// reason is the decision reason for a verdict that did not vouch.
func (v tokenVerdict) reason() string {
	switch v {
	case tokenInvalid:
		return reasonTokenInvalid
	case tokenExpired:
		return reasonTokenExpired
	case tokenBinding:
		return reasonTokenBinding
	case tokenUnderDifficulty:
		return reasonTokenUnderDiff
	default:
		// tokenAbsent, and tokenUnchecked/tokenValid which no caller asks for.
		return reasonNoToken
	}
}

// powToken verifies this request's PoW cookie at most once and memoizes the
// verdict. Three call sites ask (the WAF challenge-rule path, powTokenStage,
// and the overload shed path) and the answer cannot change mid-request: the
// host, IP, User-Agent and Cookie are fixed, env.domain is the already-resolved
// scope, and env is built fresh per request.
//
// Memoizing is not just tidiness. Without it, a token that fails on its binding
// would be verified once by powTokenStage and again by powChallengeStage to
// name the cause, so a replayed token — which an attacker can send freely, and
// which is the one failure mode that costs a full Ed25519 verification rather
// than a cheap parse error — would cost twice as much to reject as to accept.
func (env *stageEnv) powToken(req *RequestContext) tokenVerdict {
	if env.token != tokenUnchecked {
		return env.token
	}
	if env.pow == nil || !env.domain.PoW.Enabled {
		// No PoW on this scope, so no token can vouch and no reason is ever
		// emitted from it. Memoize as "absent" purely to skip the re-check.
		env.token = tokenAbsent
		return env.token
	}
	token, present := cookieValue(req.Cookie, pow.CookieName)
	if !present {
		env.token = tokenAbsent
		return env.token
	}
	// The resolved (possibly per-path) base difficulty is the floor: a token
	// solved on a cheaper path must not vouch here. An under-difficulty token
	// counts as absent, so the client is re-challenged at this path's bits.
	// The resolved token_ttl is likewise enforced: a long-lived token from a
	// lax path does not survive its full lifetime on a stricter path.
	//
	// Deliberately the UNSHIFTED base, not env.effBits(): entering attack mode
	// must not invalidate every existing visitor's token and trigger a
	// re-challenge stampede at the worst possible moment. Only NEW challenges
	// get harder; tokens already held stay valid at the difficulty they were
	// solved for.
	env.token = classifyToken(env.pow.VerifyToken(token, req.Host, req.RemoteAddr, req.UserAgent,
		env.domain.PoW.TokenMinBits(), env.domain.PoW.TokenTTL.Std()))
	return env.token
}

// classifyToken maps a VerifyToken result onto a verdict. Order does not
// matter: VerifyToken wraps exactly one sentinel per rejection.
func classifyToken(err error) tokenVerdict {
	switch {
	case err == nil:
		return tokenValid
	case errors.Is(err, pow.ErrTokenBinding):
		return tokenBinding
	case errors.Is(err, pow.ErrTokenUnderDifficulty):
		return tokenUnderDifficulty
	case errors.Is(err, pow.ErrTokenExpired):
		return tokenExpired
	case errors.Is(err, pow.ErrTokenInvalid):
		return tokenInvalid
	default:
		// A key-refresh fault: this daemon could not read its own keys, so the
		// token was never judged. Reported as invalid because the client's
		// remedy is the same (solve again) and inventing a sixth reason for a
		// local I/O failure would put daemon internals in a response header.
		// Still strictly more visible than before, when every cause alike
		// vanished into "pow:no_token".
		return tokenInvalid
	}
}

// hasValidPoWToken reports whether this request carries a token that vouches
// for it. Callers that also need the failure cause use env.powToken directly.
func hasValidPoWToken(req *RequestContext, env *stageEnv) bool {
	return env.powToken(req) == tokenValid
}

// anomalyStage is pipeline stage 5. It scores the request against the trained
// per-domain baseline: past deny_at it is rejected outright, past challenge_at
// it gets a PoW challenge whose difficulty scales with the score, so a more
// suspicious client pays more.
type anomalyStage struct{}

func (anomalyStage) Name() string { return "anomaly" }

func (anomalyStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	a := &env.domain.WAF.Anomaly
	if !a.Enabled || env.models == nil {
		return nil, nil
	}
	m := env.models.Get(a.Model)
	if m == nil {
		return nil, nil
	}
	result := m.Score(req.Host, req.Method,
		decodePath(requestPath(req.URI)),
		decodeQuery(requestQuery(req.URI)),
		req.UserAgent)
	env.metrics.AnomalyBaseline(env.domain.label, result.Level)
	if !result.Found {
		return nil, nil
	}
	score := result.Score
	env.metrics.AnomalyScore(env.domain.label, score)
	if a.ObserveOnly {
		return nil, nil
	}

	switch {
	case score >= a.DenyAt:
		return &Decision{
			Action: ActionDeny,
			Reason: "anomaly:deny",
			Events: []Event{{Type: EventAnomaly, Detail: fmt.Sprintf("score=%.2f", score)}},
		}, nil
	case score >= a.ChallengeAt && env.pow != nil && env.domain.PoW.Enabled:
		if env.headerPoWExempt(req) {
			return nil, nil
		}
		base, maxDiff := env.effBits()
		return &Decision{
			Action:     ActionChallenge,
			Difficulty: scaleDifficulty(base, maxDiff, score, a.ChallengeAt),
			Reason:     "anomaly:challenge",
			Events:     []Event{{Type: EventAnomaly, Detail: fmt.Sprintf("score=%.2f", score)}},
		}, nil
	}
	return nil, nil
}

// scaleDifficulty maps score ∈ [challengeAt, 1] linearly onto [base, max]
// bits, so a more suspicious client pays exponentially more work.
func scaleDifficulty(base, maxDiff int, score, challengeAt float64) int {
	if challengeAt >= 1 {
		return base
	}
	d := base + int(float64(maxDiff-base)*(score-challengeAt)/(1-challengeAt)+0.5)
	return min(max(d, base), maxDiff)
}

// powChallengeStage — pipeline stage 6. In mode "always" every unvouched
// request on a PoW-enabled domain is challenged at base difficulty. In mode
// "suspicion" the anomaly stage owns all challenge decisions, so ordinary-
// looking new clients browse without interstitials.
type powChallengeStage struct{}

func (powChallengeStage) Name() string { return "pow_challenge" }

func (powChallengeStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if env.pow == nil || !env.domain.PoW.Enabled || env.headerPoWExempt(req) {
		return nil, nil
	}
	// In attack mode, force_always overrides suspicion so every unvouched
	// client is challenged; otherwise suspicion leaves challenge decisions to
	// the anomaly stage.
	if env.domain.PoW.Mode == "suspicion" && env.domain.WAF.Anomaly.Enabled && !env.attack.ForceAlways {
		return nil, nil
	}
	base, _ := env.effBits()
	// powTokenStage already ran and memoized why the token did not vouch, so
	// this costs a field read. "pow:no_token" still means exactly what it always
	// did (no cookie arrived); the other four separate the cases that used to
	// hide behind it, which is what makes a re-challenge loop diagnosable from
	// /admin/decisions instead of a browser-side capture.
	return &Decision{
		Action:     ActionChallenge,
		Difficulty: base,
		Reason:     env.powToken(req).reason(),
	}, nil
}

// cookieValue extracts one cookie from a raw Cookie header without pulling
// net/http into the transport-agnostic core. The boolean distinguishes a
// missing cookie from a present empty value: the latter is unusable token data
// and must be reported as invalid rather than as "no token arrived".
func cookieValue(header, name string) (string, bool) {
	for part := range strings.SplitSeq(header, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, name+"="); ok {
			return v, true
		}
	}
	return "", false
}
