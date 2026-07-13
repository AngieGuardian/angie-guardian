// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/melroy89/angie-guardian/core/anomaly"
	"github.com/melroy89/angie-guardian/core/botverify"
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
type stageEnv struct {
	store       store.Store
	domain      *DomainConfig
	domainLabel string // bounded metric label for the resolved domain (never the raw Host)
	pow         *pow.Manager
	rules       *waf.RuleCache
	models      *anomaly.ModelCache
	intel       *intel.Provider // nil when no geoip/reputation is configured
	metrics     *metrics.Metrics
	bots        *botverify.Verifier

	origin *intel.Info // memoized geo lookup: both intel stages share one
}

// originInfo looks up the request origin (country/ASN) once per request; the
// deny and challenge stages both consult it.
func (env *stageEnv) originInfo(addr netip.Addr) intel.Info {
	if env.origin == nil {
		info := env.intel.Lookup(addr)
		env.origin = &info
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
	if d, ok := stateless.CheckAllowlist(req, &env.domain.Allowlist); ok {
		return &d, nil
	}
	return nil, nil
}

// denylistStage — pipeline stage 1. Permanent admin-set IP/CIDR blocks.
type denylistStage struct{}

func (denylistStage) Name() string { return "denylist" }

func (denylistStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	addr, err := netip.ParseAddr(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("unparseable client IP %q: %w", req.RemoteAddr, err)
	}
	if env.domain.Denylist.MatchIP(addr) {
		return &Decision{
			Action: ActionDeny,
			Reason: "denylist:ip",
			Events: []Event{{Type: "deny", Detail: "static denylist hit"}},
		}, nil
	}
	return nil, nil
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
	bot := vb.match(req.UserAgent)
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
type behaviourBlockStage struct{}

func (behaviourBlockStage) Name() string { return "behaviour_block" }

func (behaviourBlockStage) Evaluate(ctx context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	reason, blocked, err := env.store.Get(ctx, BlockKey(req.RemoteAddr))
	if err != nil {
		return nil, err
	}
	if blocked {
		return &Decision{
			Action: ActionDeny,
			Reason: "behaviour_block:" + string(reason),
		}, nil
	}
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
	if env.intel == nil || env.pow == nil || !env.domain.PoW.Enabled {
		return nil, nil
	}
	addr, err := netip.ParseAddr(req.RemoteAddr)
	if err != nil {
		return nil, nil
	}
	if env.domain.Reputation.Enabled {
		if feed, ok := env.intel.FeedMatch(addr, intel.FeedActionChallenge); ok {
			return &Decision{
				Action: ActionChallenge,
				// A reputation-listed client pays one full step (+4 bits =
				// 16x) more than a clean one, like a WAF signature hit.
				Difficulty: min(env.domain.PoW.BaseBits()+4, env.domain.PoW.MaxBits()),
				Reason:     "reputation:" + feed,
			}, nil
		}
	}
	if env.domain.Geo.Enabled {
		info := env.originInfo(addr)
		if action, reason := env.domain.Geo.Action(info.Country, info.ASN); action == "challenge" {
			return &Decision{
				Action:     ActionChallenge,
				Difficulty: env.domain.PoW.BaseBits(),
				Reason:     reason,
			}, nil
		}
	}
	return nil, nil
}

// honeypotStage — trap paths (plan §4.4). No legitimate client ever requests
// these (hidden links, robots.txt-disallowed URLs), so one hit is definitive:
// deny and block the IP immediately.
type honeypotStage struct{}

func (honeypotStage) Name() string { return "honeypot" }

func (honeypotStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if d, ok := stateless.CheckHoneypot(req, &env.domain.WAF.Honeypot); ok {
		return &d, nil
	}
	return nil, nil
}

// wafSignatureStage — pipeline stage 4 (plan §4.2). Runs BEFORE the token
// stage on purpose: a vouched client keeps passing these cheap precompiled
// checks, so a stolen or borrowed token can't ride past the WAF ("WAF-lite",
// plan §3 note on stage 3).
type wafSignatureStage struct{}

func (wafSignatureStage) Name() string { return "waf_signatures" }

func (wafSignatureStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	kw := &env.domain.WAF.Keywords
	if !kw.Enabled || env.rules == nil {
		return nil, nil
	}
	rs := env.rules.Get(kw.RulesFile)
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
	case waf.ActionChallenge:
		if env.pow != nil && env.domain.PoW.Enabled {
			return &Decision{
				Action: ActionChallenge,
				// A signature hit pays one full difficulty step (+4 bits = 16x
				// the base work), capped at the domain ceiling.
				Difficulty: min(env.domain.PoW.BaseBits()+4, env.domain.PoW.MaxBits()),
				Reason:     reason,
				Events:     []Event{{Type: EventSignature, Detail: rule.ID}},
			}, nil
		}
		fallthrough // no PoW on this domain: challenge degrades to deny
	case waf.ActionDeny:
		return &Decision{
			Action: ActionDeny,
			Reason: reason,
			Events: []Event{{Type: EventSignature, Detail: rule.ID}},
		}, nil
	default: // waf.ActionBlock
		return &Decision{
			Action: ActionDeny,
			Reason: reason,
			Events: []Event{{Type: EventInstantBlock, Detail: reason}},
		}, nil
	}
}

// powTokenStage — pipeline stage 3. A valid signed token vouches for the
// client and short-circuits the expensive stages; this is the common fast
// path. An invalid token is treated as absent (the client just gets
// re-challenged; P2 additionally scores it as a tamper signal).
type powTokenStage struct{}

func (powTokenStage) Name() string { return "pow_token" }

func (powTokenStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if env.pow == nil || !env.domain.PoW.Enabled {
		return nil, nil
	}
	token := cookieValue(req.Cookie, pow.CookieName)
	if token == "" {
		return nil, nil
	}
	if err := env.pow.VerifyToken(token, req.Host, req.RemoteAddr, req.UserAgent); err != nil {
		return nil, nil
	}
	return &Decision{Action: ActionAllow, Reason: "pow:token"}, nil
}

// anomalyStage — pipeline stage 5 (plan §4.3). Scores the request against
// the trained per-domain baseline: past deny_at it is rejected outright,
// past challenge_at it gets a PoW challenge whose difficulty scales with the
// score (a more suspicious client pays more, plan §5.5).
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
	score := m.Score(req.Host,
		decodePath(requestPath(req.URI)),
		decodeQuery(requestQuery(req.URI)),
		req.UserAgent)
	env.metrics.AnomalyScore(env.domainLabel, score)

	switch {
	case score >= a.DenyAt:
		return &Decision{
			Action: ActionDeny,
			Reason: "anomaly:deny",
			Events: []Event{{Type: EventAnomaly, Detail: fmt.Sprintf("score=%.2f", score)}},
		}, nil
	case score >= a.ChallengeAt && env.pow != nil && env.domain.PoW.Enabled:
		return &Decision{
			Action:     ActionChallenge,
			Difficulty: scaleDifficulty(env.domain.PoW.BaseBits(), env.domain.PoW.MaxBits(), score, a.ChallengeAt),
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
	if env.pow == nil || !env.domain.PoW.Enabled {
		return nil, nil
	}
	if env.domain.PoW.Mode == "suspicion" && env.domain.WAF.Anomaly.Enabled {
		return nil, nil
	}
	return &Decision{
		Action:     ActionChallenge,
		Difficulty: env.domain.PoW.BaseBits(),
		Reason:     "pow:no_token",
	}, nil
}

// cookieValue extracts one cookie from a raw Cookie header without pulling
// net/http into the transport-agnostic core.
func cookieValue(header, name string) string {
	for part := range strings.SplitSeq(header, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, name+"="); ok {
			return v
		}
	}
	return ""
}
