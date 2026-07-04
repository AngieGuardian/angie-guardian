// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// Stage is one step of the decision pipeline. Returning a nil Decision means
// "no opinion, continue"; a non-nil Decision is terminal.
type Stage interface {
	Name() string
	Evaluate(ctx context.Context, req *RequestContext, env *stageEnv) (*Decision, error)
}

// stageEnv bundles what stages may consult besides the request itself.
type stageEnv struct {
	store  store.Store
	domain *DomainConfig
	pow    *pow.Manager
}

func requestPath(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

// allowlistStage — pipeline stage 0. Trusted IPs/CIDRs, allowlisted UAs and
// well-known paths skip everything.
type allowlistStage struct{}

func (allowlistStage) Name() string { return "allowlist" }

func (allowlistStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	l := &env.domain.Allowlist
	if l.MatchPath(requestPath(req.URI)) {
		return &Decision{Action: ActionAllow, Reason: "allowlist:path"}, nil
	}
	if addr, err := netip.ParseAddr(req.RemoteAddr); err == nil && l.MatchIP(addr) {
		return &Decision{Action: ActionAllow, Reason: "allowlist:ip"}, nil
	}
	if l.MatchUA(req.UserAgent) {
		return &Decision{Action: ActionAllow, Reason: "allowlist:ua"}, nil
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

// behaviourBlockStage — pipeline stage 2. Temporary TTL'd blocks placed in
// the shared store by the behavioural scoreboard (P2) or the admin API.
type behaviourBlockStage struct{}

func (behaviourBlockStage) Name() string { return "behaviour_block" }

func (behaviourBlockStage) Evaluate(ctx context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if !env.domain.WAF.IPBehaviour.Enabled {
		return nil, nil
	}
	reason, blocked, err := env.store.Get(ctx, blockKey(req.RemoteAddr))
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

// powChallengeStage — pipeline stage 6, P1 form. Until anomaly scoring (P3)
// drives a real suspicion function, every unvouched browser-shaped request
// on a PoW-enabled domain gets challenged at the domain's base difficulty.
// Like Anubis, "browser-shaped" means a Mozilla User-Agent: the scrapers
// worth taxing impersonate browsers, while honest tools (curl, feed readers,
// package managers) pass through to the WAF-only path.
type powChallengeStage struct{}

func (powChallengeStage) Name() string { return "pow_challenge" }

func (powChallengeStage) Evaluate(_ context.Context, req *RequestContext, env *stageEnv) (*Decision, error) {
	if env.pow == nil || !env.domain.PoW.Enabled {
		return nil, nil
	}
	if req.Method != "GET" && req.Method != "HEAD" {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(req.UserAgent), "mozilla") {
		return nil, nil
	}
	return &Decision{
		Action:     ActionChallenge,
		Difficulty: env.domain.PoW.BaseDifficulty,
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
