// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httptransport is the Path A transport: a thin HTTP wrapper around
// core.Engine.Evaluate, driven by Angie's auth_request subrequests, plus the
// challenge/pass/denied endpoints the Angie glue diverts to.
package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/web"
)

// PassPath is the public URL of the solution endpoint as exposed by the
// Angie glue; the challenge page posts here.
const PassPath = "/__guardian/pass"

// The X-Guardian-* header names the glue sets, spelled in canonical MIME form
// ("Uri", not "URI"). That casing is not cosmetic. Header.Get canonicalizes its
// argument, and it can only do so allocation-free when the string is ALREADY
// canonical. "X-Guardian-URI", "X-Guardian-IP" and "X-Guardian-UA" are not, so
// every read of them allocated a rewritten key. Header names are
// case-insensitive and net/http canonicalizes both what Angie sends and what we
// look up, so this changes nothing on the wire.
const (
	hdrHost       = "X-Guardian-Host"
	hdrMethod     = "X-Guardian-Method"
	hdrURI        = "X-Guardian-Uri"
	hdrIP         = "X-Guardian-Ip"
	hdrUA         = "X-Guardian-Ua"
	hdrCookie     = "X-Guardian-Cookie"
	hdrProto      = "X-Guardian-Proto"
	hdrDifficulty = "X-Guardian-Difficulty"
)

type Server struct {
	engine   *core.Engine
	pow      *pow.Manager // nil = PoW unavailable (no signing key configured)
	store    store.Store
	counters *store.CounterCache // issuance rate limit, off the write hot path
	metrics  *metrics.Metrics    // nil = no-op
	log      *slog.Logger
	mux      *http.ServeMux

	// inflight counts auth evaluations currently in Evaluate (Part C
	// load-shedding). It is compared per request against the LIVE
	// attack_mode.effects.max_inflight bound read from the engine config, so a
	// hot reload of that bound takes effect immediately. When over the bound,
	// token holders still pass (a cheap stateless check) and everyone else
	// gets a fast 503; the backend sees only vouched traffic under saturation.
	inflight atomic.Int64

	challengeTmpl *template.Template
	deniedHTML    []byte
}

// New builds the auth-path server. Domain config is read through the engine
// per request (never cached here), so a hot reload takes effect immediately.
func New(engine *core.Engine, mgr *pow.Manager, st store.Store, m *metrics.Metrics, log *slog.Logger) *Server {
	s := &Server{
		engine: engine, pow: mgr, store: st, metrics: m, log: log,
		counters:      store.NewCounterCache(st),
		mux:           http.NewServeMux(),
		challengeTmpl: template.Must(template.ParseFS(web.FS, "challenge.html.tmpl")),
	}
	s.deniedHTML, _ = web.FS.ReadFile("denied.html")

	// The endpoints that trust X-Guardian-* identity headers sit behind the
	// require_proxied gate; /healthz (probed headerless by the systemd
	// healthcheck) and /denied (static page, the glue sets no headers on it)
	// never are.
	s.mux.HandleFunc("GET /auth", s.proxiedOnly(s.handleAuth))
	s.mux.HandleFunc("GET /challenge", s.proxiedOnly(s.handleChallenge))
	s.mux.HandleFunc("/denied", s.handleDenied)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	// The pass endpoint under both its internal name and its public path, so
	// Guardian also works probed directly (tests, dev without Angie).
	for _, p := range []string{"/pass", PassPath} {
		s.mux.HandleFunc("POST "+p, s.proxiedOnly(s.handlePassSolve))
		s.mux.HandleFunc("GET "+p, s.proxiedOnly(s.handlePassNoJS))
	}
	return s
}

// proxiedOnly enforces require_proxied: when enabled, a guard request without
// the X-Guardian-IP header the Angie glue always sets is rejected instead of
// falling back to the socket address. Behind a correctly wired glue this gate
// only ever fires on traffic that bypassed Angie, which is exactly what it
// exists to surface. It is a tripwire, not a spoofing defense: a direct
// client that sends a forged X-Guardian-IP passes it, and only listener
// isolation prevents that. Read live from the config so a hot reload can
// toggle it.
func (s *Server) proxiedOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.engine.Config().RequireProxied && r.Header.Get(hdrIP) == "" {
			s.metrics.UnproxiedReject()
			http.Error(w, "direct access rejected: proxied requests required", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// FlushCounters drains the issuance rate-limit counter cache's unpushed
// deltas to the store, bounded by ctx. Call at shutdown, after the HTTP
// server has drained and before the store closes.
func (s *Server) FlushCounters(ctx context.Context) error {
	return s.counters.Flush(ctx)
}

// requestContext builds the core request from the X-Guardian-* headers the
// Angie snippets set on the subrequest, falling back to the subrequest's own
// fields so Guardian also behaves sanely when probed directly.
func (s *Server) requestContext(r *http.Request) *core.RequestContext {
	host := headerOr(r, hdrHost, r.Host)
	// The fallbacks exist for a direct probe with no glue in front. Behind Angie
	// every header is present, so the two that cost something must not be
	// computed eagerly: Go evaluates a function argument whether or not the
	// branch uses it, and RequestURI formats a fresh string on every call while
	// stripPort allocates an error for an address without a port.
	uri := r.Header.Get(hdrURI)
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	ip := r.Header.Get(hdrIP)
	if ip == "" {
		ip = stripPort(r.RemoteAddr)
	}
	return &core.RequestContext{
		Host:       host,
		Method:     headerOr(r, hdrMethod, r.Method),
		URI:        uri,
		RemoteAddr: ip,
		UserAgent:  headerOr(r, hdrUA, r.UserAgent()),
		Cookie:     headerOr(r, hdrCookie, r.Header.Get("Cookie")),
		// The auth subrequest inherits the client's request headers. Host is
		// special in net/http: it lives in Request.Host, not Header, so expose
		// the effective Guardian host explicitly to header:host WAF targets.
		Header: func(name string) []string {
			if strings.EqualFold(name, "host") {
				return []string{host}
			}
			return r.Header.Values(name)
		},
	}
}

// handleAuth answers Angie's auth_request subrequest: 2xx lets the request
// through, 401 diverts to @guardian_challenge, 403 to @guardian_denied.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	req := s.requestContext(r)

	// Load-shedding: when the daemon is saturated, admit a bounded number of
	// full evaluations. Over the bound, a client holding a valid token still
	// passes (a cheap stateless signature check, no store I/O), and everyone
	// else gets a fast 503 with Retry-After instead of a full evaluation that
	// would only add to the pileup. This keeps the backend seeing vouched
	// traffic under overload rather than fail-open dumping the whole flood.
	// The bound is read live from the config, so a hot reload of
	// attack_mode.effects.max_inflight (including toggling it on or off) takes
	// effect immediately.
	current := s.inflight.Add(1)
	if bound := s.engine.Config().AttackMode.Effects.MaxInflight; bound > 0 {
		if current > int64(bound) {
			s.inflight.Add(-1)
			// Saturated: run only the cheap store-free terminal checks. A
			// blocked or denylisted IP is still denied (never fast-passed on a
			// token); an allowlisted client or a valid-token holder passes;
			// anyone else is shed with a 503 rather than a full evaluation.
			switch s.engine.ShedDecision(req) {
			case core.ShedPass:
				s.metrics.Shed("pass_token")
				w.Header().Set("X-Guardian-Action", string(core.ActionAllow))
				w.WriteHeader(http.StatusOK)
				return
			case core.ShedDeny:
				s.metrics.Shed("deny")
				w.Header().Set("X-Guardian-Action", string(core.ActionDeny))
				w.WriteHeader(http.StatusForbidden)
				return
			default:
				// Shed. This is an auth subrequest, and Angie's auth_request
				// module only forwards 2xx/401/403 from it; any other status
				// (a bare 503) becomes a 500 for the main request, which the
				// fail-open error_page then routes to the backend, defeating
				// the shed. So return 403 with a distinguishing action header:
				// the Angie glue maps action=shed to a real 503 + Retry-After
				// (see deploy/angie-guardian.conf @guardian_denied).
				s.metrics.Shed("shed")
				w.Header().Set("X-Guardian-Action", "shed")
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}
	// Count every evaluation, even while the bound is disabled, so enabling
	// max_inflight by hot reload immediately accounts for work already running.
	defer s.inflight.Add(-1)

	d := s.engine.Evaluate(r.Context(), req)

	w.Header().Set("X-Guardian-Action", string(d.Action))
	w.Header().Set("X-Guardian-Reason", d.Reason)
	switch d.Action {
	case core.ActionAllow:
		w.WriteHeader(http.StatusOK)
	case core.ActionChallenge:
		w.Header().Set(hdrDifficulty, strconv.Itoa(d.Difficulty))
		s.logDecision(req, d)
		w.WriteHeader(http.StatusUnauthorized)
	case core.ActionDeny:
		s.logDecision(req, d)
		w.WriteHeader(http.StatusForbidden)
	default:
		// An action the transport does not recognize fails open by contract,
		// but explicitly and logged — never as an accidental implicit 200.
		s.logDecision(req, d)
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) logDecision(req *core.RequestContext, d core.Decision) {
	s.log.Info("decision",
		"action", d.Action,
		"reason", d.Reason,
		"host", req.Host,
		"ip", req.RemoteAddr,
		"method", req.Method,
		"uri", req.URI,
		"ua", req.UserAgent,
	)
}

type challengeData struct {
	JSON           template.JS
	NoScript       bool
	RefreshSeconds int
	NoJSURL        string
}

// challengePayload is the JSON embedded in the interstitial for the solver.
// Field names are the page's contract (web/challenge.html.tmpl reads them).
type challengePayload struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	Difficulty  int    `json:"difficulty_bits"`
	PassURL     string `json:"pass_url"`
}

// refuseChallenge writes a challenge refusal: a plain 403 with an explanation,
// no page policy since this is not a document response, and no-store.
//
// A 403 is not cacheable by default, but say so anyway: a cached refusal would
// keep failing after the client earns a token.
//
// A short max-age here was tried and measured, on the theory that a client
// which never sends a cookie cannot be harmed by a cached refusal and would
// stop re-asking on every page render. It bought nothing on the path it was
// aimed at. Serving the refusal with private, max-age=30, must-revalidate
// produced the same request rate as no-store (Floorp 153 favicon loads against
// a local origin: 38 requests over 1.7 minutes against 40 over 2.1), while the
// identical policy on a 200 collapsed the same repetition from 46 requests to
// 5, so the instrument could see storage working.
//
// Scope that result honestly: it says this Floorp 153 favicon path did not
// reuse a cacheable 403. It is NOT a general claim that error statuses are
// unstorable, and RFC 9111 does not say so either, since explicit freshness
// makes a final status storable whatever it is. Another client, another status
// or another fetch path could behave differently. It was enough to drop the
// header here, because a cache directive that changes nothing still has to be
// reasoned about forever. Re-measure before re-adding it.
func refuseChallenge(w http.ResponseWriter, msg string) {
	w.Header()["Cache-Control"] = hdrValNoStore
	securityHeaders(w, "", "")
	http.Error(w, msg, http.StatusForbidden)
}

// handleChallenge issues a PoW challenge and serves the interstitial. Angie
// diverts 401s here via error_page, preserving the client's original URL.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	host := headerOr(r, hdrHost, r.Host)
	ip := clientIP(r)
	uri := headerOr(r, hdrURI, "/")
	// Path-resolved config: a paths: overlay may scope PoW (enabled,
	// difficulty, TTLs) to a URI prefix within the host.
	dcfg := s.engine.Config().ConfigFor(host, uri)

	// A subresource cannot run the interstitial, so it is refused one rather
	// than issued one it will silently drop. The page renders markup, runs
	// inline script and spawns a blob: Web Worker to search for the nonce;
	// handing all that to an <img>, a stylesheet or an XHR produces nothing but
	// a decode failure. Two things follow from issuing anyway, and both are
	// fixed by not issuing:
	//
	//   - The issuance counts against the host+IP escalation counter as an
	//     abandoned challenge. Difficulty climbs, pins at the ceiling, and
	//     challenge_farm is reported against a client that never abandoned
	//     anything. An ordinary browser polling /favicon.ico blocks itself this
	//     way in under an hour.
	//   - Refusing the challenge, rather than merely skipping the escalation
	//     bump, is also what keeps the farming defence intact. Skipping the
	//     bump alone would let a farmer collect unlimited cheap base-difficulty
	//     challenges just by claiming Sec-Fetch-Dest: image. A client that
	//     says it cannot use a challenge is simply not given one, so there is
	//     nothing left to farm.
	//
	// The client sees what it saw before: a subresource that fails to load.
	// Nothing that could have succeeded is refused; see isSubresourceDest for
	// why an absent or unrecognized destination keeps the ordinary path, and
	// unscorableFrame for why a frame is never refused, only left unscored.
	//
	// The second branch extends the same argument to a request that sends no
	// Fetch metadata at all, which is not a hypothetical: the browser's favicon
	// service refreshes an icon URL it already knows on a system principal, and
	// that request arrives with no cookie, no Sec-Fetch-* even over HTTPS, and
	// Accept: */*. It reads as unknown to everything above, so it is issued and
	// escalated on every render until the visitor's own workstation is reported
	// as a challenge farmer. Accept is only a heuristic and is consulted only
	// once the two unforgeable signals have come up empty; see
	// acceptLooksNonNavigational for what that does and does not establish, and
	// isDocumentDest for the exemption it yields to.
	dest := r.Header.Get(hdrSecFetchDest)
	switch {
	case isSubresourceDest(dest):
		s.metrics.Challenge("subresource_refused")
		s.log.Debug("challenge refused: request cannot run the interstitial",
			"host", host, "ip", ip, "uri", uri, "dest", dest)
		refuseChallenge(w, "proof-of-work challenge requires a same-origin document request")
		return

	case !isDocumentDest(dest) &&
		r.Header.Get(hdrSecFetchMode) != modeNavigate &&
		acceptLooksNonNavigational(r.Header.Values(hdrAccept)):
		s.metrics.Challenge("accept_heuristic_refused")
		s.log.Debug("challenge refused: request does not look like a navigation",
			"host", host, "ip", ip, "uri", uri,
			"accept", r.Header.Get(hdrAccept))
		// Worded as the behavioural requirement, not as a claim about what the
		// client accepts: this branch fires for Accept: */*, which formally
		// accepts HTML, so telling that client it does not accept HTML would
		// be untrue and would contradict the predicate's own reasoning.
		refuseChallenge(w, "proof-of-work challenge requires a document navigation: Accept must list text/html or text/*")
		return
	}

	h := w.Header()
	h["Content-Type"] = hdrValHTML
	h["Cache-Control"] = hdrValNoStore
	securityHeaders(w, cspChallenge, frameSameOrigin)

	if s.pow == nil || !dcfg.PoW.Enabled {
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}

	// Cheap per-IP issuance rate limit; bucketed per minute. Counted through
	// the CounterCache so the request never blocks on a store write round:
	// the local count enforces immediately (and keeps enforcing if the store
	// is down), the shared counter syncs in the background. The limit is
	// config-driven (pow.issuance_rate_limit) so operators can tighten it.
	limit := dcfg.PoW.IssuanceRateLimit
	// The config parser only accepts s/min/h windows, so Per is always at least
	// a second; the floor keeps the bucket divisor safe for any Config built in
	// code (tests, embedders) rather than parsed from YAML.
	window := max(limit.Per, time.Second)
	// Built by append rather than Sprintf: this key is created on every
	// interstitial fetch, and fmt costs several allocations (boxing plus the
	// intermediate) where append into a stack scratch costs one for the final
	// string. 64 bytes covers "chrl:" + the longest IPv6 form + the bucket.
	var rlBuf [64]byte
	rlb := append(rlBuf[:0], "chrl:"...)
	rlb = append(rlb, ip...)
	rlb = append(rlb, ':')
	rlb = strconv.AppendInt(rlb, time.Now().Unix()/int64(window.Seconds()), 10)
	if int(s.counters.Incr(string(rlb), 2*window)) > limit.Count {
		s.log.Warn("challenge issuance rate limit", "ip", ip, "host", host)
		http.Error(w, "too many challenge requests, slow down", http.StatusTooManyRequests)
		return
	}

	// The attack posture shifts the whole difficulty window up (a no-op when
	// Normal), so the base and ceiling here already reflect the fleet raise.
	attack := s.engine.AttackDetector().State()
	base, maxBits := attackmode.EffectiveBits(attack,
		dcfg.PoW.BaseBits(), dcfg.PoW.MaxBits(), attack.Cap(dcfg.PoW.MaxBits()))

	// The auth decision may have escalated the difficulty (WAF signature hit,
	// anomaly score); Angie relays it via X-Guardian-Difficulty (see the
	// auth_request_set lines in deploy/angie-guardian.conf). Clamp it to the
	// (possibly attack-shifted) [base, max] so a client forging the header can
	// only raise its own difficulty within policy, never lower it.
	difficulty := base
	if v := r.Header.Get(hdrDifficulty); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			difficulty = min(max(n, difficulty), maxBits)
		}
	}

	// A framed navigation that may not be able to render the interstitial is
	// escalated on its own counter and never reported as a farmer. The
	// interstitial's own frame-ancestors 'self' may stop the browser showing
	// it, so "unsolved" here says nothing about the client, and blocking on it
	// lets any page drive an arbitrary visitor into a challenge_farm block by
	// framing a protected URL in a loop. It is still issued, and still
	// escalated: Sec-Fetch-Site cannot tell a hostile frame apart from a
	// same-origin one reached through a cross-site redirect (an SSO callback),
	// which renders and solves fine, so refusing would break those logins, and
	// dropping the difficulty ramp as well would turn two forgeable header
	// values into a cheap-challenge exemption. See unscorableFrame.
	if unscorableFrame(r.Header.Get(hdrSecFetchDest), r.Header.Get(hdrSecFetchSite)) {
		s.metrics.Challenge("frame_unscored")
		s.log.Debug("challenge issued unscored: framed navigation may not render",
			"host", host, "ip", ip, "uri", uri,
			"dest", r.Header.Get(hdrSecFetchDest), "site", r.Header.Get(hdrSecFetchSite))
		if extra := s.pow.BumpFrameEscalation(r.Context(), host, ip, dcfg.PoW.ChallengeTTL.Std()); extra > 0 {
			difficulty = min(difficulty+extra, maxBits)
			s.metrics.Challenge("escalated")
			s.log.Info("challenge difficulty escalated",
				"ip", ip, "host", host, "extra_bits", extra, "difficulty", difficulty, "framed", true)
		}
	} else if extra := s.pow.BumpEscalation(r.Context(), host, ip, dcfg.PoW.ChallengeTTL.Std()); extra > 0 {
		// Escalate for clients that keep requesting challenges without solving
		// them: within the rate limit above, a challenge farmer would otherwise
		// pay base difficulty forever. Each unsolved issuance past a small
		// allowance raises the work, capped at the ceiling; a successful
		// redemption resets this host+IP counter (core/pow/escalation.go).
		//
		// Escalation alone pinned at the ceiling means this client has
		// abandoned enough challenges that no amount of extra work can be
		// demanded anymore: a challenge farmer. Report it as a scoreboard
		// event, blocked past the waf.ip_behaviour.thresholds challenge_farm
		// rate (ReportEvent resolves host-level config, like pow_fail, not
		// paths: overlays). The predicate compares against base, not the
		// possibly WAF/anomaly-elevated difficulty, so only abandonment
		// itself triggers.
		if base+extra >= maxBits {
			s.metrics.Challenge("farm_detected")
			s.engine.ReportEvent(r.Context(), host, ip, core.EventChallengeFarm,
				fmt.Sprintf("extra_bits=%d", extra))
		}
		difficulty = min(difficulty+extra, maxBits)
		s.metrics.Challenge("escalated")
		s.log.Info("challenge difficulty escalated",
			"ip", ip, "host", host, "extra_bits", extra, "difficulty", difficulty)
	}

	// Under attack, issue store-free (stateless) challenges so a flood of new
	// clients stops writing an issuance record per request. Redemption accepts
	// both formats, so this can flip per request with no coordination.
	var ch *pow.Challenge
	var err error
	issuedStateless := attack.Stateless
	if attack.Stateless {
		ch, err = s.pow.IssueStateless(host, ip, uri, difficulty, dcfg.PoW.NoScriptFallback)
	} else {
		ch, err = s.pow.Issue(r.Context(), host, ip, uri,
			difficulty, dcfg.PoW.ChallengeTTL.Std(), dcfg.PoW.NoScriptFallback)
		if err != nil {
			// Stateful issuance is the only challenge-page operation that needs a
			// store write. If the store is unavailable, falling back to the
			// authenticated stateless format preserves the shipped fail-open
			// availability contract for new visitors instead of trapping every
			// unvouched client on a 503 until Redis/the store backend recovers.
			s.log.Warn("stateful challenge issuance failed; falling back to stateless",
				"host", host, "ip", ip, "err", err)
			ch, err = s.pow.IssueStateless(host, ip, uri, difficulty, dcfg.PoW.NoScriptFallback)
			if err == nil {
				issuedStateless = true
				s.metrics.Challenge("issued_stateless_fallback")
			}
		}
	}
	if err != nil {
		s.log.Error("challenge issuance failed", "host", host, "ip", ip, "err", err)
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	s.engine.AttackDetector().ChallengeIssued()
	// Always count "issued" so pre-existing dashboards/alerts keep seeing the
	// full issuance rate; additionally count "issued_stateless" so the split
	// between the two paths is visible during an attack.
	s.metrics.Challenge("issued")
	if issuedStateless {
		s.metrics.Challenge("issued_stateless")
	}

	// A struct, not map[string]any: the map encoder sorts keys and boxes every
	// value through interfaces on each of the many issuances per second this
	// path serves under load; the struct encoder does none of that.
	payload, err := json.Marshal(&challengePayload{
		ChallengeID: ch.ID,
		Challenge:   ch.Challenge,
		Difficulty:  ch.Difficulty,
		PassURL:     PassPath,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	err = s.challengeTmpl.Execute(w, &challengeData{
		JSON:           template.JS(payload),
		NoScript:       dcfg.PoW.NoScriptFallback,
		RefreshSeconds: int(s.pow.NoJSMinDelay/time.Second) + 1,
		NoJSURL:        fmt.Sprintf("%s?cid=%s&nojs=1", PassPath, ch.ID),
	})
	if err != nil {
		s.log.Error("challenge render failed", "err", err)
	}
}

// handlePassSolve verifies a solved challenge posted by the page's JS and
// sets the signed token cookie.
func (s *Server) handlePassSolve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		ElapsedMS   int64  `json:"elapsed_ms"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "malformed request"})
		return
	}
	s.redeem(w, r, &pow.RedeemRequest{ChallengeID: body.ChallengeID, Nonce: body.Nonce}, body.ElapsedMS)
}

// handlePassNoJS is the meta-refresh fallback: no work was done, but the
// client demonstrably waited, which the domain opted into accepting.
func (s *Server) handlePassNoJS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("nojs") != "1" {
		http.Error(w, "missing solution", http.StatusBadRequest)
		return
	}
	s.redeem(w, r, &pow.RedeemRequest{ChallengeID: r.URL.Query().Get("cid"), NoJS: true}, 0)
}

func (s *Server) redeem(w http.ResponseWriter, r *http.Request, req *pow.RedeemRequest, elapsedMS int64) {
	host := headerOr(r, hdrHost, r.Host)
	ip := clientIP(r)
	cfg := s.engine.Config()
	dcfg := cfg.DomainFor(host)

	// Gate on PoWAnywhere, not PoW.Enabled: a domain may disable PoW at the
	// top level and enable it only for some paths, and those solves must
	// still redeem. The path itself is not in the solve request; the TTLs
	// callback below resolves it from the challenge record's stored URI.
	if s.pow == nil || !dcfg.PoWAnywhere() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "unavailable"})
		return
	}

	req.Host = host
	req.IP = ip
	req.UserAgent = headerOr(r, hdrUA, r.UserAgent())
	req.TokenTTL = dcfg.PoW.TokenTTL.Std()
	req.ChallengeTTL = dcfg.PoW.ChallengeTTL.Std()
	req.TTLs = func(uri string) (time.Duration, time.Duration) {
		pc := cfg.ConfigFor(host, uri)
		return pc.PoW.TokenTTL.Std(), pc.PoW.ChallengeTTL.Std()
	}

	res, err := s.pow.Redeem(r.Context(), req)
	if err != nil {
		s.metrics.Challenge("failed")
		status := http.StatusForbidden
		if !errors.Is(err, pow.ErrChallengeUnknown) && !errors.Is(err, pow.ErrBadSolution) &&
			!errors.Is(err, pow.ErrBindingMismatch) && !errors.Is(err, pow.ErrTooFast) &&
			!errors.Is(err, pow.ErrNoJSDisabled) {
			status = http.StatusInternalServerError
			s.log.Error("redeem failed", "host", host, "ip", ip, "err", err)
		} else {
			s.log.Info("redeem rejected", "host", host, "ip", ip, "nojs", req.NoJS, "err", err)
			// Failed solutions score against the client: repeated bad nonces
			// or forged/replayed challenge IDs earn a behavioural block.
			evtype := core.EventPoWFail
			if errors.Is(err, pow.ErrChallengeUnknown) || errors.Is(err, pow.ErrBindingMismatch) ||
				errors.Is(err, pow.ErrNoJSDisabled) {
				evtype = core.EventTamper
			}
			s.engine.ReportEvent(r.Context(), host, ip, evtype, err.Error())
		}
		if req.NoJS {
			http.Error(w, "challenge verification failed", status)
		} else {
			writeJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		}
		return
	}

	s.metrics.Challenge("solved")
	s.engine.AttackDetector().ChallengeRedeemed()
	if res.SoftError != nil {
		// The token was minted despite a failed single-spend write (store
		// outage on the stateless path). Bounded by token binding; counted.
		s.metrics.Challenge("spent_cas_failed")
		s.log.Warn("stateless spend cas failed, token minted fail-open",
			"host", host, "ip", ip, "err", res.SoftError)
	}
	// elapsed_ms is browser telemetry, not authenticated challenge state. Only
	// accept values that fit inside the actual path's challenge lifetime so a
	// successful client cannot poison the process-lifetime histogram.
	maxElapsedMS := cfg.ConfigFor(host, res.RedirectURI).PoW.ChallengeTTL.Std().Milliseconds()
	if elapsedMS > 0 && elapsedMS <= maxElapsedMS {
		s.metrics.SolveTime(float64(elapsedMS) / 1000)
	}
	s.log.Info("challenge solved",
		"host", host, "ip", ip, "nojs", req.NoJS, "elapsed_ms", elapsedMS)
	// Secure by default; dropped only when Angie says the client connection is
	// plain http (X-Guardian-Proto, $scheme), because a browser will not send
	// a Secure cookie back over http and the client would loop on the
	// challenge forever. An absent header means Secure stays on.
	http.SetCookie(w, &http.Cookie{
		Name:     pow.CookieName,
		Value:    res.Token,
		Path:     "/",
		MaxAge:   int(res.TokenTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.Header.Get(hdrProto) != "http",
		SameSite: http.SameSiteLaxMode,
	})
	if req.NoJS {
		http.Redirect(w, r, safeRedirect(res.RedirectURI), http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDenied(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	securityHeaders(w, cspStatic, frameSameOrigin)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(s.deniedHTML)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	securityHeaders(w, "", "")
	_, _ = w.Write([]byte("ok\n"))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// No CSP: a JSON body is never a document. nosniff is what stops a browser
	// from rendering one as HTML anyway.
	securityHeaders(w, "", "")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// safeRedirect confines post-challenge redirects to same-site paths.
func safeRedirect(uri string) string {
	if uri == "" || uri[0] != '/' || strings.HasPrefix(uri, "//") || strings.HasPrefix(uri, "/\\") {
		return "/"
	}
	return uri
}

func headerOr(r *http.Request, name, fallback string) string {
	if v := r.Header.Get(name); v != "" {
		return v
	}
	return fallback
}

func stripPort(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// clientIP is headerOr for the client address with a lazily evaluated fallback:
// stripPort allocates an error for an address carrying no port, and behind the
// glue the header is always set, so the fallback must not run per request.
func clientIP(r *http.Request) string {
	if v := r.Header.Get(hdrIP); v != "" {
		return v
	}
	return stripPort(r.RemoteAddr)
}
