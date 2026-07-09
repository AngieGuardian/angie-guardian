// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httptransport is the Path A transport: a thin HTTP wrapper around
// core.Engine.Evaluate, driven by Angie's auth_request subrequests, plus the
// challenge/pass/denied endpoints the Angie glue diverts to.
package httptransport

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/melroy89/angie-guardian/web"
)

// PassPath is the public URL of the solution endpoint as exposed by the
// Angie glue; the challenge page posts here.
const PassPath = "/__guardian/pass"

// issuanceRateLimit caps challenge issuance per IP per minute so the
// interstitial itself cannot be used to flood the store (plan §11).
const issuanceRateLimit = 60

type Server struct {
	engine  *core.Engine
	cfg     *core.Config
	pow     *pow.Manager // nil = PoW unavailable (no signing key configured)
	store   store.Store
	metrics *metrics.Metrics // nil = no-op
	log     *slog.Logger
	mux     *http.ServeMux

	challengeTmpl *template.Template
	deniedHTML    []byte
}

func New(engine *core.Engine, cfg *core.Config, mgr *pow.Manager, st store.Store, m *metrics.Metrics, log *slog.Logger) *Server {
	s := &Server{
		engine: engine, cfg: cfg, pow: mgr, store: st, metrics: m, log: log,
		mux:           http.NewServeMux(),
		challengeTmpl: template.Must(template.ParseFS(web.FS, "challenge.html.tmpl")),
	}
	s.deniedHTML, _ = web.FS.ReadFile("denied.html")

	s.mux.HandleFunc("GET /auth", s.handleAuth)
	s.mux.HandleFunc("GET /challenge", s.handleChallenge)
	s.mux.HandleFunc("/denied", s.handleDenied)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	// The pass endpoint under both its internal name and its public path, so
	// Guardian also works probed directly (tests, dev without Angie).
	for _, p := range []string{"/pass", PassPath} {
		s.mux.HandleFunc("POST "+p, s.handlePassSolve)
		s.mux.HandleFunc("GET "+p, s.handlePassNoJS)
	}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// requestContext builds the core request from the X-Guardian-* headers the
// Angie snippet sets on the subrequest, falling back to the subrequest's own
// fields so Guardian also behaves sanely when probed directly.
func (s *Server) requestContext(r *http.Request) *core.RequestContext {
	return &core.RequestContext{
		Host:       headerOr(r, "X-Guardian-Host", r.Host),
		Method:     headerOr(r, "X-Guardian-Method", r.Method),
		URI:        headerOr(r, "X-Guardian-URI", r.URL.RequestURI()),
		RemoteAddr: headerOr(r, "X-Guardian-IP", stripPort(r.RemoteAddr)),
		UserAgent:  headerOr(r, "X-Guardian-UA", r.UserAgent()),
		Cookie:     headerOr(r, "X-Guardian-Cookie", r.Header.Get("Cookie")),
	}
}

// handleAuth answers Angie's auth_request subrequest: 2xx lets the request
// through, 401 diverts to @guardian_challenge, 403 to @guardian_denied.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	req := s.requestContext(r)
	d := s.engine.Evaluate(r.Context(), req)

	w.Header().Set("X-Guardian-Action", string(d.Action))
	w.Header().Set("X-Guardian-Reason", d.Reason)
	switch d.Action {
	case core.ActionAllow:
		w.WriteHeader(http.StatusOK)
	case core.ActionChallenge:
		w.Header().Set("X-Guardian-Difficulty", strconv.Itoa(d.Difficulty))
		s.logDecision(req, d)
		w.WriteHeader(http.StatusUnauthorized)
	case core.ActionDeny:
		s.logDecision(req, d)
		w.WriteHeader(http.StatusForbidden)
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

// handleChallenge issues a PoW challenge and serves the interstitial. Angie
// diverts 401s here via error_page, preserving the client's original URL.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	host := headerOr(r, "X-Guardian-Host", r.Host)
	ip := headerOr(r, "X-Guardian-IP", stripPort(r.RemoteAddr))
	uri := headerOr(r, "X-Guardian-URI", "/")
	dcfg := s.cfg.DomainFor(host)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if s.pow == nil || !dcfg.PoW.Enabled {
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}

	// Cheap per-IP issuance rate limit; bucketed per minute.
	rlKey := fmt.Sprintf("chrl:%s:%d", ip, time.Now().Unix()/60)
	if n, err := s.store.Incr(r.Context(), rlKey, 2*time.Minute); err == nil && n > issuanceRateLimit {
		s.log.Warn("challenge issuance rate limit", "ip", ip, "host", host)
		http.Error(w, "too many challenge requests, slow down", http.StatusTooManyRequests)
		return
	}

	// The auth decision may have escalated the difficulty (WAF signature hit,
	// anomaly score); Angie relays it via X-Guardian-Difficulty (see the
	// auth_request_set lines in deploy/angie-guardian.conf). Clamp it to the
	// domain's [base, max] so a client forging the header can only raise its
	// own difficulty within policy, never lower it.
	difficulty := dcfg.PoW.BaseBits()
	if v := r.Header.Get("X-Guardian-Difficulty"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			difficulty = min(max(n, difficulty), dcfg.PoW.MaxBits())
		}
	}

	ch, err := s.pow.Issue(r.Context(), host, ip, uri,
		difficulty, dcfg.PoW.ChallengeTTL.Std(), dcfg.PoW.NoScriptFallback)
	if err != nil {
		s.log.Error("challenge issuance failed", "host", host, "ip", ip, "err", err)
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	s.metrics.Challenge("issued")

	payload, err := json.Marshal(map[string]any{
		"challenge_id":    ch.ID,
		"challenge":       ch.Challenge,
		"difficulty_bits": ch.Difficulty,
		"pass_url":        PassPath,
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
	host := headerOr(r, "X-Guardian-Host", r.Host)
	ip := headerOr(r, "X-Guardian-IP", stripPort(r.RemoteAddr))
	dcfg := s.cfg.DomainFor(host)

	if s.pow == nil || !dcfg.PoW.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "unavailable"})
		return
	}

	req.Host = host
	req.IP = ip
	req.UserAgent = headerOr(r, "X-Guardian-UA", r.UserAgent())
	req.TokenTTL = dcfg.PoW.TokenTTL.Std()
	req.ChallengeTTL = dcfg.PoW.ChallengeTTL.Std()

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
	if elapsedMS > 0 {
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
		Secure:   r.Header.Get("X-Guardian-Proto") != "http",
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
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(s.deniedHTML)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok\n"))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
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
