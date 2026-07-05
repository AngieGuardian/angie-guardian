// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/web"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// AdminServer exposes Prometheus /metrics and an authenticated JSON admin API
// on a listener separate from the auth hot path (bind it to loopback or a
// management interface). Every /admin route requires a bearer token; /metrics
// and /healthz do not, so a scraper needs no secret.
type AdminServer struct {
	engine  *core.Engine
	cfg     *core.Config
	token   string
	keyPath string
	prevDir string
	log     *slog.Logger
	mux     *http.ServeMux
}

func NewAdminServer(engine *core.Engine, cfg *core.Config, m *metrics.Metrics, token, keyPath, prevDir string, log *slog.Logger) *AdminServer {
	s := &AdminServer{
		engine: engine, cfg: cfg, token: token,
		keyPath: keyPath, prevDir: prevDir, log: log,
		mux: http.NewServeMux(),
	}
	if m != nil {
		s.mux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{}))
	}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	// Authenticated admin API.
	s.mux.HandleFunc("GET /admin/blocks", s.auth(s.handleBlockList))
	s.mux.HandleFunc("GET /admin/blocks/{ip}", s.auth(s.handleBlockStatus))
	s.mux.HandleFunc("PUT /admin/blocks/{ip}", s.auth(s.handleBlock))
	s.mux.HandleFunc("DELETE /admin/blocks/{ip}", s.auth(s.handleUnblock))
	s.mux.HandleFunc("GET /admin/decisions", s.auth(s.handleDecisions))
	s.mux.HandleFunc("GET /admin/stats", s.auth(s.handleStats))
	s.mux.HandleFunc("GET /admin/score", s.auth(s.handleScore))
	s.mux.HandleFunc("POST /admin/rotate-key", s.auth(s.handleRotateKey))
	s.mux.HandleFunc("GET /admin/config", s.auth(s.handleConfig))

	// The reporting dashboard is a static self-contained page: it holds no data
	// itself (all data comes from the token-guarded endpoints above, which the
	// page calls with a token the operator pastes once), so serving the shell
	// unauthenticated is safe. Off by default; enable with admin.dashboard.
	if cfg.Admin.Dashboard {
		s.mux.HandleFunc("GET /admin/dashboard", s.handleDashboard)
	}
	return s
}

func (s *AdminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// auth wraps a handler with constant-time bearer-token checking.
func (s *AdminServer) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if len(got) <= len(prefix) || subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (s *AdminServer) handleBlockStatus(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	reason, blocked, err := s.engine.BlockStatus(r.Context(), ip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "blocked": blocked, "reason": reason})
}

func (s *AdminServer) handleBlock(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	var body struct {
		Reason string `json:"reason"`
		TTL    string `json:"ttl"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	ttl := 15 * time.Minute
	if body.TTL != "" {
		d, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ttl: " + err.Error()})
			return
		}
		ttl = d
	}
	if body.Reason == "" {
		body.Reason = "admin"
	}
	if err := s.engine.BlockIP(r.Context(), ip, body.Reason, ttl); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log.Info("admin blocked ip", "ip", ip, "reason", body.Reason, "ttl", ttl)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "blocked": true, "reason": body.Reason, "ttl": ttl.String()})
}

func (s *AdminServer) handleUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if err := s.engine.UnblockIP(r.Context(), ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log.Info("admin unblocked ip", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "blocked": false})
}

// handleBlockList returns every currently active behavioural block.
func (s *AdminServer) handleBlockList(w http.ResponseWriter, r *http.Request) {
	blocks, err := s.engine.ListBlocks(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(blocks), "blocks": blocks})
}

// handleDecisions returns the engine's recent non-allow decisions, newest
// first. Query: ?limit= (default 50), ?action=deny|challenge, ?reason=<prefix>.
func (s *AdminServer) handleDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "limit must be a positive integer"})
			return
		}
		limit = n
	}
	action, reason := q.Get("action"), q.Get("reason")

	// Filter over the full ring, then cut to limit, so a filtered view is not
	// starved by unrelated entries.
	all := s.engine.RecentDecisions(0)
	out := make([]core.RecentDecision, 0, min(limit, len(all)))
	for _, d := range all {
		if action != "" && d.Action != action {
			continue
		}
		if reason != "" && !strings.HasPrefix(d.Reason, reason) {
			continue
		}
		out = append(out, d)
		if len(out) == limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "decisions": out})
}

// handleStats returns a small rollup for the dashboard header: active block
// count plus action/reason-category counts over the recent-decisions window.
// Long-horizon numbers live in /metrics; this is the "right now" view.
func (s *AdminServer) handleStats(w http.ResponseWriter, r *http.Request) {
	blocks, err := s.engine.ListBlocks(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	recent := s.engine.RecentDecisions(0)
	byAction := map[string]int{}
	byReason := map[string]int{}
	for _, d := range recent {
		byAction[d.Action]++
		// Collapse to the leading token ("waf:dotfile-probe" → "waf"), the same
		// categories the guardian_decisions_total metric uses.
		cat := d.Reason
		if i := strings.IndexByte(cat, ':'); i >= 0 {
			cat = cat[:i]
		}
		byReason[cat]++
	}
	out := map[string]any{
		"blocks_active": len(blocks),
		"recent": map[string]any{
			"total":     len(recent),
			"by_action": byAction,
			"by_reason": byReason,
		},
	}
	if len(recent) > 0 {
		out["recent"].(map[string]any)["newest"] = recent[0].Time
		out["recent"].(map[string]any)["oldest"] = recent[len(recent)-1].Time
	}
	writeJSON(w, http.StatusOK, out)
}

// handleScore answers "how anomalous would this request look?" for tuning
// challenge_at/deny_at. Query: ?host=&uri=&ua=
func (s *AdminServer) handleScore(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "host query param required"})
		return
	}
	score := s.engine.ScoreRequest(host, q.Get("uri"), q.Get("ua"))
	if score < 0 {
		writeJSON(w, http.StatusOK, map[string]any{"host": host, "scored": false, "reason": "no anomaly model for this domain"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "scored": true, "score": score})
}

func (s *AdminServer) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	mgr := s.engine.PoWManager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "proof-of-work not configured"})
		return
	}
	if s.keyPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no signing_key_file configured; cannot rotate"})
		return
	}
	if err := mgr.Rotate(s.keyPath, s.prevDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log.Info("admin rotated signing key", "key", s.keyPath, "prev_dir", s.prevDir)
	writeJSON(w, http.StatusOK, map[string]any{"rotated": true})
}

// handleDashboard serves the static reporting page. No auth: the shell holds
// no data: everything it shows comes from the token-guarded endpoints, called
// with a token the operator provides in-page (kept in sessionStorage).
func (s *AdminServer) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	page, err := web.FS.ReadFile("dashboard.html")
	if err != nil {
		http.Error(w, "dashboard page missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

// handleConfig returns a redacted view of the loaded per-domain config, so an
// operator can confirm what is active without shell access to the box.
func (s *AdminServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	type domainView struct {
		PoWEnabled  bool   `json:"pow_enabled"`
		PoWMode     string `json:"pow_mode"`
		Keywords    bool   `json:"waf_keywords"`
		Anomaly     bool   `json:"waf_anomaly"`
		Honeypot    bool   `json:"waf_honeypot"`
		IPBehaviour bool   `json:"waf_ip_behaviour"`
	}
	view := func(dc *core.DomainConfig) domainView {
		return domainView{
			PoWEnabled: dc.PoW.Enabled, PoWMode: dc.PoW.Mode,
			Keywords: dc.WAF.Keywords.Enabled, Anomaly: dc.WAF.Anomaly.Enabled,
			Honeypot: dc.WAF.Honeypot.Enabled, IPBehaviour: dc.WAF.IPBehaviour.Enabled,
		}
	}
	out := map[string]any{
		"store":    s.cfg.Store.Backend,
		"defaults": view(&s.cfg.Defaults),
		"domains":  map[string]domainView{},
	}
	for host, dc := range s.cfg.DomainViews() {
		out["domains"].(map[string]domainView)[host] = view(dc)
	}
	writeJSON(w, http.StatusOK, out)
}
