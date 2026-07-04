// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/metrics"
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
	s.mux.HandleFunc("GET /admin/blocks/{ip}", s.auth(s.handleBlockStatus))
	s.mux.HandleFunc("PUT /admin/blocks/{ip}", s.auth(s.handleBlock))
	s.mux.HandleFunc("DELETE /admin/blocks/{ip}", s.auth(s.handleUnblock))
	s.mux.HandleFunc("GET /admin/score", s.auth(s.handleScore))
	s.mux.HandleFunc("POST /admin/rotate-key", s.auth(s.handleRotateKey))
	s.mux.HandleFunc("GET /admin/config", s.auth(s.handleConfig))
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
