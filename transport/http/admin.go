// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/intel"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/web"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// AdminServer exposes Prometheus /metrics and an authenticated JSON admin API
// on a listener separate from the auth hot path (bind it to loopback or a
// management interface). Every /admin route requires a bearer token; /metrics
// and /healthz do not, so a scraper needs no secret.
type AdminServer struct {
	engine  *core.Engine
	metrics *metrics.Metrics // nil = no metrics endpoint, no challenge stats
	token   string
	keyPath string
	prevDir string
	reload  func() error // nil = no reload endpoint (owned by main: re-reads guardian.yaml)
	log     *slog.Logger
	mux     *http.ServeMux
	angie   *angieClient // nil = admin.angie_api not configured

	// assetETags holds a strong ETag per vendored dashboard asset, keyed by
	// embedded path and computed once at startup. It lets each asset revalidate
	// cheaply (304 on match) so a guardiand upgrade that changes a blob is
	// picked up immediately instead of a returning browser pairing a stale
	// library with new dashboard JavaScript.
	assetETags map[string]string
}

// dashboardAssets are the vendored files the dashboard loads, mapping the
// served URL to its embedded path and content type. All are static libraries
// or map data holding no request data, which is why they are served
// unauthenticated (see handleAsset).
var dashboardAssets = map[string]struct{ path, contentType string }{
	"/admin/chart.umd.min.js":           {"vendor/chart.umd.min.js", "text/javascript; charset=utf-8"},
	"/admin/chart-geo.umd.min.js":       {"vendor/chart-geo.umd.min.js", "text/javascript; charset=utf-8"},
	"/admin/hammer.min.js":              {"vendor/hammer.min.js", "text/javascript; charset=utf-8"},
	"/admin/chartjs-plugin-zoom.min.js": {"vendor/chartjs-plugin-zoom.min.js", "text/javascript; charset=utf-8"},
	"/admin/countries-110m.json":        {"vendor/countries-110m.json", "application/json; charset=utf-8"},
}

// NewAdminServer builds the admin+metrics handler. The cfg parameter only
// decides construction-time wiring (the dashboard route); request handlers
// read the live config through the engine so a hot reload is reflected.
// reload re-reads and applies guardian.yaml (nil disables POST /admin/reload).
func NewAdminServer(engine *core.Engine, cfg *core.Config, m *metrics.Metrics, token, keyPath, prevDir string, reload func() error, log *slog.Logger) *AdminServer {
	s := &AdminServer{
		engine: engine, metrics: m, token: token,
		keyPath: keyPath, prevDir: prevDir, reload: reload, log: log,
		mux: http.NewServeMux(),
	}
	if cfg.Admin.AngieAPI.URL != "" {
		s.angie = newAngieClient(cfg.Admin.AngieAPI, log)
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
	s.mux.HandleFunc("GET /admin/distributions", s.auth(s.handleDistributions))
	s.mux.HandleFunc("GET /admin/offenders", s.auth(s.handleOffenders))
	s.mux.HandleFunc("GET /admin/angie", s.auth(s.handleAngie))
	s.mux.HandleFunc("GET /admin/score", s.auth(s.handleScore))
	s.mux.HandleFunc("POST /admin/rotate-key", s.auth(s.handleRotateKey))
	s.mux.HandleFunc("POST /admin/reload", s.auth(s.handleReload))
	s.mux.HandleFunc("GET /admin/config", s.auth(s.handleConfig))
	s.mux.HandleFunc("GET /admin/intel", s.auth(s.handleIntel))
	s.mux.HandleFunc("GET /admin/intel/{ip}", s.auth(s.handleIntelLookup))
	s.mux.HandleFunc("GET /admin/offload", s.auth(s.handleOffload))
	s.mux.HandleFunc("POST /admin/offload/reconcile", s.auth(s.handleOffloadReconcile))
	s.mux.HandleFunc("GET /admin/attack", s.auth(s.handleAttack))
	s.mux.HandleFunc("POST /admin/attack", s.auth(s.handleAttackSet))

	// The reporting dashboard is a static self-contained page: it holds no data
	// itself (all data comes from the token-guarded endpoints above, which the
	// page calls with a token the operator pastes once), so serving the shell
	// unauthenticated is safe. Off by default; enable with admin.dashboard.
	if cfg.Admin.Dashboard {
		s.mux.HandleFunc("GET /admin/dashboard", s.handleDashboard)
		// The chart libraries and map data are vendored (web/vendor) and served
		// same-origin, unauthenticated for the same reason as the dashboard
		// shell: a <script src> fetch carries no bearer token, and the assets
		// hold no data. No CDN, works air-gapped.
		s.assetETags = make(map[string]string, len(dashboardAssets))
		for route, a := range dashboardAssets {
			if blob, err := web.FS.ReadFile(a.path); err == nil {
				sum := sha256.Sum256(blob)
				s.assetETags[a.path] = `"` + hex.EncodeToString(sum[:16]) + `"`
			}
			s.mux.HandleFunc("GET "+route, s.handleAsset)
		}
	}
	return s
}

func (s *AdminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// auth wraps a handler with constant-time bearer-token checking.
func (s *AdminServer) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if !strings.HasPrefix(got, prefix) || len(got) <= len(prefix) ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (s *AdminServer) handleBlockStatus(w http.ResponseWriter, r *http.Request) {
	ip, ok := canonicalAdminIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	reason, blocked, err := s.engine.BlockStatus(r.Context(), ip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "blocked": blocked, "reason": reason})
}

func (s *AdminServer) handleBlock(w http.ResponseWriter, r *http.Request) {
	ip, ok := canonicalAdminIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
		TTL    string `json:"ttl"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request: " + err.Error()})
		return
	} else if err == nil {
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request: trailing JSON value"})
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request: " + err.Error()})
			}
			return
		}
	}
	ttl := 15 * time.Minute
	if body.TTL != "" {
		d, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ttl: " + err.Error()})
			return
		}
		ttl = d
	}
	if ttl <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ttl must be greater than zero"})
		return
	}
	if ttl > core.MaxStateTTL {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ttl must be at most " + core.MaxStateTTL.String()})
		return
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
	ip, ok := canonicalAdminIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	if err := s.engine.UnblockIP(r.Context(), ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log.Info("admin unblocked ip", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "blocked": false})
}

func canonicalAdminIP(w http.ResponseWriter, raw string) (string, bool) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ip: " + err.Error()})
		return "", false
	}
	return addr.Unmap().String(), true
}

const (
	defaultBlockListLimit = 1000
	maxBlockListLimit     = 10000
)

// handleBlockList returns a bounded page of active behavioural blocks.
func (s *AdminServer) handleBlockList(w http.ResponseWriter, r *http.Request) {
	limit := defaultBlockListLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxBlockListLimit {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "limit must be an integer from 1 through 10000"})
			return
		}
		limit = n
	}
	blocks, complete, err := s.engine.ListBlocksLimit(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(blocks), "complete": complete, "blocks": blocks})
}

// recentDecisionView adds optional read-time IP intelligence to the ring's
// immutable request/decision record. Keeping it out of core.RecentDecision
// avoids a GeoIP lookup on the request hot path and lets refreshed databases
// improve rows that are already in the ring.
type recentDecisionView struct {
	core.RecentDecision
	intel.Info
}

// handleDecisions returns the engine's recent non-allow decisions, newest
// first, enriched with configured GeoIP/ASN data. Query: ?limit= (default 50),
// ?action=deny|challenge, ?reason=<prefix>.
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
	out := make([]recentDecisionView, 0, min(limit, len(all)))
	provider := s.engine.Intel()
	byIP := make(map[string]intel.Info)
	for _, d := range all {
		if action != "" && d.Action != action {
			continue
		}
		if reason != "" && !strings.HasPrefix(d.Reason, reason) {
			continue
		}
		row := recentDecisionView{RecentDecision: d}
		if provider != nil {
			info, ok := byIP[d.IP]
			if !ok {
				if addr, err := netip.ParseAddr(d.IP); err == nil {
					info = provider.Lookup(addr)
				}
				byIP[d.IP] = info
			}
			row.Info = info
		}
		out = append(out, row)
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
	blocksActive := -1
	blocksComplete := false
	if enf := s.engine.Enforcer(); enf != nil {
		mirror := enf.Status().Mirror
		if mirror.Seeded {
			blocksActive = mirror.Entries
			blocksComplete = mirror.Complete
		}
	}
	recent := s.engine.RecentDecisions(0)
	byAction := map[string]int{}
	byReason := map[string]int{}
	for _, d := range recent {
		byAction[d.Action]++
		byReason[reasonCat(d.Reason)]++
	}
	out := map[string]any{
		"blocks_active":   blocksActive,
		"blocks_complete": blocksComplete,
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
	if ch := s.challengeStats(); ch != nil {
		out["challenges"] = ch
	}
	if d := s.engine.AttackDetector(); d != nil {
		st := d.State()
		out["attack"] = map[string]any{"level": st.Level.String(), "since": st.Since}
	}
	writeJSON(w, http.StatusOK, out)
}

// challengeStats reads the PoW lifecycle counters and the mean solve time
// back out of the Prometheus registry, so the dashboard shows them without a
// second bookkeeping path (process lifetime, not just the recent window).
// Returns nil when metrics are disabled.
func (s *AdminServer) challengeStats() map[string]any {
	if s.metrics == nil {
		return nil
	}
	families, err := s.metrics.Registry().Gather()
	if err != nil {
		s.log.Warn("metrics gather failed", "err", err)
		return nil
	}
	out := map[string]any{"issued": 0.0, "solved": 0.0, "failed": 0.0}
	for _, mf := range families {
		switch mf.GetName() {
		case "guardian_challenges_total":
			for _, m := range mf.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "outcome" {
						out[l.GetValue()] = m.GetCounter().GetValue()
					}
				}
			}
		case "guardian_challenge_solve_seconds":
			for _, m := range mf.GetMetric() {
				h := m.GetHistogram()
				if h.GetSampleCount() > 0 {
					out["avg_solve_seconds"] = h.GetSampleSum() / float64(h.GetSampleCount())
				}
			}
		}
	}
	return out
}

// handleDistributions returns registry-derived data the recent-decisions ring
// cannot supply: the solve-time and anomaly-score histograms (as ready-to-plot
// per-bucket counts, not cumulative) and per-domain decision totals from
// decisions_total (allow-inclusive, since the ring holds no allows). All from a
// single Gather() of the existing metrics, so it adds no cardinality and never
// touches the hot path. Empty (but well-formed) when metrics are disabled.
func (s *AdminServer) handleDistributions(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"solve_time": emptyHistogram(),
		"anomaly":    emptyHistogram(),
		"per_domain": map[string]map[string]float64{},
	}
	if s.metrics == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	families, err := s.metrics.Registry().Gather()
	if err != nil {
		s.log.Warn("metrics gather failed", "err", err)
		writeJSON(w, http.StatusOK, out)
		return
	}
	for _, mf := range families {
		switch mf.GetName() {
		case "guardian_challenge_solve_seconds":
			// A single (unlabeled) histogram.
			for _, m := range mf.GetMetric() {
				out["solve_time"] = histogramToBuckets(m.GetHistogram())
			}
		case "guardian_anomaly_score":
			// Labelled by domain; sum every domain's buckets into one
			// distribution (a per-domain split can come later if wanted).
			out["anomaly"] = sumHistograms(mf.GetMetric())
		case "guardian_decisions_total":
			perDomain := map[string]map[string]float64{}
			for _, m := range mf.GetMetric() {
				var action, domain string
				for _, l := range m.GetLabel() {
					switch l.GetName() {
					case "action":
						action = l.GetValue()
					case "domain":
						domain = l.GetValue()
					}
				}
				if domain == "" {
					domain = "default"
				}
				if perDomain[domain] == nil {
					perDomain[domain] = map[string]float64{}
				}
				perDomain[domain][action] += m.GetCounter().GetValue()
			}
			out["per_domain"] = perDomain
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// bucketCount is one histogram bar: observations that fell in (prev_le, le],
// with le="+Inf" for the overflow bucket. Non-cumulative, ready to plot.
type bucketCount struct {
	Le    string  `json:"le"`
	Count float64 `json:"count"`
}

func emptyHistogram() map[string]any {
	return map[string]any{"buckets": []bucketCount{}, "sum": 0.0, "count": 0.0}
}

// histogramToBuckets converts one Prometheus histogram (cumulative buckets +
// an implicit +Inf) into per-bucket counts the dashboard can bar-chart directly.
func histogramToBuckets(h *dto.Histogram) map[string]any {
	if h == nil {
		return emptyHistogram()
	}
	buckets := make([]bucketCount, 0, len(h.GetBucket())+1)
	var prevCumulative float64
	for _, b := range h.GetBucket() {
		cum := float64(b.GetCumulativeCount())
		buckets = append(buckets, bucketCount{
			Le:    strconv.FormatFloat(b.GetUpperBound(), 'g', -1, 64),
			Count: cum - prevCumulative,
		})
		prevCumulative = cum
	}
	// The +Inf overflow bucket: total observations minus the last explicit le.
	total := float64(h.GetSampleCount())
	buckets = append(buckets, bucketCount{Le: "+Inf", Count: total - prevCumulative})
	return map[string]any{"buckets": buckets, "sum": h.GetSampleSum(), "count": total}
}

// sumHistograms merges the per-label histograms of one metric family (e.g.
// anomaly_score across domains) into a single distribution by adding aligned
// cumulative bucket counts, then converting to per-bucket counts.
func sumHistograms(ms []*dto.Metric) map[string]any {
	var merged *dto.Histogram
	var sum, count float64
	upper := map[float64]uint64{}
	var bounds []float64
	for _, m := range ms {
		h := m.GetHistogram()
		if h == nil {
			continue
		}
		merged = h // keep a shape reference
		sum += h.GetSampleSum()
		count += float64(h.GetSampleCount())
		for _, b := range h.GetBucket() {
			ub := b.GetUpperBound()
			if _, seen := upper[ub]; !seen {
				bounds = append(bounds, ub)
			}
			upper[ub] += b.GetCumulativeCount()
		}
	}
	if merged == nil {
		return emptyHistogram()
	}
	sort.Float64s(bounds)
	buckets := make([]bucketCount, 0, len(bounds)+1)
	var prev float64
	for _, ub := range bounds {
		cum := float64(upper[ub])
		buckets = append(buckets, bucketCount{
			Le: strconv.FormatFloat(ub, 'g', -1, 64), Count: cum - prev,
		})
		prev = cum
	}
	buckets = append(buckets, bucketCount{Le: "+Inf", Count: count - prev})
	return map[string]any{"buckets": buckets, "sum": sum, "count": count}
}

// offenderTopK is the number of rows returned per dimension.
const offenderTopK = 15

// countEntry is one ranked offender: a key and how many non-allow decisions it
// accounts for in the recent window.
type countEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// offenderIP carries the IP plus whatever GeoIP/ASN detail is configured.
// City and Subdivision need a City-class location_db and are absent for
// roughly a fifth of networks even then; AccuracyRadiusKM qualifies them as
// an area, not a precision (see intel.Info).
type offenderIP struct {
	IP               string `json:"ip"`
	Count            int    `json:"count"`
	Country          string `json:"country,omitempty"`
	City             string `json:"city,omitempty"`
	Subdivision      string `json:"subdivision,omitempty"`
	AccuracyRadiusKM uint16 `json:"accuracy_radius_km,omitempty"`
	ASN              uint32 `json:"asn,omitempty"`
	ASOrg            string `json:"as_org,omitempty"`
}

// handleOffenders reports the heaviest sources of non-allow decisions in the
// recent window: top IPs, reason categories, and request paths, plus a country
// rollup when GeoIP is loaded. It counts the in-process RecentDecisions ring
// exactly (bounded to 512 entries, microseconds per request); no Count-Min
// Sketch, no engine change, and nothing on the hot path. The window is the ring,
// so it covers challenged/denied traffic, not allows (which are never recorded).
func (s *AdminServer) handleOffenders(w http.ResponseWriter, _ *http.Request) {
	decisions := s.engine.RecentDecisions(0)

	byIP := map[string]int{}
	byReason := map[string]int{}
	byPath := map[string]int{}
	for _, d := range decisions {
		byIP[d.IP]++
		byReason[reasonCat(d.Reason)]++
		byPath[normalizePath(d.URI)]++
	}

	// GeoIP/ASN merge. nil Provider is lookup-safe, so this degrades to IP-only
	// when no databases load.
	intel := s.engine.Intel()
	topIPs := topKEntries(byIP, offenderTopK)
	ips := make([]offenderIP, 0, len(topIPs))
	for _, e := range topIPs {
		row := offenderIP{IP: e.Key, Count: e.Count}
		if intel != nil {
			if addr, err := netip.ParseAddr(e.Key); err == nil {
				info := intel.Lookup(addr)
				row.Country, row.ASN, row.ASOrg = info.Country, info.ASN, info.ASOrg
				row.City, row.Subdivision = info.City, info.Subdivision
				row.AccuracyRadiusKM = info.AccuracyRadiusKM
			}
		}
		ips = append(ips, row)
	}

	// The country rollup covers EVERY distinct IP in the window, not just the
	// top-K rows above: a botnet spreading 200 requests over 200 addresses
	// would otherwise show as a handful of hits while one noisy IP from
	// somewhere else outranked it, inverting where the traffic actually came
	// from. One lookup per distinct IP, bounded by the ring rather than by
	// request volume, so the cost is flat however large the attack gets.
	byCountry := map[string]int{}
	if intel != nil {
		for ip, n := range byIP {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if cc := intel.Lookup(addr).Country; cc != "" {
				byCountry[cc] += n
			}
		}
	}

	out := map[string]any{
		"window":  len(decisions), // ring depth this reflects
		"ips":     ips,
		"reasons": topKEntries(byReason, offenderTopK),
		"paths":   topKEntries(byPath, offenderTopK),
	}
	if len(byCountry) > 0 {
		// Every country, not a top-K slice. Countries are the one bounded
		// dimension here (at most one per distinct IP in the ring, and in
		// practice far fewer), unlike attacker-controlled reasons and paths.
		// Truncating them would silently drop part of the window from both the
		// map and the table, which is the same under-reporting the rollup above
		// exists to prevent.
		out["countries"] = topKEntries(byCountry, len(byCountry))
	}
	writeJSON(w, http.StatusOK, out)
}

// reasonCat collapses a decision reason to its leading token ("waf:dotfile" →
// "waf"), matching the bounded categories the guardian_decisions_total metric
// uses. Mirrors core.reasonCategory (unexported there).
func reasonCat(reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		return reason[:i]
	}
	return reason
}

// normalizePath strips the query string and caps length, so attacker-controlled
// URIs group cleanly and never bloat the response. The dashboard renders these
// via textContent only.
func normalizePath(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	if uri == "" {
		uri = "/"
	}
	const maxLen = 128
	if len(uri) > maxLen {
		uri = uri[:maxLen] + "…"
	}
	return uri
}

// topKEntries returns the k highest-count keys, descending, ties broken by key
// for a stable order across ticks.
func topKEntries(counts map[string]int, k int) []countEntry {
	entries := make([]countEntry, 0, len(counts))
	for key, n := range counts {
		entries = append(entries, countEntry{Key: key, Count: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	if len(entries) > k {
		entries = entries[:k]
	}
	return entries
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
	if strings.TrimSpace(s.prevDir) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no previous_key_dir configured; safe rotation requires an archive directory"})
		return
	}
	if err := mgr.Rotate(s.keyPath, s.prevDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log.Info("admin rotated signing key", "key", s.keyPath, "prev_dir", s.prevDir)
	writeJSON(w, http.StatusOK, map[string]any{"rotated": true})
}

// handleReload re-reads guardian.yaml and applies it without a restart, like
// SIGHUP. Validation failure keeps the running config and reports the error.
func (s *AdminServer) handleReload(w http.ResponseWriter, _ *http.Request) {
	if s.reload == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "reload not available"})
		return
	}
	if err := s.reload(); err != nil {
		s.log.Error("admin config reload failed, keeping running config", "err", err)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"reloaded": false, "error": err.Error()})
		return
	}
	s.log.Info("admin reloaded config")
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true})
}

// handleOffload reports the enforcement offload state: mirror mode, size and
// seed status plus every external sink's health, so an operator can see at a
// glance whether blocks are enforced in the kernel or in-daemon.
func (s *AdminServer) handleOffload(w http.ResponseWriter, _ *http.Request) {
	enf := s.engine.Enforcer()
	if enf == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, enf.Status())
}

// handleOffloadReconcile schedules an immediate authoritative store scan:
// drift repair after a manual nft flush or an out-of-band store edit, without
// waiting for the next reconcile tick. The scan itself runs asynchronously.
func (s *AdminServer) handleOffloadReconcile(w http.ResponseWriter, _ *http.Request) {
	enf := s.engine.Enforcer()
	if enf == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "enforcement offload not active"})
		return
	}
	enf.ForceReconcile()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "reconcile scheduled"})
}

// handleAttack reports the current attack posture: level, since, reason,
// whether it is operator-pinned, the current window signal rates, the active
// effects, and the configured thresholds.
func (s *AdminServer) handleAttack(w http.ResponseWriter, _ *http.Request) {
	d := s.engine.AttackDetector()
	if d == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	st := d.State()
	_, pinned := d.Pinned()
	writeJSON(w, http.StatusOK, map[string]any{
		"level":   st.Level.String(),
		"since":   st.Since,
		"reason":  st.Reason,
		"pinned":  pinned,
		"effects": map[string]any{"extra_bits": st.ExtraBits, "stateless": st.Stateless, "force_always": st.ForceAlways},
		"signals": d.CurrentSignals(),
	})
}

// handleAttackSet pins or unpins the posture. Body: {"level": "normal" |
// "elevated" | "attack" | "auto", "ttl": "10m"}. "auto" unpins; a pinned
// level wins in both directions, so pinning "normal" is a kill switch.
func (s *AdminServer) handleAttackSet(w http.ResponseWriter, r *http.Request) {
	d := s.engine.AttackDetector()
	if d == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "attack mode not active"})
		return
	}
	var body struct {
		Level string `json:"level"`
		TTL   string `json:"ttl"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request: " + err.Error()})
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request: trailing JSON value"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request: " + err.Error()})
		}
		return
	}
	level, auto, ok := attackmode.ParseLevel(body.Level)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "level must be normal, elevated, attack or auto"})
		return
	}
	if auto {
		d.Unpin()
		writeJSON(w, http.StatusOK, map[string]any{"pinned": false, "level": d.State().Level.String()})
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(body.TTL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ttl: " + err.Error()})
			return
		}
		if ttl <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ttl must be positive when supplied"})
			return
		}
		if ttl > core.MaxStateTTL {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ttl must be at most " + core.MaxStateTTL.String()})
			return
		}
	}
	d.Pin(level, ttl)
	s.log.Warn("attack posture pinned via admin API", "level", level.String(), "ttl", ttl)
	writeJSON(w, http.StatusOK, map[string]any{"pinned": true, "level": level.String()})
}

// handleIntel reports the state of the IP-intelligence sources: which GeoIP
// databases are loaded (type, build date) and every reputation feed's entry
// count, last refresh and last error.
func (s *AdminServer) handleIntel(w http.ResponseWriter, _ *http.Request) {
	p := s.engine.Intel()
	if p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "intel": p.Status()})
}

// handleIntelLookup answers "what do we know about this IP?": country, ASN
// and the reputation feeds it appears in, for testing geo rules and
// answering "why was this client denied".
func (s *AdminServer) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ip: " + err.Error()})
		return
	}
	p := s.engine.Intel()
	if p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "enabled": false})
		return
	}
	out := map[string]any{"ip": ip, "enabled": true, "info": p.Lookup(addr)}
	if hits := p.FeedHits(addr); len(hits) > 0 {
		out["feeds"] = hits
	}
	writeJSON(w, http.StatusOK, out)
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

// handleAsset serves a vendored dashboard asset (the chart libraries and the
// TopoJSON world atlas) same-origin. Unauthenticated like the dashboard shell
// (a <script src> or atlas fetch sends no bearer token) and safe: these are
// static libraries and map data, not request data.
//
// The URLs are fixed (dashboard.html references stable relative paths), so they
// must not be cached as immutable: a guardiand upgrade changes a blob, and a
// returning browser holding a year-old copy would pair a stale library with
// freshly loaded (no-store) dashboard JavaScript. Instead each revalidates
// against a content ETag, so a matching browser gets a cheap 304 and a changed
// blob is fetched fresh.
func (s *AdminServer) handleAsset(w http.ResponseWriter, r *http.Request) {
	a, ok := dashboardAssets[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	asset, err := web.FS.ReadFile(a.path)
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	if etag := s.assetETags[a.path]; etag != "" {
		w.Header().Set("ETag", etag)
		// Must revalidate every time; a stale cached copy is never served blind.
		w.Header().Set("Cache-Control", "no-cache")
		if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	_, _ = w.Write(asset)
}

// etagMatches reports whether the client's If-None-Match header lists our ETag.
// The header can be a comma-separated list or "*"; a weak "W/" prefix still
// matches the same content for this immutable-per-build asset.
func etagMatches(header, etag string) bool {
	for candidate := range strings.SplitSeq(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

// handleConfig returns a redacted view of the loaded per-domain config, so an
// operator can confirm what is active without shell access to the box.
func (s *AdminServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	type domainView struct {
		PoWEnabled bool    `json:"pow_enabled"`
		PoWMode    string  `json:"pow_mode"`
		PoWBase    float64 `json:"pow_base_difficulty"`
		PoWMax     float64 `json:"pow_max_difficulty"`
		Keywords   bool    `json:"waf_keywords"`
		// RulesFile and DisabledRuleIDs expose the effective signature-rule
		// selection together, so an operator can see which file a scope uses
		// and which rule IDs it excludes from it without shell access.
		RulesFile       string   `json:"waf_rules_file,omitempty"`
		DisabledRuleIDs []string `json:"waf_disabled_rule_ids,omitempty"`
		Anomaly         bool     `json:"waf_anomaly"`
		Honeypot        bool     `json:"waf_honeypot"`
		IPBehaviour     bool     `json:"waf_ip_behaviour"`
		Geo             bool     `json:"geo"`
		Reputation      bool     `json:"reputation"`
		// Paths are the domain's per-path overlays keyed by their configured
		// path. JSON map order is alphabetical; lookup precedence is by key
		// specificity (longest bare key, exact before prefix).
		Paths map[string]domainView `json:"paths,omitempty"`
	}
	base := func(dc *core.DomainConfig) domainView {
		return domainView{
			PoWEnabled: dc.PoW.Enabled, PoWMode: dc.PoW.Mode,
			PoWBase: dc.PoW.BaseDifficulty, PoWMax: dc.PoW.MaxDifficulty,
			Keywords: dc.WAF.Keywords.Enabled, RulesFile: dc.WAF.Keywords.RulesFile,
			DisabledRuleIDs: dc.WAF.Keywords.DisabledRuleIDs, Anomaly: dc.WAF.Anomaly.Enabled,
			Honeypot: dc.WAF.Honeypot.Enabled, IPBehaviour: dc.WAF.IPBehaviour.Enabled,
			Geo: dc.Geo.Enabled, Reputation: dc.Reputation.Enabled,
		}
	}
	view := func(dc *core.DomainConfig) domainView {
		v := base(dc)
		if overrides := dc.PathOverrideViews(); len(overrides) > 0 {
			v.Paths = make(map[string]domainView, len(overrides))
			for _, o := range overrides {
				v.Paths[o.Path] = base(o.Config)
			}
		}
		return v
	}
	cfg := s.engine.Config()
	out := map[string]any{
		"store":    cfg.Store.Backend,
		"defaults": view(&cfg.Defaults),
		"domains":  map[string]domainView{},
	}
	for host, dc := range cfg.DomainViews() {
		out["domains"].(map[string]domainView)[host] = view(dc)
	}
	writeJSON(w, http.StatusOK, out)
}
