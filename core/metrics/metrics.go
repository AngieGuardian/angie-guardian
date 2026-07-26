// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics holds the Prometheus instrumentation. Everything lives on a
// private registry (not the global default) so the daemon controls exactly
// what is exposed, and label cardinality is kept bounded — action, reason
// category, domain and store op are all small closed sets.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics is the set of collectors Guardian records into. A nil *Metrics is
// safe to call every method on (no-op), so instrumentation can be disabled
// without nil-checks at every call site.
type Metrics struct {
	reg *prometheus.Registry
	// backend labels every store series with the configured backend. It is
	// constant for the process (store.backend is startup-only), so it costs one
	// label value per target rather than multiplying series.
	backend string

	decisions           *prometheus.CounterVec // by action, reason_category, domain
	challenge           *prometheus.CounterVec // by outcome: issued|issued_stateless|issued_stateless_fallback|escalated|farm_detected|subresource_refused|frame_unscored|solved|failed|spent_cas_failed
	solveTime           prometheus.Histogram   // client-reported solve time, seconds
	anomalyScore        *prometheus.HistogramVec
	anomalyBaselineMiss *prometheus.CounterVec
	anomalySelection    *prometheus.CounterVec
	anomalyModelAge     *prometheus.GaugeVec   // by model path (config-bounded)
	blocksPlaced        *prometheus.CounterVec // by reason_category
	botVerify           *prometheus.CounterVec // by bot (config-bounded), result
	storeOps            *prometheus.CounterVec // by backend, op, status
	storeLatency        *prometheus.HistogramVec
	storeUp             *prometheus.GaugeVec   // by backend; 1 = reachable, 0 = failing open
	storeProbe          *prometheus.CounterVec // by backend, status
	evalLatency         prometheus.Histogram
	feedEntries         *prometheus.GaugeVec   // by feed
	feedRefresh         *prometheus.CounterVec // by feed, status

	blockLookups     *prometheus.CounterVec // by source (mirror|store), outcome (hit|miss)
	offloadEntries   *prometheus.GaugeVec   // by sink (mirror|nftables)
	offloadOps       *prometheus.CounterVec // by sink, op (add|remove), status (ok|error|dropped)
	offloadReconcile *prometheus.CounterVec // by status (ok|error)
	offloadSkipped   *prometheus.CounterVec // by reason (incomplete_snapshot|concurrent_event)
	offloadHealthy   *prometheus.GaugeVec   // by sink; 1 = enforcing, 0 = degraded to in-daemon

	attackMode        prometheus.Gauge       // 0 normal, 1 elevated, 2 attack
	attackExtraBits   prometheus.Gauge       // active fleet difficulty raise in bits
	attackTransitions *prometheus.CounterVec // by to, reason
	attackSignal      *prometheus.GaugeVec   // by signal; current window value
	shed              *prometheus.CounterVec // load-shed decisions by outcome
	unproxiedRejects  prometheus.Counter     // require_proxied gate rejections
	storeClockSkew    *prometheus.GaugeVec   // store server clock minus local, by backend
}

// New builds the collector set for a process using the named store backend.
// Every store series carries it, so a fleet scrape can group by backend
// without joining against another metric.
func New(backend string) *Metrics {
	reg := prometheus.NewRegistry()
	f := promauto.With(reg)

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return &Metrics{
		reg:     reg,
		backend: backend,
		decisions: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "decisions_total",
			Help: "Pipeline decisions by action, reason category and domain.",
		}, []string{"action", "reason", "domain"}),
		challenge: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "challenges_total",
			Help: "Proof-of-work challenge lifecycle events.",
		}, []string{"outcome"}),
		solveTime: f.NewHistogram(prometheus.HistogramOpts{
			Namespace: "guardian", Name: "challenge_solve_seconds",
			Help:    "Client-reported proof-of-work solve time.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
		}),
		anomalyScore: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "guardian", Name: "anomaly_score",
			Help:    "Distribution of anomaly scores by domain.",
			Buckets: prometheus.LinearBuckets(0, 0.1, 11),
		}, []string{"domain"}),
		anomalyBaselineMiss: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "anomaly_baseline_misses_total",
			Help: "Anomaly scoring attempts without a domain baseline.",
		}, []string{"domain"}),
		anomalySelection: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "anomaly_baseline_selections_total",
			Help: "Selected anomaly baseline level (exact|route|method|domain|missing).",
		}, []string{"domain", "level"}),
		anomalyModelAge: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "anomaly_model_trained_timestamp_seconds",
			Help: "Unix time the loaded anomaly model artifact was trained; a stalling value means retraining or promotion is silently failing.",
		}, []string{"model"}),
		blocksPlaced: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "blocks_placed_total",
			Help: "Behavioural IP blocks placed, by reason category.",
		}, []string{"reason"}),
		botVerify: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "bot_verifications_total",
			Help: "Verified-bot checks by bot name and result (verified|spoof|error).",
		}, []string{"bot", "result"}),
		storeOps: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "store_ops_total",
			Help: "Store operations by backend, op and status (ok|error).",
		}, []string{"backend", "op", "status"}),
		storeLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "guardian", Name: "store_op_seconds",
			Help:    "Store operation latency by backend and op.",
			Buckets: []float64{50e-6, 100e-6, 250e-6, 500e-6, 1e-3, 2.5e-3, 5e-3, 10e-3, 50e-3},
		}, []string{"backend", "op"}),
		storeUp: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "store_up",
			Help: "Whether the store answered its last health probe (1) or Guardian is failing open (0).",
		}, []string{"backend"}),
		storeClockSkew: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "store_clock_skew_seconds",
			Help: "Store server clock minus local clock, probed on remote backends; skew beyond a counter window silently voids deadline-based counter flushes.",
		}, []string{"backend"}),
		storeProbe: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "store_probe_total",
			Help: "Completed store health probes by backend and status (ok|error).",
		}, []string{"backend", "status"}),
		evalLatency: f.NewHistogram(prometheus.HistogramOpts{
			Namespace: "guardian", Name: "evaluate_seconds",
			Help:    "End-to-end Evaluate() latency (the auth hot path).",
			Buckets: []float64{5e-6, 10e-6, 25e-6, 50e-6, 100e-6, 250e-6, 500e-6, 1e-3, 5e-3},
		}),
		feedEntries: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "feed_entries",
			Help: "Loaded entries per reputation feed.",
		}, []string{"feed"}),
		feedRefresh: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "feed_refresh_total",
			Help: "Reputation feed refresh attempts by feed and status (ok|error).",
		}, []string{"feed", "status"}),
		blockLookups: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "block_lookups_total",
			Help: "Behavioural block lookups by source (mirror|store) and outcome (hit|miss).",
		}, []string{"source", "outcome"}),
		offloadEntries: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "offload_entries",
			Help: "Active block entries held per enforcement sink.",
		}, []string{"sink"}),
		offloadOps: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "offload_ops_total",
			Help: "Enforcement offload operations by sink, op (add|remove) and status (ok|error|dropped).",
		}, []string{"sink", "op", "status"}),
		offloadReconcile: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "offload_reconcile_total",
			Help: "Block-set reconciliation scans by status (ok|error).",
		}, []string{"status"}),
		offloadSkipped: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "offload_reconcile_skipped_total",
			Help: "External-sink replace-all reconciles skipped because the store snapshot was incomplete or a newer event made it stale.",
		}, []string{"reason"}),
		offloadHealthy: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "offload_healthy",
			Help: "Whether an enforcement sink is healthy (1) or degraded to in-daemon enforcement (0).",
		}, []string{"sink"}),
		attackMode: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "attack_mode",
			Help: "Global attack posture: 0 normal, 1 elevated, 2 attack.",
		}),
		attackExtraBits: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "attack_extra_bits",
			Help: "Active fleet-wide PoW difficulty raise, in leading-zero bits.",
		}),
		attackTransitions: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "attack_mode_transitions_total",
			Help: "Attack posture transitions by target level and reason.",
		}, []string{"to", "reason"}),
		attackSignal: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "attack_mode_signal",
			Help: "Current window value per attack-mode signal.",
		}, []string{"signal"}),
		shed: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "guardian", Name: "shed_total",
			Help: "Load-shed decisions under saturation by outcome (pass_token|shed).",
		}, []string{"outcome"}),
		unproxiedRejects: f.NewCounter(prometheus.CounterOpts{
			Namespace: "guardian", Name: "unproxied_rejects_total",
			Help: "Guard requests rejected by require_proxied for missing X-Guardian-* headers; nonzero means something reaches the guard port without going through Angie.",
		}),
	}
}

// Registry exposes the private registry for the /metrics handler.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

func (m *Metrics) Decision(action, reason, domain string) {
	if m == nil {
		return
	}
	m.decisions.WithLabelValues(action, reason, domain).Inc()
}

func (m *Metrics) Challenge(outcome string) {
	if m == nil {
		return
	}
	m.challenge.WithLabelValues(outcome).Inc()
}

func (m *Metrics) SolveTime(seconds float64) {
	if m == nil || seconds <= 0 {
		return
	}
	m.solveTime.Observe(seconds)
}

func (m *Metrics) AnomalyScore(domain string, score float64) {
	if m == nil {
		return
	}
	m.anomalyScore.WithLabelValues(domain).Observe(score)
}

func (m *Metrics) AnomalyBaseline(domain, level string) {
	if m == nil {
		return
	}
	m.anomalySelection.WithLabelValues(domain, level).Inc()
	if level == "missing" {
		m.anomalyBaselineMiss.WithLabelValues(domain).Inc()
	}
}

// AnomalyModelTrainedAt publishes when a loaded model artifact was trained.
// The model label is the operator-configured artifact path, so cardinality is
// bounded by the config, never by traffic.
func (m *Metrics) AnomalyModelTrainedAt(model string, trainedAt int64) {
	if m == nil {
		return
	}
	m.anomalyModelAge.WithLabelValues(model).Set(float64(trainedAt))
}

// AnomalyModelRemoved drops the trained-at series of a model artifact a
// reload removed from the config. Left published, the gauge would freeze and
// eventually fire the staleness alert for a model this process no longer
// loads.
func (m *Metrics) AnomalyModelRemoved(model string) {
	if m == nil {
		return
	}
	m.anomalyModelAge.DeleteLabelValues(model)
}

func (m *Metrics) BlockPlaced(reason string) {
	if m == nil {
		return
	}
	m.blocksPlaced.WithLabelValues(reason).Inc()
}

func (m *Metrics) BotVerification(bot, result string) {
	if m == nil {
		return
	}
	m.botVerify.WithLabelValues(bot, result).Inc()
}

func (m *Metrics) StoreOp(op string, seconds float64, err error) {
	if m == nil {
		return
	}
	status := "ok"
	if err != nil {
		status = "error"
	}
	m.storeOps.WithLabelValues(m.backend, op, status).Inc()
	m.storeLatency.WithLabelValues(m.backend, op).Observe(seconds)
}

// StoreProbe records one completed store health probe: the gauge follows the
// result and the counter separates ok from error. Together they answer both
// "is it down right now" and "how flaky has it been".
func (m *Metrics) StoreProbe(backend string, up bool) {
	if m == nil {
		return
	}
	status, value := "error", 0.0
	if up {
		status, value = "ok", 1.0
	}
	m.storeUp.WithLabelValues(backend).Set(value)
	m.storeProbe.WithLabelValues(backend, status).Inc()
}

// StoreProbeStale drives the gauge to 0 when no probe completed in time (a
// wedged probe loop). No probe finished, so no probe counter moves: pretending
// an error was observed would misreport the failure rate.
func (m *Metrics) StoreProbeStale(backend string) {
	if m == nil {
		return
	}
	m.storeUp.WithLabelValues(backend).Set(0)
}

// StoreClockSkew publishes the store server clock offset (server minus local)
// measured by the health probe on remote backends.
func (m *Metrics) StoreClockSkew(backend string, seconds float64) {
	if m == nil {
		return
	}
	m.storeClockSkew.WithLabelValues(backend).Set(seconds)
}

// FeedRefresh records one reputation feed refresh attempt and the resulting
// entry count. Feed names come from config, so the label set stays bounded.
func (m *Metrics) FeedRefresh(feed string, entries int, failed bool) {
	if m == nil {
		return
	}
	status := "ok"
	if failed {
		status = "error"
	}
	m.feedRefresh.WithLabelValues(feed, status).Inc()
	m.feedEntries.WithLabelValues(feed).Set(float64(entries))
}

func (m *Metrics) EvaluateLatency(seconds float64) {
	if m == nil {
		return
	}
	m.evalLatency.Observe(seconds)
}

// BlockLookup records one behavioural block lookup on the auth hot path.
// Both label sets are closed: source is mirror|store, outcome is hit|miss.
func (m *Metrics) BlockLookup(source, outcome string) {
	if m == nil {
		return
	}
	m.blockLookups.WithLabelValues(source, outcome).Inc()
}

func (m *Metrics) OffloadEntries(sink string, n int) {
	if m == nil {
		return
	}
	m.offloadEntries.WithLabelValues(sink).Set(float64(n))
}

func (m *Metrics) OffloadOp(sink, op, status string) {
	if m == nil {
		return
	}
	m.offloadOps.WithLabelValues(sink, op, status).Inc()
}

func (m *Metrics) OffloadReconcile(ok bool) {
	if m == nil {
		return
	}
	status := "ok"
	if !ok {
		status = "error"
	}
	m.offloadReconcile.WithLabelValues(status).Inc()
}

// OffloadReconcileSkipped records why a successful mirror scan could not be
// used for destructive replace-all repair of external enforcement sinks.
func (m *Metrics) OffloadReconcileSkipped(reason string) {
	if m == nil {
		return
	}
	m.offloadSkipped.WithLabelValues(reason).Inc()
}

func (m *Metrics) OffloadHealthy(sink string, healthy bool) {
	if m == nil {
		return
	}
	v := 0.0
	if healthy {
		v = 1.0
	}
	m.offloadHealthy.WithLabelValues(sink).Set(v)
}

// AttackMode records the current posture level and the active difficulty raise.
func (m *Metrics) AttackMode(level, extraBits int) {
	if m == nil {
		return
	}
	m.attackMode.Set(float64(level))
	m.attackExtraBits.Set(float64(extraBits))
}

// AttackTransition counts one posture transition. reason is a bounded set.
func (m *Metrics) AttackTransition(to, reason string) {
	if m == nil {
		return
	}
	m.attackTransitions.WithLabelValues(to, reason).Inc()
}

// AttackSignal sets one signal's current window value (bounded label set).
func (m *Metrics) AttackSignal(signal string, value float64) {
	if m == nil {
		return
	}
	m.attackSignal.WithLabelValues(signal).Set(value)
}

// Shed counts one load-shed decision (outcome pass_token|shed).
func (m *Metrics) Shed(outcome string) {
	if m == nil {
		return
	}
	m.shed.WithLabelValues(outcome).Inc()
}

// UnproxiedReject counts one guard request rejected by the require_proxied
// gate (no X-Guardian-* headers, so it did not come through the Angie glue).
func (m *Metrics) UnproxiedReject() {
	if m == nil {
		return
	}
	m.unproxiedRejects.Inc()
}
