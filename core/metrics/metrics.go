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

	decisions    *prometheus.CounterVec // by action, reason_category, domain
	challenge    *prometheus.CounterVec // by outcome: issued|escalated|solved|failed
	solveTime    prometheus.Histogram   // client-reported solve time, seconds
	anomalyScore *prometheus.HistogramVec
	blocksPlaced *prometheus.CounterVec // by reason_category
	botVerify    *prometheus.CounterVec // by bot (config-bounded), result
	storeOps     *prometheus.CounterVec // by op, status
	storeLatency *prometheus.HistogramVec
	evalLatency  prometheus.Histogram
	feedEntries  *prometheus.GaugeVec   // by feed
	feedRefresh  *prometheus.CounterVec // by feed, status

	blockLookups     *prometheus.CounterVec // by source (mirror|store), outcome (hit|miss)
	offloadEntries   *prometheus.GaugeVec   // by sink (mirror|nftables)
	offloadOps       *prometheus.CounterVec // by sink, op (add|remove), status (ok|error|dropped)
	offloadReconcile *prometheus.CounterVec // by status (ok|error)
	offloadHealthy   *prometheus.GaugeVec   // by sink; 1 = enforcing, 0 = degraded to in-daemon
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	f := promauto.With(reg)

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return &Metrics{
		reg: reg,
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
			Help: "Store operations by op and status (ok|error).",
		}, []string{"op", "status"}),
		storeLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "guardian", Name: "store_op_seconds",
			Help:    "Store operation latency by op.",
			Buckets: []float64{50e-6, 100e-6, 250e-6, 500e-6, 1e-3, 2.5e-3, 5e-3, 10e-3, 50e-3},
		}, []string{"op"}),
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
		offloadHealthy: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "guardian", Name: "offload_healthy",
			Help: "Whether an enforcement sink is healthy (1) or degraded to in-daemon enforcement (0).",
		}, []string{"sink"}),
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
	m.storeOps.WithLabelValues(op, status).Inc()
	m.storeLatency.WithLabelValues(op).Observe(seconds)
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
