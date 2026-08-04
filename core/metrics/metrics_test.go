// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"errors"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// labelsOf returns a gathered metric's labels as a map, so a test can pin the
// exact label set rather than only the values.
func labelsOf(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, l := range m.GetLabel() {
		out[l.GetName()] = l.GetValue()
	}
	return out
}

// family returns the named metric family from a fresh gather, or fails.
func family(t *testing.T, m *Metrics, name string) *dto.MetricFamily {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() == name {
			return mf
		}
	}
	t.Fatalf("metric family %q not registered", name)
	return nil
}

// series returns the single sample of a family carrying the given labels.
func series(t *testing.T, mf *dto.MetricFamily, want map[string]string) *dto.Metric {
	t.Helper()
	for _, m := range mf.GetMetric() {
		got := labelsOf(m)
		if len(got) != len(want) {
			continue
		}
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m
		}
	}
	t.Fatalf("%s has no series with labels %v", mf.GetName(), want)
	return nil
}

// TestStoreProbeSeriesIdentity pins the names and label sets the shipped alert
// rules, the Grafana panels and docs/reference/metrics.md all reference. A
// rename or an extra label here silently breaks every one of them.
func TestStoreProbeSeriesIdentity(t *testing.T) {
	m := New("memory")
	m.StoreProbe("pebble", true)

	up := family(t, m, "guardian_store_up")
	if up.GetType() != dto.MetricType_GAUGE {
		t.Errorf("guardian_store_up type = %v, want gauge", up.GetType())
	}
	if got := labelsOf(up.GetMetric()[0]); len(got) != 1 || got["backend"] != "pebble" {
		t.Errorf("guardian_store_up labels = %v, want exactly {backend=pebble}", got)
	}

	probe := family(t, m, "guardian_store_probe_total")
	if probe.GetType() != dto.MetricType_COUNTER {
		t.Errorf("guardian_store_probe_total type = %v, want counter", probe.GetType())
	}
	got := labelsOf(probe.GetMetric()[0])
	if len(got) != 2 || got["backend"] != "pebble" || got["status"] != "ok" {
		t.Errorf("guardian_store_probe_total labels = %v, want exactly {backend=pebble,status=ok}", got)
	}
}

func TestRuleMatchBlockMetricLabel(t *testing.T) {
	m := New("memory")
	m.BlockPlaced("rule_match")
	mf := family(t, m, "guardian_blocks_placed_total")
	got := series(t, mf, map[string]string{"reason": "rule_match"})
	if got.GetCounter().GetValue() != 1 {
		t.Errorf("rule_match block counter = %v, want 1", got.GetCounter().GetValue())
	}
}

// TestStoreSeriesCarryTheBackend: every store series is labelled with the
// backend, so a mixed fleet (or a deployment mid-migration between backends)
// can group by it directly instead of joining against guardian_store_up. The
// value is constant for the process, so it adds one label value per target
// rather than multiplying series.
func TestStoreSeriesCarryTheBackend(t *testing.T) {
	m := New("pebble")
	m.StoreOp("get", 0.001, nil)

	got := labelsOf(family(t, m, "guardian_store_ops_total").GetMetric()[0])
	if len(got) != 3 || got["backend"] != "pebble" || got["op"] != "get" || got["status"] != "ok" {
		t.Errorf("guardian_store_ops_total labels = %v, want exactly {backend,op,status}", got)
	}
	lat := labelsOf(family(t, m, "guardian_store_op_seconds").GetMetric()[0])
	if len(lat) != 2 || lat["backend"] != "pebble" || lat["op"] != "get" {
		t.Errorf("guardian_store_op_seconds labels = %v, want exactly {backend,op}", lat)
	}
}

// TestStoreOpBackendComesFromTheProcess: the op series take the backend the
// process was constructed with rather than a per-call argument, so two series
// on one target can never disagree about which store they describe.
func TestStoreOpBackendComesFromTheProcess(t *testing.T) {
	m := New("redis")
	m.StoreOp("set", 0.002, nil)
	m.StoreOp("cas", 0.003, errors.New("boom"))

	metrics := family(t, m, "guardian_store_ops_total").GetMetric()
	if len(metrics) != 2 {
		t.Fatalf("got %d op series, want 2", len(metrics))
	}
	for _, mm := range metrics {
		if got := labelsOf(mm)["backend"]; got != "redis" {
			t.Errorf("backend = %q on %v, want redis on every op series", got, labelsOf(mm))
		}
	}
}

// TestStoreUpGaugeTransitions walks the sequence an operator actually sees: a
// healthy start, an outage, and recovery without a daemon restart.
func TestStoreUpGaugeTransitions(t *testing.T) {
	m := New("memory")
	backend := map[string]string{"backend": "redis"}

	for _, step := range []struct {
		up   bool
		want float64
	}{{true, 1}, {false, 0}, {true, 1}} {
		m.StoreProbe("redis", step.up)
		gauge := series(t, family(t, m, "guardian_store_up"), backend)
		if got := gauge.GetGauge().GetValue(); got != step.want {
			t.Fatalf("after StoreProbe(up=%v) gauge = %v, want %v", step.up, got, step.want)
		}
	}
}

// TestStoreProbeCountersAreIndependent: the ok and error counters must move
// separately, since the shipped alert rule divides one by their sum.
func TestStoreProbeCountersAreIndependent(t *testing.T) {
	m := New("memory")
	m.StoreProbe("buntdb", true)
	m.StoreProbe("buntdb", false)
	m.StoreProbe("buntdb", false)

	mf := family(t, m, "guardian_store_probe_total")
	ok := series(t, mf, map[string]string{"backend": "buntdb", "status": "ok"})
	bad := series(t, mf, map[string]string{"backend": "buntdb", "status": "error"})
	if got := ok.GetCounter().GetValue(); got != 1 {
		t.Errorf("ok counter = %v, want 1", got)
	}
	if got := bad.GetCounter().GetValue(); got != 2 {
		t.Errorf("error counter = %v, want 2", got)
	}
}

// TestStoreProbeStaleOnlyMovesTheGauge: a wedged probe loop means no probe
// completed. Driving the gauge to 0 is right; inventing an error observation
// would misreport the probe failure rate the alert rule is built on.
func TestStoreProbeStaleOnlyMovesTheGauge(t *testing.T) {
	m := New("memory")
	m.StoreProbe("pebble", true)
	m.StoreProbeStale("pebble")

	gauge := series(t, family(t, m, "guardian_store_up"), map[string]string{"backend": "pebble"})
	if got := gauge.GetGauge().GetValue(); got != 0 {
		t.Errorf("guardian_store_up = %v after a stale probe, want 0", got)
	}
	mf := family(t, m, "guardian_store_probe_total")
	if n := len(mf.GetMetric()); n != 1 {
		t.Fatalf("probe counter has %d series after one probe plus one stale event, want 1", n)
	}
	if got := series(t, mf, map[string]string{"backend": "pebble", "status": "ok"}).GetCounter().GetValue(); got != 1 {
		t.Errorf("ok counter = %v, want it untouched at 1", got)
	}
}

// TestStoreProbeIsBackendScoped: a fleet query groups by backend, so two
// backends must never share a series.
func TestStoreProbeIsBackendScoped(t *testing.T) {
	m := New("memory")
	m.StoreProbe("redis", false)
	m.StoreProbe("pebble", true)

	mf := family(t, m, "guardian_store_up")
	if got := series(t, mf, map[string]string{"backend": "redis"}).GetGauge().GetValue(); got != 0 {
		t.Errorf("redis gauge = %v, want 0", got)
	}
	if got := series(t, mf, map[string]string{"backend": "pebble"}).GetGauge().GetValue(); got != 1 {
		t.Errorf("pebble gauge = %v, want 1", got)
	}
}

// TestNilMetricsProbeIsSafe: every recorder method is a no-op on a nil
// *Metrics so instrumentation can be disabled without nil-checks at the call
// site, and health.Checker holds a Recorder it never guards.
func TestNilMetricsProbeIsSafe(t *testing.T) {
	var m *Metrics
	m.StoreProbe("memory", true)
	m.StoreProbeStale("memory")
}
