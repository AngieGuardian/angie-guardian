// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/attackmode"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/health"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/store"
	"github.com/prometheus/client_golang/prometheus"
)

// probeErrorText is the raw backend error the checker will hold. Readiness must
// never leak it: real ones carry addresses, DSN credentials and paths.
const probeErrorText = "dial tcp 127.0.0.1:6379: connection refused"

// brokenStore fails Get on demand, which is how a test drives the probe from
// healthy to down and back without a real backend.
type brokenStore struct {
	store.Store
	broken atomic.Bool
}

func (b *brokenStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if b.broken.Load() {
		return nil, false, errors.New(probeErrorText)
	}
	return b.Store.Get(ctx, key)
}

// gatherCounter is an unchecked collector that counts registry gathers:
// Prometheus calls Collect exactly once per registered collector per Gather.
type gatherCounter struct{ n atomic.Int64 }

func (g *gatherCounter) Describe(chan<- *prometheus.Desc) {}
func (g *gatherCounter) Collect(chan<- prometheus.Metric) { g.n.Add(1) }

type healthFixture struct {
	ts      *httptest.Server
	checker *health.Checker
	store   *brokenStore
	metrics *metrics.Metrics
	engine  *core.Engine
}

// healthServer builds an admin server wired the way guardiand runs it: the
// checker probes the raw store while the engine uses the instrumented one.
// wire=false models the deployment fault where no checker was attached.
func healthServer(t *testing.T, wire bool) *healthFixture {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	raw := &brokenStore{Store: store.NewMemory()}
	t.Cleanup(func() { raw.Close() })

	m := metrics.New("memory")
	engine, err := core.NewEngine(cfg, store.Instrument(raw, m), nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	engine.SetMetrics(m)
	// guardiand always wires an enforcer (the mirror is unconditional), and the
	// health rollup reports its status, so the fixture matches production.
	enf := enforce.New(cfg.EnforceConfig(), store.Instrument(raw, m), m, slog.Default())
	t.Cleanup(func() { enf.Close() })
	engine.SetEnforcer(enf)

	var hc *health.Checker
	if wire {
		hc = health.New(raw, "memory", m, slog.Default())
		t.Cleanup(func() { hc.Close() })
		engine.SetHealth(hc)
	}

	ts := httptest.NewServer(NewAdminServer(engine, cfg, m, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)
	return &healthFixture{ts: ts, checker: hc, store: raw, metrics: m, engine: engine}
}

// readyz calls the open readiness endpoint with no credentials, exactly how an
// orchestrator or load balancer probes it.
func readyz(t *testing.T, ts *httptest.Server) (*http.Response, map[string]any, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /readyz body %q: %v", raw, err)
	}
	return resp, body, string(raw)
}

// TestReadyzHealthy: readiness is open like liveness (a scraper or a load
// balancer needs no secret), never cached, and reports the store round trip.
func TestReadyzHealthy(t *testing.T) {
	f := healthServer(t, true)
	f.checker.ProbeForTest(context.Background())

	resp, body, raw := readyz(t, f.ts)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, raw)
	}
	if body["ready"] != true {
		t.Errorf("ready = %v, want true: %s", body["ready"], raw)
	}
	if _, has := body["reason"]; has {
		t.Errorf("a ready response carries a reason: %s", raw)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	st, ok := body["store"].(map[string]any)
	if !ok {
		t.Fatalf("no store block: %s", raw)
	}
	if st["up"] != true || st["probed"] != true {
		t.Errorf("store block = %v, want probed and up", st)
	}
	if st["backend"] != "memory" {
		t.Errorf("backend = %v, want memory", st["backend"])
	}
}

// TestReadyzNotReadyStates: every way store readiness fails maps to a 503 with
// one stable coarse reason, and none of them leaks the raw backend error. An
// unwired checker is a deployment fault and must report unavailable rather than
// silently collapsing readiness into a second liveness endpoint.
func TestReadyzNotReadyStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		drive  func(t *testing.T, f *healthFixture)
		wire   bool
		reason string
	}{
		{"never probed", func(*testing.T, *healthFixture) {}, true, "store probe pending"},
		{"no checker wired", func(*testing.T, *healthFixture) {}, false, "store probe unavailable"},
		{"probe failed", func(_ *testing.T, f *healthFixture) {
			f.store.broken.Store(true)
			f.checker.ProbeForTest(context.Background())
		}, true, "store probe failed"},
		{"snapshot stale", func(_ *testing.T, f *healthFixture) {
			f.checker.ProbeForTest(context.Background())
			f.checker.MarkStaleForTest()
		}, true, "store probe stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := healthServer(t, tc.wire)
			tc.drive(t, f)

			resp, body, raw := readyz(t, f.ts)
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503: %s", resp.StatusCode, raw)
			}
			if body["ready"] != false {
				t.Errorf("ready = %v, want false: %s", body["ready"], raw)
			}
			if body["reason"] != tc.reason {
				t.Errorf("reason = %v, want %q", body["reason"], tc.reason)
			}
			if strings.Contains(raw, probeErrorText) {
				t.Errorf("the unauthenticated readiness body leaked the raw store error: %s", raw)
			}
			if strings.Contains(raw, `"error"`) {
				t.Errorf("readiness body carries an error field: %s", raw)
			}
		})
	}
}

// TestReadyzIgnoresAttackPosture: an active attack is not a readiness failure.
// Guardian is protecting traffic; pulling the instance out of a load balancer
// during exactly that incident would be the wrong reflex.
func TestReadyzIgnoresAttackPosture(t *testing.T) {
	f := healthServer(t, true)
	f.checker.ProbeForTest(context.Background())

	d := attackmode.New(attackmode.Config{Enabled: true}, nil, slog.Default())
	d.Pin(attackmode.Attack, time.Minute)
	f.engine.SetAttackDetector(d)

	resp, body, raw := readyz(t, f.ts)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 under attack posture: %s", resp.StatusCode, raw)
	}
	attack, ok := body["attack"].(map[string]any)
	if !ok || attack["level"] != "attack" {
		t.Errorf("attack block = %v, want the level reported for context", body["attack"])
	}
	// Only the level: sink last_error and detector internals stay authenticated.
	if len(attack) != 1 {
		t.Errorf("attack block = %v, want the level alone", attack)
	}
}

// TestLivenessIgnoresStore: /healthz must not follow the store. Guardian fails
// open, so a store outage leaves it serving; killing the container (Compose
// healthcheck) or flapping the unit would turn a degradation into an outage.
func TestLivenessIgnoresStore(t *testing.T) {
	f := healthServer(t, true)
	f.store.broken.Store(true)
	f.checker.ProbeForTest(context.Background())

	if _, body, raw := readyz(t, f.ts); body["ready"] != false {
		t.Fatalf("precondition: readiness did not fail: %s", raw)
	}
	resp, err := http.Get(f.ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d with the store down, want 200", resp.StatusCode)
	}
}

// TestAdminStatsHealth: the authenticated rollup is where the detail lives, so
// the dashboard can say which component is degraded and why.
func TestAdminStatsHealth(t *testing.T) {
	f := healthServer(t, true)
	f.store.broken.Store(true)
	f.checker.ProbeForTest(context.Background())
	f.metrics.Shed("shed")
	f.metrics.Challenge("issued_stateless_fallback")
	f.metrics.Challenge("spent_cas_failed")
	f.metrics.StoreOp("get", 0.001, nil)
	f.metrics.StoreOp("set", 0.002, errors.New("boom"))

	stats := decodeJSON(t, adminReq(t, f.ts, "GET", "/admin/stats", adminToken, ""))
	h, ok := stats["health"].(map[string]any)
	if !ok {
		t.Fatalf("stats has no health object: %v", stats)
	}

	st, ok := h["store"].(map[string]any)
	if !ok {
		t.Fatalf("health has no store block: %v", h)
	}
	if st["up"] != false || st["probed"] != true {
		t.Errorf("store block = %v, want probed and down", st)
	}
	// The raw error is confined to this token-guarded surface (and the log).
	if got, _ := st["error"].(string); !strings.Contains(got, probeErrorText) {
		t.Errorf("store error = %q, want the raw backend error", got)
	}

	ops, ok := h["store_ops"].(map[string]any)
	if !ok || ops["total"].(float64) < 2 || ops["errors"].(float64) != 1 {
		t.Errorf("store_ops = %v, want the lifetime totals with one error", h["store_ops"])
	}
	shed, ok := h["shed"].(map[string]any)
	if !ok || shed["shed"] != 1.0 || shed["pass_token"] != 0.0 {
		t.Errorf("shed = %v, want {shed:1, pass_token:0}", h["shed"])
	}
	fb, ok := h["pow_fallback"].(map[string]any)
	if !ok || fb["issued_stateless_fallback"] != 1.0 || fb["spent_cas_failed"] != 1.0 {
		t.Errorf("pow_fallback = %v, want both counters at 1", h["pow_fallback"])
	}
	if _, ok := h["enforcement"]; !ok {
		t.Error("health has no enforcement block")
	}
}

// TestAdminStatsHealthSignals: current-window ratios come from the detector and
// the thresholds from the live config, so the dashboard compares like with
// like instead of deriving a fake "current" ratio from lifetime totals.
func TestAdminStatsHealthSignals(t *testing.T) {
	f := healthServer(t, true)
	f.checker.ProbeForTest(context.Background())
	f.engine.SetAttackDetector(attackmode.New(attackmode.Config{
		Enabled: true, StoreErrorRatio: 0.05, StoreSlowRatio: 0.25,
	}, nil, slog.Default()))

	stats := decodeJSON(t, adminReq(t, f.ts, "GET", "/admin/stats", adminToken, ""))
	h := stats["health"].(map[string]any)
	if _, ok := h["store_signals"].(map[string]any); !ok {
		t.Errorf("health has no store_signals: %v", h)
	}
	th, ok := h["store_thresholds"].(map[string]any)
	if !ok {
		t.Fatalf("health has no store_thresholds: %v", h)
	}
	// Resolved from config, not from the detector the test just attached: the
	// dashboard must compare against what the running config actually enforces.
	if _, ok := th["error_ratio"]; !ok {
		t.Errorf("store_thresholds = %v, want error_ratio", th)
	}
	if _, ok := th["slow_ratio"]; !ok {
		t.Errorf("store_thresholds = %v, want slow_ratio", th)
	}
}

// TestAdminStatsGathersOnce: the dashboard polls /admin/stats every couple of
// seconds and the handler derives two rollups from the registry. Gathering
// twice per refresh would double that cost for nothing.
func TestAdminStatsGathersOnce(t *testing.T) {
	f := healthServer(t, true)
	counter := &gatherCounter{}
	if err := f.metrics.Registry().Register(counter); err != nil {
		t.Fatal(err)
	}
	f.checker.ProbeForTest(context.Background())

	if resp := adminReq(t, f.ts, "GET", "/admin/stats", adminToken, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("stats status = %d", resp.StatusCode)
	}
	if n := counter.n.Load(); n != 1 {
		t.Errorf("one /admin/stats gathered the registry %d times, want 1", n)
	}
}

// TestAdminStatsHealthWithoutMetrics: with metrics disabled the counter-derived
// blocks are absent rather than reported as zeroes, which would read as "no
// shedding, no fallback" instead of "unknown".
func TestAdminStatsHealthWithoutMetrics(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardian.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	engine, err := core.NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	hc := health.New(st, "memory", nil, slog.Default())
	t.Cleanup(func() { hc.Close() })
	hc.ProbeForTest(context.Background())
	engine.SetHealth(hc)

	ts := httptest.NewServer(NewAdminServer(engine, cfg, nil, adminToken, "", "", nil, slog.Default()))
	t.Cleanup(ts.Close)

	stats := decodeJSON(t, adminReq(t, ts, "GET", "/admin/stats", adminToken, ""))
	h, ok := stats["health"].(map[string]any)
	if !ok {
		t.Fatalf("stats has no health object: %v", stats)
	}
	if _, has := h["store"]; !has {
		t.Errorf("store status needs no metrics but is missing: %v", h)
	}
	for _, key := range []string{"store_ops", "shed", "pow_fallback"} {
		if _, has := h[key]; has {
			t.Errorf("%s reported with metrics disabled: %v", key, h[key])
		}
	}
}
