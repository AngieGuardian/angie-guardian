// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/melroy89/angie-guardian/core"
	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

// angieAdminServer builds an admin server whose angie_api points at the given
// upstream URL ("" disables it).
func angieAdminServer(t *testing.T, upstream string) *httptest.Server {
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
	cfg.Admin.AngieAPI.URL = upstream
	var st store.Store = store.NewMemory()
	t.Cleanup(func() { st.Close() })
	keyPath := filepath.Join(dir, "ed25519.key")
	key, err := pow.LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	st = store.Instrument(st, m)
	engine, err := core.NewEngine(cfg, st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMetrics(m)
	t.Cleanup(engine.Close)
	admin := NewAdminServer(engine, cfg, m, adminToken, keyPath, filepath.Join(dir, "previous"), nil, slog.Default())
	ts := httptest.NewServer(admin)
	t.Cleanup(ts.Close)
	return ts
}

// TestAngieDisabled: with no angie_api configured, the endpoint reports
// enabled:false rather than erroring, so the dashboard hides the panel.
func TestAngieDisabled(t *testing.T) {
	ts := angieAdminServer(t, "")
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))
	if out["enabled"] != false {
		t.Fatalf("enabled = %v, want false when unconfigured", out["enabled"])
	}
}

// TestAngieRequiresAuth: the relayed data is behind the admin token.
func TestAngieRequiresAuth(t *testing.T) {
	ts := angieAdminServer(t, "http://127.0.0.1:1")
	resp := adminReq(t, ts, http.MethodGet, "/admin/angie", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}
}

// TestAngieRelay: a mock Angie API's zone JSON is relayed under server_zones /
// location_zones, and only the two fixed paths are ever requested.
func TestAngieRelay(t *testing.T) {
	var paths sync.Map
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths.Store(r.URL.Path, true)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status/http/server_zones/":
			_, _ = w.Write([]byte(`{"example.com":{"requests":{"total":42,"processing":3}}}`))
		case "/status/http/location_zones/":
			_, _ = w.Write([]byte(`{"/api":{"requests":{"total":7}}}`))
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	ts := angieAdminServer(t, upstream.URL+"/status")
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))

	if out["enabled"] != true {
		t.Fatalf("enabled = %v, want true", out["enabled"])
	}
	if _, ok := out["error"]; ok {
		t.Fatalf("unexpected error: %v", out["error"])
	}
	sz, ok := out["server_zones"].(map[string]any)
	if !ok {
		t.Fatalf("server_zones missing or wrong type: %v", out["server_zones"])
	}
	ex := sz["example.com"].(map[string]any)["requests"].(map[string]any)
	if ex["total"].(float64) != 42 || ex["processing"].(float64) != 3 {
		t.Errorf("server_zones relay wrong: %v", ex)
	}
	if _, ok := out["location_zones"].(map[string]any); !ok {
		t.Errorf("location_zones missing: %v", out["location_zones"])
	}

	// Only the two fixed suffixes were ever fetched — no client-controlled path.
	paths.Range(func(k, _ any) bool {
		p := k.(string)
		if p != "/status/http/server_zones/" && p != "/status/http/location_zones/" {
			t.Errorf("unexpected upstream path requested: %q", p)
		}
		return true
	})
}

// TestAngieUnreachable: when the upstream is down, the endpoint degrades to
// enabled:true + an error string instead of failing.
func TestAngieUnreachable(t *testing.T) {
	// A URL that refuses connections (nothing listening on this loopback port).
	ts := angieAdminServer(t, "http://127.0.0.1:9")
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))
	if out["enabled"] != true {
		t.Fatalf("enabled = %v, want true", out["enabled"])
	}
	if _, ok := out["error"].(string); !ok {
		t.Errorf("want an error string when upstream is unreachable, got %v", out["error"])
	}
}

// TestAngieMissingZonesNoError: a 404 (no status_zone configured for an
// endpoint) is a normal result, not a failure. server_zones still relays, and no
// "error" is surfaced. Repeated polls do not re-request the 404'd endpoint (the
// negative result is cached), so a server-only config stays quiet.
func TestAngieMissingZonesNoError(t *testing.T) {
	var serverHits, locationHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status/http/server_zones/":
			serverHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"example.com":{"requests":{"total":1}}}`))
		case "/status/http/location_zones/":
			// No location has a status_zone: Angie returns 404 here.
			locationHits.Add(1)
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	ts := angieAdminServer(t, upstream.URL+"/status")

	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))
	if out["enabled"] != true {
		t.Fatalf("enabled = %v, want true", out["enabled"])
	}
	if _, ok := out["error"]; ok {
		t.Errorf("a missing location_zones must not surface an error: %v", out["error"])
	}
	if _, ok := out["server_zones"].(map[string]any); !ok {
		t.Errorf("server_zones must still relay when location_zones is absent: %v", out["server_zones"])
	}
	if _, ok := out["location_zones"]; ok {
		t.Errorf("location_zones should be omitted when absent, got %v", out["location_zones"])
	}

	// A second poll within the TTL must not re-request the 404'd endpoint: the
	// negative result is cached, so it stays quiet.
	adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, "")
	if got := locationHits.Load(); got != 1 {
		t.Errorf("location_zones fetched %d times, want 1 (404 must be negative-cached)", got)
	}
}

// TestAngieInvalidJSONNotCached: a 200 carrying malformed JSON must not be cached
// as a good result. It degrades to an error, and a later poll re-fetches (so a
// transient bad body is not stuck for the whole TTL).
func TestAngieInvalidJSONNotCached(t *testing.T) {
	var mode atomic.Int32 // 0 = serve garbage, 1 = serve valid
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/status/http/server_zones/" && mode.Load() == 0 {
			_, _ = w.Write([]byte(`{"truncated": `)) // invalid JSON
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	ts := angieAdminServer(t, upstream.URL+"/status")

	// First poll: server_zones is invalid -> not relayed, not cached.
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))
	if _, ok := out["server_zones"]; ok {
		t.Errorf("invalid JSON must not be relayed as server_zones: %v", out["server_zones"])
	}

	// Flip to valid; because the bad body was never cached, the next poll fetches
	// fresh and now relays it.
	mode.Store(1)
	out = decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))
	if _, ok := out["server_zones"].(map[string]any); !ok {
		t.Errorf("after the body became valid, server_zones must relay: %v", out["server_zones"])
	}
}

// TestAngieOverLimitRejected: a body larger than the read cap is detected and
// rejected, not silently truncated and cached as valid-looking JSON.
func TestAngieOverLimitRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Emit a valid-JSON object far larger than angieMaxResponse (4 MiB), so a
		// truncating reader would leave a broken but plausible prefix.
		_, _ = w.Write([]byte(`{"pad":"`))
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for written := 0; written < (5 << 20); written += len(chunk) {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	defer upstream.Close()

	ts := angieAdminServer(t, upstream.URL+"/status")
	out := decodeJSON(t, adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, ""))
	if _, ok := out["server_zones"]; ok {
		t.Errorf("an over-limit body must be rejected, not relayed: %v", out["server_zones"])
	}
	if _, ok := out["error"].(string); !ok {
		t.Errorf("want an error string when every endpoint is over-limit, got %v", out["error"])
	}
}

// TestAngieSingleflight: many concurrent polls that all miss the cache collapse
// into one upstream fetch per suffix, not one per caller.
func TestAngieSingleflight(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// Hold briefly so the concurrent callers genuinely overlap on the miss.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	ts := angieAdminServer(t, upstream.URL+"/status")

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, "")
		})
	}
	wg.Wait()

	// Two fixed suffixes. Even with 20 concurrent callers all missing the empty
	// cache, singleflight should collapse each suffix's burst, so hits stays low
	// (a handful at most, not ~40). Assert well under the no-collapse count.
	if got := hits.Load(); got > 6 {
		t.Errorf("upstream hits = %d, want a small number (singleflight should collapse concurrent misses)", got)
	}
}

// TestAngieCaches: two admin requests within the TTL hit the upstream once.
func TestAngieCaches(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	ts := angieAdminServer(t, upstream.URL+"/status")
	// Two admin calls; each fetches two fixed suffixes, but within the TTL the
	// second call serves both from cache. So exactly 2 upstream hits total.
	adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, "")
	adminReq(t, ts, http.MethodGet, "/admin/angie", adminToken, "")
	if got := hits.Load(); got != 2 {
		t.Errorf("upstream hits = %d, want 2 (second call should be cached)", got)
	}
}
