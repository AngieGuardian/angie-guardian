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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/melroy89/angie-guardian/core"
	"golang.org/x/sync/singleflight"
)

// angieClient reads Angie's own HTTP API so the dashboard can show real traffic
// (per-domain requests, in-flight connections, response codes, bandwidth) that
// Guardian never sees on its stateless allow path. It is a plain outbound read
// of another service on the same box: nothing here is on Guardian's hot path.
//
// Only fixed, known-safe suffixes are ever appended to the configured base URL,
// so there is no client-controlled request target (no SSRF surface). Responses
// are size-capped, redirects are refused, and a short TTL cache collapses the
// load of several dashboard tabs polling every few seconds.
type angieClient struct {
	base   string // configured URL, trailing slash trimmed
	client *http.Client
	log    *slog.Logger

	// group collapses concurrent misses for the same suffix into one upstream
	// fetch, so several dashboard tabs aligning on a TTL expiry hit Angie once.
	group singleflight.Group

	mu     sync.Mutex
	cached map[string]cachedZones // suffix -> last result + when (ok or 404)
	ttl    time.Duration
}

// cachedZones is a single memoized fetch result. A 404 (no such status_zone
// configured) is a legitimate outcome and is cached too (absent=true), so a
// server-only Angie config does not produce a warning and an outbound request on
// every 2-5s dashboard tick.
type cachedZones struct {
	body   []byte
	absent bool // upstream returned 404: endpoint simply not configured
	at     time.Time
}

// errZoneAbsent signals the endpoint 404'd: not an error to surface, just a
// zone the operator did not configure a status_zone for.
var errZoneAbsent = errors.New("angie status zone not configured")

// The two Angie API endpoints the dashboard consumes. Fixed constants, never
// built from request input. Trailing slash matches Angie's documented API tree
// paths (GET /status/http/server_zones/).
var angiePaths = []struct{ key, suffix string }{
	{"server_zones", "/http/server_zones/"},
	{"location_zones", "/http/location_zones/"},
}

const (
	angieMaxResponse = 4 << 20 // 4 MiB: a status payload is small; cap the read.
	angieCacheTTL    = 3 * time.Second
)

func newAngieClient(cfg core.AngieAPIConfig, log *slog.Logger) *angieClient {
	timeout := cfg.Timeout.Std()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &angieClient{
		base: strings.TrimRight(cfg.URL, "/"),
		client: &http.Client{
			Timeout: timeout,
			// Never follow redirects: the target is fixed, so a redirect can only
			// point somewhere we did not intend to read.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log:    log,
		cached: map[string]cachedZones{},
		ttl:    angieCacheTTL,
	}
}

// fetch retrieves one fixed Angie API endpoint, serving a fresh-enough cached
// copy when available. Returns the raw JSON body (Angie's own structure, passed
// through verbatim), errZoneAbsent when the endpoint 404s (no status_zone), or a
// transport/decode error. Concurrent misses for the same suffix are collapsed
// into one upstream request via singleflight so aligned multi-tab polls hit
// Angie once, and both success and 404 outcomes are cached.
func (a *angieClient) fetch(suffix string) ([]byte, error) {
	if body, absent, ok := a.lookup(suffix); ok {
		if absent {
			return nil, errZoneAbsent
		}
		return body, nil
	}

	// singleflight dedupes concurrent misses; the shared result is then cached,
	// so followers return from cache on their next tick. We pass a background
	// context to the fetch so one caller cancelling does not fail the shared
	// request for the others; the client's own Timeout still bounds it.
	res, err, _ := a.group.Do(suffix, func() (any, error) {
		// A racing caller may have populated the cache while we queued.
		if body, absent, ok := a.lookup(suffix); ok {
			if absent {
				return nil, errZoneAbsent
			}
			return body, nil
		}
		return a.fetchUpstream(suffix)
	})
	if err != nil {
		return nil, err
	}
	return res.([]byte), nil
}

// lookup returns a still-fresh cached entry: (body, absent, true) on a hit,
// (nil, false, false) on a miss or expiry.
func (a *angieClient) lookup(suffix string) ([]byte, bool, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cached[suffix]; ok && time.Since(c.at) < a.ttl {
		return c.body, c.absent, true
	}
	return nil, false, false
}

// fetchUpstream performs the real HTTP read, validates the payload, and caches
// the outcome. Runs under singleflight, so only one of a burst executes it.
func (a *angieClient) fetchUpstream(suffix string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, a.base+suffix, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// A missing status_zone is a normal, expected result, not a failure: cache it
	// so we neither warn nor re-request it every tick.
	if resp.StatusCode == http.StatusNotFound {
		a.store(suffix, cachedZones{absent: true, at: time.Now()})
		return nil, errZoneAbsent
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &angieStatusError{code: resp.StatusCode}
	}

	// Read one byte past the cap so a body that would exceed the limit is
	// detectable rather than silently truncated (a truncated JSON body would
	// otherwise cache as "successful" and later fail to re-encode).
	body, err := io.ReadAll(io.LimitReader(resp.Body, angieMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > angieMaxResponse {
		return nil, errors.New("angie api response exceeds " + strconv.Itoa(angieMaxResponse) + " bytes")
	}
	// Validate before caching: a 200 with malformed (or truncated) JSON must not
	// be stored as a good result, or the dashboard gets an empty-but-200 render
	// and the bad entry sticks for the whole TTL.
	if !json.Valid(body) {
		return nil, errors.New("angie api returned invalid JSON")
	}

	a.store(suffix, cachedZones{body: body, at: time.Now()})
	return body, nil
}

func (a *angieClient) store(suffix string, c cachedZones) {
	a.mu.Lock()
	a.cached[suffix] = c
	a.mu.Unlock()
}

type angieStatusError struct{ code int }

func (e *angieStatusError) Error() string {
	return "angie api returned status " + http.StatusText(e.code)
}

// handleAngie relays Angie's status zones to the dashboard. The response always
// carries an "enabled" flag and, on any fetch failure, a short "error" string,
// so the dashboard can show "Angie API unreachable" without the whole render
// tick failing. The zone payloads are Angie's own JSON, merged into one object.
func (s *AdminServer) handleAngie(w http.ResponseWriter, r *http.Request) {
	if s.angie == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	out := map[string]any{"enabled": true}
	var firstErr error
	got := 0
	for _, p := range angiePaths {
		body, err := s.angie.fetch(p.suffix)
		if err != nil {
			// A 404 is a normal result, not a failure: the operator simply did
			// not configure a status_zone for this endpoint (commonly true of
			// location_zones). Skip it silently; the panel renders from whatever
			// zones do exist. Only genuine failures are worth a log line, and the
			// fetch layer caches even the 404 so this does not repeat every tick.
			if !errors.Is(err, errZoneAbsent) {
				s.log.Warn("angie api fetch failed", "endpoint", p.suffix, "err", err)
				if firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		out[p.key] = json.RawMessage(body)
		got++
	}
	// Only surface an error when we got nothing usable; otherwise the panel
	// renders from the zones we do have (e.g. server_zones without any
	// location_zones configured).
	if got == 0 && firstErr != nil {
		out["error"] = firstErr.Error()
	}
	writeJSON(w, http.StatusOK, out)
}
