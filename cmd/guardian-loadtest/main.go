// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// guardian-loadtest stress-tests Guardian and its Angie integration over real
// HTTP with keepalive. It reports request rate and latency percentiles so
// regressions against the ≥50k req/s budget are caught before deployment.
//
// Scenarios:
//
//	allow     — plain request, full pipeline, terminal "default allow"
//	deny      — denylisted client IP (exercises the logging deny path)
//	token     — solves one real PoW challenge, then hammers /auth with the
//	            minted cookie (the production common path)
//	challenge — hammers /challenge, issuing a fresh PoW challenge per request.
//	            Each issuance is a store write (CAS), so this is the write-heavy
//	            path that separates the store backends (embedded vs redis).
//	refuse-auth      — directly measures the /auth half of a refusal.
//	refuse-challenge — directly measures the small /challenge refusal response.
//	refuse-angie     — measures one original request through Angie's production
//	                   /auth → @guardian_challenge → 403 two-hop route.
//	allow-angie      — measures authorization followed by an application 200.
//	deny-angie       — measures a Guardian deny through Angie (final 403).
//
// Two run modes. -d runs for a fixed wall-clock duration; -n attempts a fixed
// number of measured requests. For the write-heavy challenge scenario only -n
// yields numbers comparable across machines and commits: the store grows for
// the whole run and throughput decays with it, so a fixed-duration average
// blends a fast cold phase with a slow loaded phase in a ratio set by machine
// speed and duration. Fixed work measures a fixed store-size window instead.
// -warmup completes (and discards) requests first so that window starts from a
// known store size rather than from an empty store, and the per-second line in
// the output makes any remaining decay visible instead of averaging it away.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var version = "dev" // set via -ldflags "-X main.version=..."

const (
	browserUA              = "Mozilla/5.0 (loadtest)"
	refusalAccept          = "*/*"
	refusalOutcome         = "accept_heuristic_refused"
	guardianActionHeader   = "X-Guardian-Action"
	guardianRefusalHeader  = "X-Guardian-Refusal"
	guardianHostHeader     = "X-Guardian-Host"
	guardianMethodHeader   = "X-Guardian-Method"
	guardianURIHeader      = "X-Guardian-URI"
	guardianIPHeader       = "X-Guardian-IP"
	guardianUAHeader       = "X-Guardian-UA"
	guardianCookieHeader   = "X-Guardian-Cookie"
	loadtestRequestURI     = "/loadtest?x=1"
	refusalContentType     = "text/plain"
	refusalCacheControlKey = "no-store"
)

type scenarioSpec struct {
	path               string
	userAgent          string
	wantStatus         int
	rotateIP           bool
	throughAngie       bool
	extraHeaders       map[string]string
	wantHeaders        map[string]string
	wantHeaderPrefix   map[string]string
	wantHeaderContains map[string]string
}

func scenarioByName(name string) (scenarioSpec, error) {
	s := scenarioSpec{
		path:       "/auth",
		userAgent:  browserUA,
		wantStatus: http.StatusOK,
	}
	switch name {
	case "allow":
		s.userAgent = "curl/8.0 (loadtest)" // avoid the challenge path
	case "deny":
		s.userAgent = "curl/8.0 (loadtest)" // avoid the challenge path
		s.wantStatus = http.StatusForbidden
	case "token":
	case "challenge":
		s.path = "/challenge"
		s.rotateIP = true
	case "refuse-auth":
		s.extraHeaders = map[string]string{"Accept": refusalAccept}
		s.wantStatus = http.StatusUnauthorized
		s.wantHeaders = map[string]string{
			guardianActionHeader:  "refuse",
			guardianRefusalHeader: refusalOutcome,
		}
	case "refuse-challenge":
		s.path = "/challenge"
		s.extraHeaders = map[string]string{
			"Accept":              refusalAccept,
			guardianRefusalHeader: refusalOutcome,
		}
		s.wantStatus = http.StatusForbidden
		s.wantHeaderPrefix = map[string]string{"Content-Type": refusalContentType}
		s.wantHeaderContains = map[string]string{"Cache-Control": refusalCacheControlKey}
	case "refuse-angie":
		s.path = loadtestRequestURI
		s.throughAngie = true
		s.extraHeaders = map[string]string{"Accept": refusalAccept}
		s.wantStatus = http.StatusForbidden
		s.wantHeaderPrefix = map[string]string{"Content-Type": refusalContentType}
		s.wantHeaderContains = map[string]string{"Cache-Control": refusalCacheControlKey}
	case "allow-angie", "deny-angie":
		s.path = loadtestRequestURI
		s.throughAngie = true
		if name == "deny-angie" {
			s.wantStatus = http.StatusForbidden
		}
	default:
		return scenarioSpec{}, fmt.Errorf("unknown scenario: %s", name)
	}
	return s, nil
}

func (s scenarioSpec) newRequest(baseURL, host, ip string, seq int64) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+s.path, nil)
	if err != nil {
		return nil, err
	}
	if s.throughAngie {
		req.Host = host
		req.Header.Set("User-Agent", s.userAgent)
	} else {
		req.Header.Set(guardianHostHeader, host)
		req.Header.Set(guardianMethodHeader, http.MethodGet)
		req.Header.Set(guardianURIHeader, loadtestRequestURI)
		req.Header.Set(guardianIPHeader, ip)
		req.Header.Set(guardianUAHeader, s.userAgent)
	}
	for k, v := range s.extraHeaders {
		req.Header.Set(k, v)
	}
	if s.rotateIP {
		req.Header.Set(guardianIPHeader, rotatingChallengeIP(seq))
	}
	return req, nil
}

func (s scenarioSpec) responseMatches(resp *http.Response) bool {
	for k, want := range s.wantHeaders {
		if resp.Header.Get(k) != want {
			return false
		}
	}
	for k, want := range s.wantHeaderPrefix {
		if !strings.HasPrefix(resp.Header.Get(k), want) {
			return false
		}
	}
	for k, want := range s.wantHeaderContains {
		if !strings.Contains(resp.Header.Get(k), want) {
			return false
		}
	}
	return true
}

func main() {
	baseURL := flag.String("url", "http://127.0.0.1:8071", "target base URL (guardiand, or Angie for *-angie scenarios)")
	scenario := flag.String("scenario", "allow", "allow | deny | token | challenge | refuse-auth | refuse-challenge | refuse-angie | allow-angie | deny-angie")
	host := flag.String("host", "plain.test", "protected host (X-Guardian-Host, or HTTP Host for *-angie scenarios)")
	ip := flag.String("ip", "198.51.100.7", "X-Guardian-IP to send (direct Guardian scenarios only)")
	concurrency := flag.Int("c", 64, "concurrent connections")
	duration := flag.Duration("d", 5*time.Second, "test duration (ignored when -n is set)")
	requests := flag.Int("n", 0, "run exactly this many measured request attempts instead of a duration (comparable across machines and commits)")
	warmup := flag.Int("warmup", 0, "attempt and discard this many requests first, so measurement starts from a known store size")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("guardian-loadtest", version)
		return
	}
	if *requests < 0 || *warmup < 0 {
		fmt.Fprintln(os.Stderr, "-n and -warmup must be >= 0")
		os.Exit(2)
	}

	spec, err := scenarioByName(*scenario)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	transport := &http.Transport{
		MaxIdleConns:        *concurrency * 2,
		MaxIdleConnsPerHost: *concurrency * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: transport}

	if *scenario == "token" {
		cookie, err := bootstrapToken(client, *baseURL, *host, *ip, spec.userAgent)
		if err != nil {
			fmt.Fprintln(os.Stderr, "token bootstrap failed:", err)
			os.Exit(1)
		}
		spec.extraHeaders = map[string]string{guardianCookieHeader: cookie}
	}

	if *requests > 0 {
		fmt.Printf("scenario=%s url=%s%s c=%d n=%d warmup=%d expect=%d\n",
			*scenario, *baseURL, spec.path, *concurrency, *requests, *warmup, spec.wantStatus)
	} else {
		fmt.Printf("scenario=%s url=%s%s c=%d d=%s warmup=%d expect=%d\n",
			*scenario, *baseURL, spec.path, *concurrency, *duration, *warmup, spec.wantStatus)
	}

	result := runLoad(client, spec, loadConfig{
		baseURL: *baseURL, host: *host, ip: *ip, concurrency: *concurrency,
		warmup: int64(*warmup), requests: int64(*requests), duration: *duration,
	})

	var all []time.Duration
	for _, l := range result.latencies {
		all = append(all, l...)
	}
	slices.Sort(all)
	pct := func(p float64) time.Duration {
		if len(all) == 0 {
			return 0
		}
		return all[min(int(float64(len(all))*p), len(all)-1)]
	}

	n := result.measured.completed
	elapsed := result.elapsed
	if elapsed <= 0 {
		elapsed = *duration // no measured completions; avoid dividing by zero
	}
	if *warmup > 0 {
		fmt.Printf("warmup:     %d requests discarded (errors=%d, unexpected-status=%d, unexpected-contract=%d)\n",
			*warmup, result.warmup.errors, result.warmup.unexpectedStatus, result.warmup.unexpectedContract)
	}
	fmt.Printf("requests:   %d in %.2fs (errors=%d, unexpected-status=%d, unexpected-contract=%d)\n",
		n, elapsed.Seconds(), result.measured.errors, result.measured.unexpectedStatus, result.measured.unexpectedContract)
	fmt.Printf("throughput: %.0f req/s\n", float64(n)/elapsed.Seconds())
	fmt.Printf("latency:    p50=%v  p90=%v  p99=%v  max=%v\n",
		pct(0.50), pct(0.90), pct(0.99), pct(0.9999))

	fmt.Print("statuses:")
	for status, count := range result.measured.statuses {
		if count > 0 {
			fmt.Printf(" %d=%d", status, count)
		}
	}
	fmt.Println()

	// One count per elapsed second of the measured window. A flat line means a
	// steady state; a falling line means the run is measuring store growth, and
	// its aggregate above is not comparable across machines or commits.
	seconds := min(int(elapsed.Seconds())+1, len(result.perSecond))
	if seconds > 1 {
		fmt.Printf("per-second:")
		for i := 0; i < seconds; i++ {
			fmt.Printf(" %d", result.perSecond[i])
		}
		fmt.Println()
	}
}

// Phase counters are worker-local: a status histogram must not introduce a
// contended atomic increment into every request in the generator.
type phaseCounts struct {
	completed, errors, unexpectedStatus, unexpectedContract int64
	statuses                                                [1000]int64 // net/http accepts three-digit response status codes.
}

func (c *phaseCounts) add(other *phaseCounts) {
	c.completed += other.completed
	c.errors += other.errors
	c.unexpectedStatus += other.unexpectedStatus
	c.unexpectedContract += other.unexpectedContract
	for status, count := range other.statuses {
		c.statuses[status] += count
	}
}

type workerResult struct {
	warmup, measured phaseCounts
	latencies        []time.Duration
}

type loadConfig struct {
	baseURL, host, ip string
	concurrency       int
	warmup, requests  int64
	duration          time.Duration
}

type loadResult struct {
	warmup, measured phaseCounts
	elapsed          time.Duration
	latencies        [][]time.Duration
	perSecond        []int64
}

func runLoad(client *http.Client, spec scenarioSpec, config loadConfig) loadResult {
	var (
		wg sync.WaitGroup
		// claimed hands out one globally unique sequence number per request
		// before it runs: numbers below warmup are the discarded warmup phase,
		// the rest are measured. Claiming also drives the challenge scenario's
		// IP rotation, so no two requests, warmup included, share an IP.
		claimed atomic.Int64
		// measureStart/EndNano bound the measured window: set once by the first
		// measured request, advanced to the latest measured attempt's end. The
		// throughput denominator is this window, not the configured duration,
		// so a fixed-work run reports honestly however long it takes.
		measureStartNano atomic.Int64
		measureEndNano   atomic.Int64
	)
	// Per-second measured completions, so decay over the run is visible in the
	// output instead of being averaged away. An hour of buckets is far beyond
	// any sane run; later completions land in the last bucket rather than
	// indexing out of range.
	buckets := make([]atomic.Int64, 3600)

	workers := make([]workerResult, config.concurrency)
	warmupN := config.warmup
	measuredN := config.requests
	// Failed attempts also bound the measured window, including all-error runs.
	recordError := func(counts *phaseCounts, measured bool) {
		counts.errors++
		if !measured {
			return
		}
		end := time.Now().UnixNano()
		for {
			cur := measureEndNano.Load()
			if end <= cur || measureEndNano.CompareAndSwap(cur, end) {
				return
			}
		}
	}

	for w := 0; w < config.concurrency; w++ {
		wg.Go(func() {
			lats := make([]time.Duration, 0, 1<<16)
			for {
				seq := claimed.Add(1) - 1
				measured := seq >= warmupN
				if measured {
					if measureStartNano.Load() == 0 {
						measureStartNano.CompareAndSwap(0, time.Now().UnixNano())
					}
					if measuredN > 0 {
						if seq >= warmupN+measuredN {
							break // fixed work done
						}
					} else if time.Now().UnixNano()-measureStartNano.Load() >= config.duration.Nanoseconds() {
						break // fixed duration elapsed (measured from warmup end)
					}
				}
				counts := &workers[w].warmup
				if measured {
					counts = &workers[w].measured
				}
				req, err := spec.newRequest(config.baseURL, config.host, config.ip, seq)
				if err != nil {
					recordError(counts, measured)
					continue
				}
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					recordError(counts, measured)
					continue
				}
				// Count observed HTTP statuses even if draining the body fails.
				counts.statuses[resp.StatusCode]++
				_, bodyErr := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if bodyErr != nil {
					recordError(counts, measured)
					continue
				}
				if resp.StatusCode != spec.wantStatus {
					counts.unexpectedStatus++
				} else if !spec.responseMatches(resp) {
					counts.unexpectedContract++
				}
				counts.completed++
				if !measured {
					continue
				}
				end := time.Now()
				lats = append(lats, end.Sub(start))
				if s := measureStartNano.Load(); s != 0 {
					buckets[min(int((end.UnixNano()-s)/1e9), len(buckets)-1)].Add(1)
				}
				for {
					cur := measureEndNano.Load()
					if end.UnixNano() <= cur || measureEndNano.CompareAndSwap(cur, end.UnixNano()) {
						break
					}
				}
			}
			workers[w].latencies = lats
		})
	}
	wg.Wait()

	result := loadResult{
		elapsed:   time.Duration(measureEndNano.Load() - measureStartNano.Load()),
		perSecond: make([]int64, len(buckets)),
	}
	for _, worker := range workers {
		result.warmup.add(&worker.warmup)
		result.measured.add(&worker.measured)
		result.latencies = append(result.latencies, worker.latencies)
	}
	for i := range buckets {
		result.perSecond[i] = buckets[i].Load()
	}
	return result
}

// rotatingChallengeIP derives a synthetic private IPv4 address from the
// global request sequence. Use the full 10/8: its 16.7M addresses take more
// than the default one-minute issuance window to cycle even at the in-memory
// backend's measured ~160k requests/s. The former 10.64/10 range wrapped after
// 4.1M requests. A multi-million-request soak must still raise the temporary
// issuance limit: CounterCache's bounded overload sketch intentionally becomes
// conservative when flooded with more distinct keys than it can retain.
func rotatingChallengeIP(seq int64) string {
	return fmt.Sprintf("10.%d.%d.%d",
		(seq>>16)&0xff, (seq>>8)&0xff, seq&0xff)
}

var dataRe = regexp.MustCompile(`<script id="guardian-data" type="application/json">(.*?)</script>`)

// bootstrapToken performs one real challenge → solve → redeem round trip and
// returns the resulting Cookie header value.
func bootstrapToken(client *http.Client, baseURL, host, ip, ua string) (string, error) {
	set := func(r *http.Request) {
		r.Header.Set("X-Guardian-Host", host)
		r.Header.Set("X-Guardian-IP", ip)
		r.Header.Set("X-Guardian-UA", ua)
		r.Header.Set("X-Guardian-URI", "/loadtest")
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/challenge", nil)
	set(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	page, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("challenge endpoint: %d %s", resp.StatusCode, page)
	}
	m := dataRe.FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("no challenge data in page")
	}
	var data struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Difficulty  int    `json:"difficulty_bits"`
	}
	if err := json.Unmarshal(m[1], &data); err != nil {
		return "", err
	}

	// Brute-force a nonce with data.Difficulty leading zero bits, the same
	// check core/pow's leadingZeroBits performs.
	var nonce string
	for n := 0; ; n++ {
		nonce = strconv.Itoa(n)
		sum := sha256.Sum256([]byte(data.Challenge + nonce))
		zeros, ok := 0, false
		for _, b := range sum {
			if b == 0 {
				zeros += 8
				continue
			}
			ok = zeros+bits.LeadingZeros8(b) >= data.Difficulty
			break
		}
		if ok {
			break
		}
	}

	body, _ := json.Marshal(map[string]any{"challenge_id": data.ChallengeID, "nonce": nonce})
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/pass", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	set(req)
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("pass endpoint: %d %s", resp.StatusCode, b)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "guardian_token" {
			return c.Name + "=" + c.Value, nil
		}
	}
	return "", fmt.Errorf("no token cookie in pass response")
}
