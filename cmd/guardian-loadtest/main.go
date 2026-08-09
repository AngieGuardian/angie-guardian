// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// guardian-loadtest stress-tests a running guardiand's /auth hot path over
// real HTTP with keepalive, the way Angie drives it. It reports request
// rate and latency percentiles so regressions against the ≥50k req/s
// budget are caught before deployment.
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
//
// Two run modes. -d runs for a fixed wall-clock duration; -n completes a fixed
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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var version = "dev" // set via -ldflags "-X main.version=..."

func main() {
	baseURL := flag.String("url", "http://127.0.0.1:8071", "guardiand base URL")
	scenario := flag.String("scenario", "allow", "allow | deny | token | challenge")
	host := flag.String("host", "plain.test", "X-Guardian-Host to send")
	ip := flag.String("ip", "198.51.100.7", "X-Guardian-IP to send")
	concurrency := flag.Int("c", 64, "concurrent connections")
	duration := flag.Duration("d", 5*time.Second, "test duration (ignored when -n is set)")
	requests := flag.Int("n", 0, "run exactly this many measured requests instead of a duration (comparable across machines and commits)")
	warmup := flag.Int("warmup", 0, "complete and discard this many requests first, so measurement starts from a known store size")
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

	ua := "Mozilla/5.0 (loadtest)"
	if *scenario == "allow" || *scenario == "deny" {
		ua = "curl/8.0 (loadtest)" // avoid the challenge path
	}

	transport := &http.Transport{
		MaxIdleConns:        *concurrency * 2,
		MaxIdleConnsPerHost: *concurrency * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: transport}

	headers := map[string]string{
		"X-Guardian-Host":   *host,
		"X-Guardian-Method": "GET",
		"X-Guardian-URI":    "/loadtest?x=1",
		"X-Guardian-IP":     *ip,
		"X-Guardian-UA":     ua,
	}
	// path is the endpoint each request hits; challenge is the only write-heavy
	// scenario, so it targets /challenge instead of /auth.
	path := "/auth"
	wantStatus := http.StatusOK
	switch *scenario {
	case "allow":
	case "deny":
		wantStatus = http.StatusForbidden
	case "token":
		cookie, err := bootstrapToken(client, *baseURL, *host, *ip, ua)
		if err != nil {
			fmt.Fprintln(os.Stderr, "token bootstrap failed:", err)
			os.Exit(1)
		}
		headers["X-Guardian-Cookie"] = cookie
	case "challenge":
		path = "/challenge"
		ua = "Mozilla/5.0 (loadtest)"
		headers["X-Guardian-UA"] = ua
		// Each issuance is rate-limited per IP (60/min); the worker rotates the
		// IP per request (see below) so the limiter never trips.
	default:
		fmt.Fprintln(os.Stderr, "unknown scenario:", *scenario)
		os.Exit(2)
	}

	if *requests > 0 {
		fmt.Printf("scenario=%s url=%s%s c=%d n=%d warmup=%d expect=%d\n",
			*scenario, *baseURL, path, *concurrency, *requests, *warmup, wantStatus)
	} else {
		fmt.Printf("scenario=%s url=%s%s c=%d d=%s warmup=%d expect=%d\n",
			*scenario, *baseURL, path, *concurrency, *duration, *warmup, wantStatus)
	}

	var (
		wg        sync.WaitGroup
		total     atomic.Int64 // measured completions
		errored   atomic.Int64
		badStatus atomic.Int64
		// claimed hands out one globally unique sequence number per request
		// before it runs: numbers below warmup are the discarded warmup phase,
		// the rest are measured. Claiming also drives the challenge scenario's
		// IP rotation, so no two requests, warmup included, share an IP.
		claimed atomic.Int64
		// measureStart/EndNano bound the measured window: set once by the first
		// measured request, advanced to the latest measured completion. The
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

	latencies := make([][]time.Duration, *concurrency)
	warmupN := int64(*warmup)
	measuredN := int64(*requests)

	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			lats := make([]time.Duration, 0, 1<<16)
			rotateIP := *scenario == "challenge" // spread issuance across IPs to dodge the per-IP limiter
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
					} else if time.Now().UnixNano()-measureStartNano.Load() >= duration.Nanoseconds() {
						break // fixed duration elapsed (measured from warmup end)
					}
				}
				req, _ := http.NewRequest(http.MethodGet, *baseURL+path, nil)
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				if rotateIP {
					req.Header.Set("X-Guardian-IP", rotatingChallengeIP(seq))
				}
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errored.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != wantStatus {
					badStatus.Add(1)
				}
				if !measured {
					continue
				}
				end := time.Now()
				lats = append(lats, end.Sub(start))
				total.Add(1)
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
			latencies[w] = lats
		}(w)
	}
	wg.Wait()

	var all []time.Duration
	for _, l := range latencies {
		all = append(all, l...)
	}
	slices.Sort(all)
	pct := func(p float64) time.Duration {
		if len(all) == 0 {
			return 0
		}
		return all[min(int(float64(len(all))*p), len(all)-1)]
	}

	n := total.Load()
	elapsed := time.Duration(measureEndNano.Load() - measureStartNano.Load())
	if elapsed <= 0 {
		elapsed = *duration // no measured completions; avoid dividing by zero
	}
	if warmupN > 0 {
		fmt.Printf("warmup:     %d requests discarded\n", warmupN)
	}
	fmt.Printf("requests:   %d in %.2fs (errors=%d, unexpected-status=%d)\n",
		n, elapsed.Seconds(), errored.Load(), badStatus.Load())
	fmt.Printf("throughput: %.0f req/s\n", float64(n)/elapsed.Seconds())
	fmt.Printf("latency:    p50=%v  p90=%v  p99=%v  max=%v\n",
		pct(0.50), pct(0.90), pct(0.99), pct(0.9999))

	// One count per elapsed second of the measured window. A flat line means a
	// steady state; a falling line means the run is measuring store growth, and
	// its aggregate above is not comparable across machines or commits.
	seconds := min(int(elapsed.Seconds())+1, len(buckets))
	if seconds > 1 {
		fmt.Printf("per-second:")
		for i := 0; i < seconds; i++ {
			fmt.Printf(" %d", buckets[i].Load())
		}
		fmt.Println()
	}
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
