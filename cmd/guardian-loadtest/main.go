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
//	            path that separates the store backends (bbolt vs redis).
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
	"sort"
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
	duration := flag.Duration("d", 5*time.Second, "test duration")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("guardian-loadtest", version)
		return
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

	fmt.Printf("scenario=%s url=%s%s c=%d d=%s expect=%d\n",
		*scenario, *baseURL, path, *concurrency, *duration, wantStatus)

	var (
		wg        sync.WaitGroup
		total     atomic.Int64
		errored   atomic.Int64
		badStatus atomic.Int64
	)
	latencies := make([][]time.Duration, *concurrency)
	deadline := time.Now().Add(*duration)

	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			lats := make([]time.Duration, 0, 1<<16)
			rotateIP := *scenario == "challenge" // spread issuance across IPs to dodge the per-IP limiter
			var i int
			for time.Now().Before(deadline) {
				req, _ := http.NewRequest(http.MethodGet, *baseURL+path, nil)
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				if rotateIP {
					// A distinct IP per request across the 10.0.0.0/8 space:
					// worker in the low bits of octet 2, iteration across the
					// rest, so no request repeats an IP and hits the 60/min cap.
					req.Header.Set("X-Guardian-IP", fmt.Sprintf("10.%d.%d.%d",
						(w+(i>>16))&0x3f|0x40, (i>>8)&0xff, i&0xff))
					i++
				}
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errored.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				lats = append(lats, time.Since(start))
				total.Add(1)
				if resp.StatusCode != wantStatus {
					badStatus.Add(1)
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
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	pct := func(p float64) time.Duration {
		if len(all) == 0 {
			return 0
		}
		return all[min(int(float64(len(all))*p), len(all)-1)]
	}

	n := total.Load()
	fmt.Printf("requests:   %d (errors=%d, unexpected-status=%d)\n", n, errored.Load(), badStatus.Load())
	fmt.Printf("throughput: %.0f req/s\n", float64(n)/duration.Seconds())
	fmt.Printf("latency:    p50=%v  p90=%v  p99=%v  max=%v\n",
		pct(0.50), pct(0.90), pct(0.99), pct(0.9999))
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
