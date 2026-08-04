// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command seed drives a local guardiand with realistic mixed traffic so the
// dashboard, the admin API and /metrics have something to show: solved and
// failed proof-of-work, challenge and deny decisions, behavioural blocks over a
// spread of IPs, honeypot and static-denylist hits, and plain allowed traffic.
//
// It exists for demos, for refreshing docs/public/dashboard.png, and for eyeballing
// a dashboard change against populated charts instead of empty ones. It is not
// a load test — see cmd/guardian-loadtest for throughput measurement. This one
// optimises for a representative *mix* at a gentle rate.
//
// It talks to guardiand directly, standing in for Angie by setting the
// X-Guardian-* headers itself, so the target must run with trusted_proxy: true.
// To exercise every leg the target config also needs proof of work enabled,
// waf.rules pointing at a file (deploy/rules-common.yaml works), and
// waf.ip_behaviour on for blocks. A pow-disabled domain (default plain.test)
// supplies the allowed traffic. test/seed/guardian.seed.yaml is a ready-made
// throwaway config with all of that set up.
//
// Usage (two shells, from the repo root):
//
//	go run ./cmd/guardiand -config test/seed/guardian.seed.yaml
//	make seed
//
// or against an existing instance:
//
//	go run ./test/seed -url http://127.0.0.1:18071 -d 2m \
//	    -admin http://127.0.0.1:18072 -token "$TOKEN"
//
// The seed config also loads committed GeoIP/ASN fixtures and a demo
// reputation feed (see gengeoip and guardian.seed.yaml), so the geo surfaces
// and the IP lookup panel are part of the demo. Two addresses are staged for
// pasting into the lookup: starOffender probes every round and accumulates a
// deep decision history plus a behavioural block, and manualBlockIP carries a
// hand-placed admin block but sends no traffic (the empty-ring case). The
// summary prints ready-made ?ip= links for both.
//
//go:generate go run ./gengeoip -dir .
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dataRe pulls the JSON the interstitial embeds for its solver. Same contract
// the browser and the e2e suite use.
var dataRe = regexp.MustCompile(`<script id="guardian-data" type="application/json">(.*?)</script>`)

type challengeData struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	Difficulty  int    `json:"difficulty_bits"`
	PassURL     string `json:"pass_url"`
}

// Traffic shape. Hosts must exist (or fall through to defaults) in the target
// config with proof of work enabled; allowHost must have it disabled.
// seedBaseBits is defaults.pow.base_difficulty in guardian.seed.yaml (4 on the
// config scale) expressed in leading zero bits, the reference point the modelled
// solve times below scale from. Keep the two in step.
const seedBaseBits = 16

// maxSeedElapsedMS keeps a modelled solve time inside what the daemon will
// accept from a client that redeems immediately: pow.ClockSkewAllowance is 30s,
// and this leaves headroom under it.
const maxSeedElapsedMS = 25_000

var (
	hosts = []string{"example.com", "shop.example.com", "blog.example.com"}
	paths = []string{"/", "/products", "/cart", "/search?q=shoes", "/account", "/blog/post-1", "/checkout"}
	uas   = []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
	}
	// Paths and agents the shipped starter rules (deploy/rules-common.yaml)
	// deny or block outright.
	badPaths = []string{"/.env", "/.git/config", "/wp-login.php", "/wp-config.php.bak", "/.aws/credentials", "/../../etc/passwd"}
	badUAs   = []string{"sqlmap/1.7#stable", "Nikto/2.5.0", "curl/8.0", "python-requests/2.31", "Nmap Scripting Engine"}
	// Trap paths configured in guardian.seed.yaml: one hit denies and persists
	// a block. Under the declared prefixes so both spellings match.
	honeypotPaths = []string{"/admin-old/", "/admin-old/config.php", "/wp-admin-backup/index.php"}
)

// denylistIP returns an address inside the statically denied range in
// guardian.seed.yaml, so the decision is a terminal denylist hit rather than
// anything the WAF or the scoreboard decided.
func (s *seeder) denylistIP() string { return fmt.Sprintf("203.0.113.%d", s.intn(14)+241) }

// feedIP returns an address inside the demo-blocklist reputation feed
// (test/seed/seed-blocklist.txt), so the decision is a reputation deny.
func (s *seeder) feedIP() string { return fmt.Sprintf("203.0.113.%d", s.intn(16)+224) }

const (
	// starOffender probes every round: the address to paste into the IP
	// lookup panel for a deep history (and, quickly, a behavioural block).
	starOffender = "203.0.113.66"
	// manualBlockIP gets a hand-placed admin block and never sends traffic:
	// the lookup's blocked-but-nothing-in-the-ring case.
	manualBlockIP = "198.51.100.250"
)

type seeder struct {
	base, allowHost string
	client          *http.Client
	rng             *rand.Rand
	mu              sync.Mutex // guards rng: math/rand is not concurrency-safe
}

func (s *seeder) intn(n int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rng.Intn(n)
}

func (s *seeder) pick(xs []string) string { return xs[s.intn(len(xs))] }

// clientIP returns an address from a bounded pool so repeat offenders build up
// a behavioural score and eventually get blocked, which is what makes the
// active-block list look like a real deployment rather than one hit per IP.
func (s *seeder) clientIP(prefix string, size int) string {
	return fmt.Sprintf("%s.%d", prefix, s.intn(size)+1)
}

// do performs one request wearing Angie's hat: guardiand reads the request from
// the X-Guardian-* headers, which is why the target needs trusted_proxy: true.
func (s *seeder) do(method, path, host, uri, ip, ua string, body []byte) (int, []byte) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, s.base+path, rdr)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("X-Guardian-Host", host)
	req.Header.Set("X-Guardian-URI", uri)
	req.Header.Set("X-Guardian-IP", ip)
	req.Header.Set("X-Guardian-UA", ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, c := range b {
		if c == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask > 0; mask >>= 1 {
			if c&mask != 0 {
				return n
			}
			n++
		}
	}
	return n
}

// solveNonce does the same work the browser's solver does: find a nonce whose
// SHA-256 has at least difficulty leading zero bits.
func solveNonce(challenge string, difficulty int) string {
	for n := 0; n < 1<<30; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		if leadingZeroBits(sum[:]) >= difficulty {
			return nonce
		}
	}
	return ""
}

// visitor walks the full path a real browser takes: /auth returns a challenge
// (recorded as a challenge decision), the interstitial is fetched, the proof of
// work is solved, and the solution is redeemed. redeem=false models a visitor
// that closes the tab, so issued stays ahead of solved; valid=false submits a
// wrong nonce, which is the "failed" leg of the funnel.
func (s *seeder) visitor(host, uri, ip, ua string, redeem, valid bool) {
	// The auth subrequest first: this is what puts a "challenge" decision in
	// the recent ring. Fetching /challenge alone would populate the PoW
	// counters but leave the decisions feed showing denies only.
	s.do(http.MethodGet, "/auth", host, uri, ip, ua, nil)

	_, body := s.do(http.MethodGet, "/challenge", host, uri, ip, ua, nil)
	m := dataRe.FindSubmatch(body)
	if m == nil {
		return
	}
	var ch challengeData
	if json.Unmarshal(m[1], &ch) != nil {
		return
	}
	if !redeem {
		return
	}
	nonce := "not-a-valid-nonce"
	if valid {
		nonce = solveNonce(ch.Challenge, ch.Difficulty)
	}
	// A plausible spread of client solve times so the solve-time histogram has a
	// shape instead of a single spike. The seeder solves natively in Go, orders
	// of magnitude faster than a browser, so the reported figure is modelled
	// rather than measured: it doubles per difficulty bit, which is what the
	// work itself does.
	elapsed := 150 + s.intn(2800)
	for range ch.Difficulty - seedBaseBits {
		elapsed *= 2
	}
	if strings.Contains(ua, "iPhone") {
		// Phones hash far slower than laptops, which is the whole point of the
		// by-client card: a difficulty that is fine on a desktop can be
		// punishing on mobile.
		elapsed = elapsed*2 + 900
	}
	// The daemon accepts a reported time up to the issue-to-redeem interval it
	// measured plus pow.ClockSkewAllowance (30s). The seeder redeems within
	// milliseconds of issuing, so that allowance is the whole budget, and a
	// modelled value above it would be discarded as impossible: the seeded
	// histogram would quietly thin out at exactly the difficulties this demo
	// exists to show. Doubling per bit reaches it once escalation pushes a
	// client a few bits past base, so cap the model short of the bound and let
	// the deliberate spike below be the only rejected report.
	elapsed = min(elapsed, maxSeedElapsedMS)
	// A rare impossible report, so the rejected-telemetry path (a dashed cell in
	// the Solve column, and the solve_time_implausible counter) is demoed too.
	if s.intn(100) == 0 {
		elapsed = 3_600_000
	}
	payload, _ := json.Marshal(map[string]any{
		"challenge_id": ch.ChallengeID,
		"nonce":        nonce,
		"elapsed_ms":   elapsed,
	})
	s.do(http.MethodPost, "/__guardian/pass", host, uri, ip, ua, payload)
}

// scanner probes rule-matching paths from a small IP pool. The starter
// rules deny most of these and block a couple, and the repeats push offenders
// over the behavioural threshold.
func (s *seeder) scanner() { s.scan(s.clientIP("203.0.113", 60)) }

func (s *seeder) scan(ip string) {
	for range 1 + s.intn(3) {
		s.do(http.MethodGet, "/auth", s.pick(hosts), s.pick(badPaths), ip, s.pick(badUAs), nil)
	}
}

func main() {
	base := flag.String("url", "http://127.0.0.1:8071", "guardiand hot-path base URL")
	admin := flag.String("admin", "", "admin base URL; set with -token to print a summary at the end")
	token := flag.String("token", "", "admin bearer token, for the summary")
	duration := flag.Duration("d", 2*time.Minute, "how long to keep seeding")
	pause := flag.Duration("pause", 4*time.Second, "delay between rounds; spreads traffic over the charts' time axis")
	allowHost := flag.String("allow-host", "plain.test", "host with proof of work disabled, used for allowed traffic")
	seed := flag.Int64("seed", 1, "RNG seed, for a reproducible mix")
	flag.Parse()

	s := &seeder{
		base:      strings.TrimRight(*base, "/"),
		allowHost: *allowHost,
		rng:       rand.New(rand.NewSource(*seed)),
		client: &http.Client{
			Timeout: 15 * time.Second,
			// Never follow the challenge redirect: each leg is driven explicitly.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	if code, _ := s.do(http.MethodGet, "/healthz", "", "/healthz", "127.0.0.1", "seed", nil); code != http.StatusOK {
		fmt.Fprintf(os.Stderr, "seed: %s/healthz did not answer (got %d); is guardiand running?\n", s.base, code)
		os.Exit(1)
	}

	// A hand-placed admin block on an address that sends no traffic, so the
	// blocks table shows the manual kind and the IP lookup has a blocked-but-
	// quiet address to demo. Best-effort: seeding works without admin access.
	if *admin != "" && *token != "" {
		placeManualBlock(strings.TrimRight(*admin, "/"), *token)
	}

	deadline := time.Now().Add(*duration)
	for round := 1; time.Now().Before(deadline); round++ {
		var wg sync.WaitGroup
		spawn := func(fn func()) { wg.Go(fn) }

		// Legitimate visitors solving the proof of work.
		for range 9 + s.intn(6) {
			spawn(func() {
				s.visitor(s.pick(hosts), s.pick(paths), s.clientIP("198.51.100", 220), s.pick(uas), true, true)
			})
		}
		// Visitors that abandon the interstitial: issued stays above solved.
		for range 2 + s.intn(3) {
			spawn(func() {
				s.visitor(s.pick(hosts), s.pick(paths), s.clientIP("198.51.100", 220), s.pick(uas), false, false)
			})
		}
		// A bot submitting a bad nonce every few rounds: the "failed" leg.
		if round%3 == 0 {
			spawn(func() {
				s.visitor(hosts[0], "/", s.clientIP("203.0.113", 200), s.pick(badUAs), true, false)
			})
		}
		// Scanners: denies plus behavioural blocks.
		for range 3 + s.intn(4) {
			spawn(s.scanner)
		}
		// The star offender probes every round, so the IP lookup demo has an
		// address with a deep decision history.
		spawn(func() { s.scan(starOffender) })
		// Traffic from the demo reputation feed's range: reputation denies,
		// and feed-hit chips on those IPs in the lookup.
		for range 1 + s.intn(2) {
			spawn(func() {
				s.do(http.MethodGet, "/auth", s.pick(hosts), s.pick(paths),
					s.feedIP(), s.pick(uas), nil)
			})
		}
		// Crawlers falling into a honeypot trap: an instant deny plus a block.
		for range 1 + s.intn(2) {
			spawn(func() {
				s.do(http.MethodGet, "/auth", s.pick(hosts), s.pick(honeypotPaths),
					s.clientIP("198.18.0", 90), s.pick(badUAs), nil)
			})
		}
		// Traffic from the statically denied range: terminal denylist hits.
		for range 1 + s.intn(3) {
			spawn(func() {
				s.do(http.MethodGet, "/auth", s.pick(hosts), s.pick(paths),
					s.denylistIP(), s.pick(uas), nil)
			})
		}
		// Plain allowed traffic, so per-domain totals carry a green allow band.
		for range 6 + s.intn(8) {
			spawn(func() {
				s.do(http.MethodGet, "/auth", s.allowHost, s.pick(paths),
					s.clientIP("192.0.2", 200), s.pick(uas), nil)
			})
		}

		wg.Wait()
		fmt.Printf("round %d (%s left)\n", round, time.Until(deadline).Truncate(time.Second))
		if time.Now().Before(deadline) {
			time.Sleep(*pause)
		}
	}

	if *admin != "" && *token != "" {
		printSummary(strings.TrimRight(*admin, "/"), *token)
	}
}

// placeManualBlock puts an admin block on manualBlockIP, reusing the same
// endpoint the dashboard's block form calls.
func placeManualBlock(admin, token string) {
	req, err := http.NewRequest(http.MethodPut, admin+"/admin/blocks/"+manualBlockIP,
		strings.NewReader(`{"reason":"manual: abuse report","ttl":"45m"}`))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: manual block not placed: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "seed: manual block not placed: status %d\n", resp.StatusCode)
	}
}

// printSummary reads the rollup back so a run ends with proof of what it
// produced, rather than the operator having to go look.
func printSummary(admin, token string) {
	req, err := http.NewRequest(http.MethodGet, admin+"/admin/stats", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: summary unavailable: %v\n", err)
		return
	}
	defer resp.Body.Close()
	var stats struct {
		BlocksActive int `json:"blocks_active"`
		Recent       struct {
			Total    int            `json:"total"`
			ByAction map[string]int `json:"by_action"`
			ByReason map[string]int `json:"by_reason"`
		} `json:"recent"`
		Challenges map[string]float64 `json:"challenges"`
	}
	if json.NewDecoder(resp.Body).Decode(&stats) != nil {
		return
	}
	fmt.Println("\n--- seeded ---")
	fmt.Printf("active blocks   %d\n", stats.BlocksActive)
	fmt.Printf("recent window   %d decisions %v\n", stats.Recent.Total, stats.Recent.ByAction)
	fmt.Printf("by reason       %v\n", stats.Recent.ByReason)
	if c := stats.Challenges; c != nil {
		fmt.Printf("proof of work   issued %.0f, solved %.0f, failed %.0f",
			c["issued"], c["solved"], c["failed"])
		if avg, ok := c["avg_solve_seconds"]; ok {
			fmt.Printf(", avg %.1fs", avg)
		}
		fmt.Println()
	}
	fmt.Printf("ip lookup demo  %s/admin/dashboard?ip=%s (repeat offender)\n", admin, starOffender)
	fmt.Printf("                %s/admin/dashboard?ip=%s (manual block, quiet)\n", admin, manualBlockIP)
}
