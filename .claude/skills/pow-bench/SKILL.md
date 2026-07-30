---
name: pow-bench
description: Measure SHA-256 hashrates (browser JS and native Go) to calibrate PoW difficulty for angie-guardian. Use when tuning base_difficulty/max_difficulty, estimating client solve times, comparing crypto.subtle vs pure-JS solver speed, or reasoning about how much a native attacker outpaces a browser.
---

# PoW hashrate benchmarks

Tools for answering "how long does a client take to solve a difficulty-d challenge, and how much cheaper is it for a native attacker?" Both artifacts live in this skill directory; they were originally built in a session scratchpad and preserved here so they survive across sessions and models.

## The math

Config difficulty `d` requires `4*d` leading zero BITS in the SHA-256, in quarter steps: +0.25 = 1 bit = 2x work, +1 = 16x (see USAGE.md, "base_difficulty and max_difficulty"). Expected attempts to solve = `2^(4d)` = `16^d`, so:

    expected solve time (s) = 16^d / hashrate (H/s)

To pick a difficulty, measure the slowest browser rate you care about and check `16^d / rate` stays tolerable (a second or two), then check the same `d` against the native Go rate to see what it costs an attacker. Solve time is exponentially distributed: ~5% of visitors wait 3x the mean.

## pow-bench.html (browser side)

Self-contained page, no external resources. Open it in any browser (file:// works, or via the chrome-devtools MCP tools) and read the JSON in the `<pre>` or from `window.__benchResult`. It reports:

- `ok` / `errors`: the bundled pure-JS SHA-256 (FIPS 180-4) is verified against `crypto.subtle` on assorted input lengths first; ignore the rates if `ok` is false.
- `subtleRate`: hashes/sec of one awaited `crypto.subtle.digest` per nonce. This was the production solver shape until 2026-07-09; kept for comparison.
- `jsRate`: hashes/sec of a synchronous pure-JS loop. This IS the shipped interstitial solver shape since 2026-07-09 (web/challenge.html.tmpl runs the same FIPS 180-4 JS in up to 8 workers, so whole-page throughput is roughly `jsRate * min(cores, 8)`). Measured 2026-07-09 on Melroy's desktop (Chrome, 48 threads): jsRate ~1.1 MH/s single, ~9 MH/s with 8 workers; subtleRate ~140 kH/s; native Go ~7.6 MH/s/core.

Re-measured 2026-07-30, same desktop, both engines: Chrome 151 jsRate 960 kH/s (~7.7 MH/s at the cap), subtleRate 258 kH/s; Firefox 153 jsRate 552-559 kH/s over two runs (~4.4 MH/s at the cap), subtleRate 87 kH/s. **Firefox is ~1.75x slower than Chrome on the JS solver and ~3x slower on subtle**, on identical hardware, so quote the browser with every rate. Cross-checked against production: seven real 22-bit solves in Firefox averaged 1.31 s against the 0.95 s this bench predicts, the gap being worker spawn plus ~1,000 progress postMessages, and well inside the 38% standard error of an exponential mean at n=7.
- `hardwareConcurrency`, `userAgent`: context for recording results.

Note the pure-JS digest assumes ASCII input up to 246 bytes (single-buffer padding); that matches challenge+nonce shapes, do not feed it arbitrary data.

## hashrate_test.go (native attacker side)

Single Go benchmark measuring `sha256.Sum256(challenge + itoa(nonce))`, the exact per-attempt work of a native solver. Run it from a throwaway module dir (it is intentionally NOT part of the main module, keep it out of `go.mod`):

    d=$(mktemp -d) && cp .claude/skills/pow-bench/hashrate_test.go "$d" \
      && (cd "$d" && go mod init bench >/dev/null && go test -bench . -benchtime 2s)

ns/op converts to hashrate as `1e9 / ns_per_op` H/s. Compare against `subtleRate`/`jsRate` to quantify the browser-vs-native gap.

## Interpreting results

- Judge visitor experience by `jsRate * min(cores, 8)` (the shipped solver is the parallel pure-JS worker pool).
- The attacker advantage is `nativeRate * attackerCores / (jsRate * min(cores, 8))`; PoW is a cost multiplier, not a wall, so pair it with the WAF/anomaly scoring rather than cranking difficulty until browsers suffer.
- Record measured rates with the machine and browser they came from; they vary wildly across devices, and low-end phones are the real constraint on `base_difficulty`.
