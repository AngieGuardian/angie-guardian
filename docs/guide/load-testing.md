# Load Testing

`guardian-loadtest` drives Guardian's HTTP hot paths directly, or the complete
refusal route through Angie, over keepalive connections. It reports throughput
and latency percentiles. Run it before relying on a deployment near its
throughput budget.

It does not model partial TLS handshakes, slow HTTP/1.1 clients, HTTP/2 stream
resets, or file-descriptor recovery. Those are Angie's protocol layer. Run the
real-stack [Angie validation and soak](/guide/angie-hardening#validate-and-soak)
for that separate question.

For a repeatable operational exercise that combines these measurements with
attack pinning, origin-impact checks, sidecar faults, false-positive probes,
and cleanup, use the [DDoS drill](/guide/ddos-drill).

## Scenarios

`allow`, `token`, and the `/auth` half of `refuse` are read-dominated; the
[block mirror](/guide/block-offload) removes even that read on the embedded
backends. A static denylist match terminates before the store. `challenge` is
the write-heavy path (the only one whose throughput depends on the store
backend) unless [attack mode](/guide/attack-mode) has switched issuance to the
stateless path.

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | none on the embedded backends (`memory`/`buntdb`/`pebble`) once the mirror is seeded; 1 read on `redis` (read-through for cross-replica blocks) |
| `token` | solve one PoW challenge, then hammer `/auth` with the cookie (the production common path) | same as `allow` |
| `deny` | denylisted client IP (deny + decision logging path) | none |
| `challenge` | issue a fresh PoW challenge per request | normally 1 synchronous **write** (CAS), plus coalesced background counter increments; under attack mode, or when that stateful write fails, issuance is stateless (no write at issue, the single-spend write moves to redemption) |
| `refuse-auth` | directly measure `/auth` recording `ActionRefuse` and returning the 401 Angie routes onward | same as `allow` |
| `refuse-challenge` | directly measure `/challenge` consuming the relayed refusal verdict and returning its small 403 | none |
| `refuse-angie` | send one original request through Angie's real `/auth` → `@guardian_challenge` → 403 route | combines the two Guardian hops above |

## Run it

```sh
# Plain allow path (full pipeline). Use a host WITHOUT PoW (the scenario
# expects 200s; a PoW-on host would answer 401 challenge instead).
guardian-loadtest -url http://127.0.0.1:8071 -scenario allow -host api.example.com -c 64 -d 10s

# Production common path: solve one real challenge, then hammer with the cookie.
guardian-loadtest -scenario token -host example.com -c 128 -d 10s

# Static deny path; the IP must appear in this host's denylist.
guardian-loadtest -scenario deny -host example.com -ip 203.0.113.9 -c 64 -d 10s

# Refusal split: the two Guardian subrequests made for one refused client
# request. Accept: */* and the browser UA are supplied by these scenarios.
guardian-loadtest -scenario refuse-auth      -host example.com -c 64 -warmup 50000 -n 500000
guardian-loadtest -scenario refuse-challenge -host example.com -c 64 -warmup 50000 -n 500000

# Optional topology measurement: point -url at Angie's public listener. This
# counts original client requests, each of which makes both Guardian hops.
# Angie supplies the real connection address, so -ip does not apply here.
guardian-loadtest -scenario refuse-angie -url http://127.0.0.1:8080 -host example.com -c 64 -warmup 50000 -n 500000

# Write path (requires PoW enabled): one synchronous challenge CAS per request;
# per-IP counters are counted in-process and flushed to the store in background.
# Use FIXED WORK (-warmup/-n), not a duration: every request grows the store and
# the counter caches, so throughput falls as the run proceeds and a duration
# average depends on machine speed and run length. The warmup pushes both
# 131k-entry counter caches past capacity, so the measured window is the loaded
# steady state that matters under a flood, and the same flags on two machines
# or two commits measure the same work.
guardian-loadtest -scenario challenge -host example.com -c 64 -warmup 150000 -n 150000

# Stateless issuance (the attack-mode path): pin the posture first, then rerun
# the challenge scenario to measure the store-free issuance ceiling.
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"level":"attack"}' http://127.0.0.1:8072/admin/attack
guardian-loadtest -scenario challenge -host example.com -c 64 -warmup 150000 -n 150000
```

::: tip Use a distinct -ip per read run
A behavioural block from one run can bleed into the next. The `challenge`
scenario rotates the client IP itself to dodge the per-IP issuance limit.
:::

::: warning Duration soaks need a test-only limiter override
A multi-million-request challenge soak eventually exceeds CounterCache's
bounded exact-key capacity. Its overload sketch then becomes deliberately
conservative, and collisions start testing the per-IP issuance limiter rather
than Pebble endurance. For that soak only, use a temporary config with a very
high `pow.issuance_rate_limit`; never carry that setting into production. The
fixed-work comparison above does not need an override.
:::

Every run ends with a `per-second:` line, one measured-completion count per
second. Read it before trusting the aggregate: a flat line is a steady state,
a falling line means the run was measuring store growth and only a fixed-work
(`-n`) comparison against another machine or commit is meaningful.

The refusal scenarios also validate the headers that identify the intended
route. Treat any non-zero `unexpected-status` or `unexpected-contract` count as
an invalid run, even if its throughput looks plausible.

## Benchmark results

Methodology, recorded here because the numbers are meaningless without it:
single node, native binaries over loopback, 64 connections, load generator
sharing the same CPU (AMD Ryzen Threadripper 7960X, 24C/48T; Linux 6.17 for the
existing non-Pebble rows and Linux 7.0.0 for the refreshed Pebble and refusal
rows; Go 1.26.5; Valkey 9 for the redis backend; fresh daemon and store per run;
median of 3 runs per cell).
Reads use `-warmup 50000 -n 500000`; **challenge uses
`-warmup 150000 -n 150000`**, pushing both 131k-entry counter caches past
capacity so the measured window is the loaded steady state a sustained flood of
new clients actually produces, not the fast cold start of an empty store. Each
cell is **throughput / p50 / p99** (req/s and per-request latency):

A separate Docker + Angie comparison found that a Unix-socket Guardian
upstream has less local transport overhead than loopback TCP. With
`keepalive 64`, it delivered about 3% more throughput on the two-hop
`refuse-angie` route and about 1.5% more on an allowed request through the
backend. The exact gain is deployment-specific, but Unix sockets are the
slightly faster same-host option.

| Backend | allow | token | deny | refuse auth | refuse 403 | challenge write |
|---|---|---|---|---|---|---|
| `memory` (ephemeral)              | 180k / 0.13ms / 1.8ms | 173k / 0.16ms / 1.7ms | 157k / 0.14ms / 2.3ms | 172k / 0.15ms / 1.8ms | 179k / 0.15ms / 1.7ms | **160k / 0.29ms / 1.6ms** |
| `pebble` (async, default durable) | 185k / 0.14ms / 1.7ms | 172k / 0.15ms / 1.8ms | 188k / 0.13ms / 1.7ms | 173k / 0.15ms / 1.8ms | 180k / 0.15ms / 1.7ms | **152k / 0.32ms / 1.6ms** |
| `pebble` (sync, fully durable)    | 183k / 0.14ms / 1.7ms | 172k / 0.15ms / 1.8ms | 189k / 0.14ms / 1.7ms | 174k / 0.15ms / 1.8ms | 178k / 0.15ms / 1.7ms | **35k / 1.5ms / 5.1ms** |
| `buntdb` (async, single-file)     | 182k / 0.13ms / 1.8ms | 170k / 0.14ms / 1.8ms | 155k / 0.13ms / 2.4ms | 179k / 0.16ms / 1.7ms | 173k / 0.14ms / 1.8ms | **56k / 1.2ms / 4.8ms** |
| `redis`·`valkey` (fleet)          | 94k / 0.64ms / 1.3ms  | 93k / 0.64ms / 1.4ms  | 162k / 0.13ms / 2.3ms | 97k / 0.62ms / 1.4ms | 184k / 0.15ms / 1.7ms | **49k / 1.2ms / 2.5ms** |

Refusal is a two-hop production route, so the direct measurements remain
separate columns: `refuse auth` is the `/auth` record + 401, while `refuse 403`
is the small `/challenge` response.

The `/auth` hop evaluates and records the refusal, updates decision metrics,
and calls the decision logger (suppressed at the measured production-default
`warn` level). The `/challenge` hop trusts the relayed refusal kind, increments
the refusal outcome metric, and returns a plain-text 403. It does not render
HTML or issue/store a challenge. The direct `/auth` refusal outpaced direct
stateful challenge issuance on every measured backend, especially those
limited by synchronous writes.

Do **not** add the two direct rates or report either as client-facing capacity.
One original request through Angie makes both Guardian subrequests and also
pays Angie's routing and HTTP overhead. `refuse-angie` exists to measure that
topology on the deployment being evaluated; the table deliberately makes no
unmeasured DDoS-capacity claim.

Read paths comfortably clear a 50k req/s budget on every backend: the
[block mirror](/guide/block-offload) makes the embedded stores authoritative,
so the per-request store read is gone on allow/token (redis keeps one read for
cross-replica correctness, so its reads land lower). The takeaway is the
**write** path, one CAS record per issued challenge. The durable
LSM/append-only backends absorb it far better than a synchronously-fsync'd
single writer (`pebble` ~152k/s async, ~35k/s fully durable; `buntdb` ~56k/s
async; `buntdb` + `sync: true` is rejected at startup, since its single writer
makes fsync-per-commit ~100x slower, so use `pebble` for synchronous
durability), and [attack mode](/guide/attack-mode)'s stateless issuance lifts
it further by deferring the only write to redemption. The per-IP rate-limit and
[farming-escalation](/guide/configuration#base-difficulty-and-max-difficulty)
counters add no store write *rounds* on the request path: they are counted
in-process and synced to the shared store in the background. See
[choosing a store backend](/guide/production#choosing-a-store-backend).

::: tip The block check is off the store
With the [in-process mirror](/guide/block-offload) (always on), the behavioural
block lookup on the `allow` path does not read the store on the embedded
backends. In the `core` micro-benchmarks the seeded authoritative mirror takes
the full allow path on pebble from ~140 ns (one bloom-filtered store read per
request) to ~70 ns per `Evaluate`, and a request from an already-blocked IP is
denied in ~0.5 µs with zero store I/O. That is what keeps a flood from
known-bad clients cheap; run
`go test -bench BenchmarkEvaluatePebbleMirror ./core/` to reproduce.
:::

## Micro-benchmarks

Every performance-sensitive layer carries Go benchmarks alongside the code:

```sh
go test -bench=. -benchmem ./core/... ./transport/http/
```

| Package | Covers |
| --- | --- |
| `core` | `Evaluate` per verdict (default allow, static allow/deny, valid token, challenge), with and without the block mirror; a clean request scanned against a realistic rule set; `ShedDecision` |
| `transport/http` | the `/auth` handler end to end per verdict, `requestContext` on its own (the header reads and the request value built before any policy runs), and `/challenge` issuance with a never-repeating client IP |
| `core/pow` | token verification (cached and uncached) and challenge issuance |
| `core/store` | the store engines on Guardian's real write workload (see `make bench-store`) |
| `core/anomaly` | the online scorer |

Each `Evaluate` benchmark builds a **fresh** request per iteration, matching
what the transport does. That matters: a request memoizes its normalized path
and lowercased User-Agent on first use, so reusing one value across iterations
would measure a request that had already paid for them.

### Reading the two together

The micro-benchmarks and `guardian-loadtest` answer different questions, and
the gap between them is the useful part. On loopback at ~180k req/s the daemon
spends roughly **70–80 µs of CPU per request**, while the decision itself is
well under a microsecond: almost all of that is the kernel and `net/http`, not
Guardian. So a change that makes the decision path several times cheaper moves
the end-to-end request rate by only a few percent.

Measure it as CPU per request rather than req/s when you want to see the
difference: on a loopback test the load generator shares the CPU with the
daemon, so freed cycles show up partly as generator headroom. In a real
deployment they go to Angie and your backend instead.

### Comparing two commits

Three tiers, cheapest and most reliable first:

1. **`make bench-regress`**: the hot-path benchmarks at a fixed iteration
   count, compared against the committed baselines in `allocs-baseline.txt`.
   This runs as a CI job, so a commit that adds an allocation to the auth or
   challenge hot path fails its pipeline in seconds. When a change legitimately
   needs an allocation, raise the baseline in the same commit and say why.

   Only benchmarks free of **background goroutines** can be gated: one that
   spawns them is charged their allocations too, at a rate the scheduler
   decides, so its count moves with core count. `BenchmarkChallengeIssue`
   drives `CounterCache` and swings between 28 and 36 allocs/op on GOMAXPROCS
   alone, so it stays a profiling benchmark while `BenchmarkIssue` gates the
   deterministic core of the same path. Check a candidate holds steady across
   `GOMAXPROCS=1,2,4,8` before adding it.

   The gate covers `allocs/op` only, so it can miss a real regression: growing
   a per-request struct past an allocator size class costs every request more
   memory while the allocation *count* never moves. `make bench-report` shows
   the `B/op` column the gate does not, summarized across several runs
   (`296.0 ± 0%`); it stays reported rather than gated because at the gate's
   fixed iteration count `B/op` still carries per-P setup cost that varies
   with core count, making it manual and machine-specific.
2. **CPU per request**: run one `guardian-loadtest` scenario against each
   build and divide the daemon's `utime+stime` by the completed requests. A few
   percent of noise on a pinned machine; measures the whole daemon, not just
   the decision.
3. **Throughput**: only with fixed work (`-n`, plus `-warmup` for the
   challenge scenario), only comparing runs with identical flags, and only
   after checking the `per-second:` line was flat. A duration-mode average of
   the write path is not comparable across anything.

All `guardian-loadtest` flags are listed in the
[CLI reference](/reference/cli#guardian-loadtest).
