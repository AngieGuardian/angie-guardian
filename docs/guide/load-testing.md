# Load Testing

`guardian-loadtest` drives the `/auth` hot path the way Angie does, over
keepalive connections, and reports throughput + latency percentiles. Run it
before relying on a deployment near its throughput budget.

## Scenarios

`allow` and `token` are read-dominated; the [block mirror](/guide/block-offload)
removes even that read on the embedded backends. A static denylist match
terminates before the store. `challenge` is the write-heavy path (the only one
whose throughput depends on the store backend) unless
[attack mode](/guide/attack-mode) has switched issuance to the stateless path.

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | none on the embedded backends (`memory`/`buntdb`/`pebble`) once the mirror is seeded; 1 read on `redis` (read-through for cross-replica blocks) |
| `token` | solve one PoW challenge, then hammer `/auth` with the cookie (the production common path) | same as `allow` |
| `deny` | denylisted client IP (deny + decision logging path) | none |
| `challenge` | issue a fresh PoW challenge per request | normally 1 synchronous **write** (CAS), plus coalesced background counter increments; under attack mode, or when that stateful write fails, issuance is stateless (no write at issue, the single-spend write moves to redemption) |

## Run it

```sh
# Plain allow path (full pipeline). Use a host WITHOUT PoW (the scenario
# expects 200s; a PoW-on host would answer 401 challenge instead).
guardian-loadtest -url http://127.0.0.1:8071 -scenario allow -host api.example.com -c 64 -d 10s

# Production common path: solve one real challenge, then hammer with the cookie.
guardian-loadtest -scenario token -host example.com -c 128 -d 10s

# Static deny path; the IP must appear in this host's denylist.
guardian-loadtest -scenario deny -host example.com -ip 203.0.113.9 -c 64 -d 10s

# Write path (requires PoW enabled): one synchronous challenge CAS per request;
# per-IP counters are counted in-process and flushed to the store in background.
guardian-loadtest -scenario challenge -host example.com -c 64 -d 10s

# Stateless issuance (the attack-mode path): pin the posture first, then rerun
# the challenge scenario to measure the store-free issuance ceiling.
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"level":"attack"}' http://127.0.0.1:8072/admin/attack
guardian-loadtest -scenario challenge -host example.com -c 64 -d 10s
```

::: tip Use a distinct -ip per read run
A behavioural block from one run can bleed into the next. The `challenge`
scenario rotates the client IP itself to dodge the per-IP issuance limit.
:::

## Benchmark results

Single node, loopback, 64 connections, load generator sharing the same CPU
(AMD Ryzen Threadripper 7960X, 24C/48T; Go 1.25; Valkey 9 for the redis backend;
fresh daemon per run). Each cell is **throughput / p50 / p99** (req/s and
per-request latency):

| Backend | allow | token | deny | challenge (write) |
|---|---|---|---|---|
| `memory` (ephemeral)              | 169k / 0.15ms / 1.8ms | 159k / 0.21ms / 1.7ms | 150k / 0.14ms / 2.4ms | **156k / 0.29ms / 1.7ms** |
| `pebble` (async, default durable) | 177k / 0.14ms / 1.7ms | 154k / 0.21ms / 1.8ms | 152k / 0.14ms / 2.4ms | **39k / 0.73ms / 20ms** |
| `pebble` (sync, fully durable)    | 172k / 0.14ms / 1.8ms | 155k / 0.21ms / 1.8ms | 152k / 0.14ms / 2.4ms | **25k / 2.6ms / 7.5ms** |
| `buntdb` (async, single-file)     | 175k / 0.14ms / 1.7ms | 153k / 0.23ms / 1.8ms | 150k / 0.14ms / 2.4ms | **36k / 1.3ms / 17ms** |
| `redis`·`valkey` (fleet)          | 96k / 0.62ms / 1.4ms  | 94k / 0.63ms / 1.4ms  | 162k / 0.13ms / 2.3ms | **34k / 1.2ms / 21ms** |

Read paths comfortably clear a 50k req/s budget on every backend: the
[block mirror](/guide/block-offload) makes the embedded stores authoritative, so
the per-request store read is gone on allow/token (redis keeps one read for
cross-replica correctness, so its reads land lower). The takeaway is the
**write** path: each issued
challenge writes one CAS record. The durable LSM/append-only backends absorb
this far better than a synchronously-fsync'd single writer (`pebble` ~39k/s
async, ~25k/s fully durable; `buntdb` ~36k/s async), and
[attack mode](/guide/attack-mode)'s stateless issuance lifts it further by
deferring the only write to redemption. (`buntdb` + `sync: true` is rejected at
startup: its single writer makes fsync-per-commit ~100x slower, so use `pebble`
for synchronous durability.) The per-IP rate-limit and
[farming-escalation](/guide/configuration#base-difficulty-and-max-difficulty)
counters do not add write rounds: they are counted in-process and synced to
the shared store in the background. See
[choosing a store backend](/guide/production#choosing-a-store-backend).

::: tip The block check is now off the store
With the [in-process mirror](/guide/block-offload) (always on), the behavioural
block lookup on the `allow` path no longer reads the store on the embedded
backends. In the `core` micro-benchmarks the seeded authoritative mirror takes
the full allow path from ~1600 ns to ~160 ns per `Evaluate` (about 10x), and a
request from an already-blocked IP is denied in ~590 ns with zero store I/O.
That is what keeps a flood from known-bad clients cheap; run
`go test -bench BenchmarkEvaluatePebbleMirror ./core/` to reproduce.
:::

## Micro-benchmarks

Performance-sensitive hot paths (`Evaluate`, PoW verification, anomaly
scoring) carry Go benchmarks alongside the code:

```sh
go test -bench=. -benchmem ./core/... ./core/pow/...
```

All `guardian-loadtest` flags are listed in the
[CLI reference](/reference/cli#guardian-loadtest).
