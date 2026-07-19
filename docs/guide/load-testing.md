# Load Testing

`guardian-loadtest` drives the `/auth` hot path the way Angie does, over
keepalive connections, and reports throughput + latency percentiles. Run it
before relying on a deployment near its throughput budget.

## Scenarios

`allow` and `token` are read-dominated; the [block mirror](/guide/block-offload)
removes even that read on single-writer backends. A static denylist match
terminates before the store. `challenge` is the write-heavy path where bbolt's
single embedded writer trails redis/valkey, unless
[attack mode](/guide/attack-mode) has switched issuance to the stateless path.

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | none on `bbolt`/`memory` once the mirror is seeded; 1 read on `redis` (read-through for cross-replica blocks) |
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

## Reference numbers

Single node, loopback, 64 connections, load generator sharing the same CPU
(AMD Ryzen Threadripper 7960X, 24C/48T; Go 1.25; Valkey 9 for the redis
backend; fresh daemon per run). Numbers are req/s and per-request latency:

| Scenario | bbolt (throughput / p50 / p99) | redis · valkey (throughput / p50 / p99) |
|---|---|---|
| allow     | ~161k / 0.19 ms / 1.8 ms | ~78k / 0.77 ms / 1.7 ms |
| token     | ~135k / 0.34 ms / 1.9 ms | ~77k / 0.78 ms / 1.8 ms |
| deny      | ~125k / 0.41 ms / 1.8 ms | ~151k / 0.24 ms / 1.8 ms |
| challenge (write) | **~4.5k / 14 ms / 16 ms** | **~21k / 1.5 ms / 33 ms** |
| challenge, attack mode (stateless) | ~44k / 0.27 ms / 18 ms | ~26k / 0.38 ms / 25 ms |

Read paths comfortably clear a 50k req/s budget on both backends. On
single-writer backends the [block mirror](/guide/block-offload) removes the
per-request store read entirely, which is why bbolt now out-reads the
networked store on allow/token; redis keeps one read per request for
cross-replica correctness. The takeaway is the **write** path: each issued
challenge writes its issuance record through embedded bbolt's single fsync'd
writer, while redis/valkey sustains ~5x its throughput, and
[attack mode](/guide/attack-mode)'s stateless issuance lifts the bbolt ceiling
an order of magnitude by deferring the only write to redemption. The per-IP
rate-limit and
[farming-escalation](/guide/configuration#base-difficulty-and-max-difficulty)
counters do not add write rounds: they are counted in-process and synced to
the shared store in the background. See
[choosing a store backend](/guide/production#choosing-a-store-backend).

::: tip The block check is now off the store
With the [in-process mirror](/guide/block-offload) (always on), the behavioural
block lookup on the `allow` path no longer reads the store on single-writer
backends. In the `core` micro-benchmarks the seeded authoritative mirror takes
the full bbolt allow path from ~1600 ns to ~160 ns per `Evaluate` (about 10x),
and a request from an already-blocked IP is denied in ~590 ns with zero store
I/O. That is what keeps a flood from known-bad clients cheap; run
`go test -bench BenchmarkEvaluateBoltMirror ./core/` to reproduce.
:::

## Micro-benchmarks

Performance-sensitive hot paths (`Evaluate`, PoW verification, anomaly
scoring) carry Go benchmarks alongside the code:

```sh
go test -bench=. -benchmem ./core/... ./core/pow/...
```

All `guardian-loadtest` flags are listed in the
[CLI reference](/reference/cli#guardian-loadtest).
