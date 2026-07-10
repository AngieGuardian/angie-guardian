# Load Testing

`guardian-loadtest` drives the `/auth` hot path the way Angie does, over
keepalive connections, and reports throughput + latency percentiles. Run it
before relying on a deployment near its throughput budget.

## Scenarios

The first three are read-dominated (one block lookup each) and behave the same
on any backend; `challenge` is the one write-heavy path and is where bbolt's
single embedded writer trails redis/valkey.

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | 1 read (block lookup) |
| `token` | solve one PoW challenge, then hammer `/auth` with the cookie (the production common path) | 1 read |
| `deny` | denylisted client IP (deny + decision logging path) | 1 read |
| `challenge` | issue a fresh PoW challenge per request | 1 **write** (CAS) |

## Run it

```sh
# Plain allow path (full pipeline).
guardian-loadtest -url http://127.0.0.1:8071 -scenario allow -host example.com -c 64 -d 10s

# Production common path: solve one real challenge, then hammer with the cookie.
guardian-loadtest -scenario token -host example.com -c 128 -d 10s

# Worst case: a denylisted client (exercises the deny + logging path).
guardian-loadtest -scenario deny -host example.com -ip 203.0.113.9 -c 64 -d 10s

# Write path: issue a fresh PoW challenge per request (two store writes each:
# the challenge CAS + the per-IP farming-escalation counter).
guardian-loadtest -scenario challenge -host example.com -c 64 -d 10s
```

::: tip Use a distinct -ip per read run
A behavioural block from one run can bleed into the next. The `challenge`
scenario rotates the client IP itself to dodge the per-IP issuance limit.
:::

## Reference numbers

Single node, loopback, 64 connections, load generator sharing the same CPU
(AMD Ryzen Threadripper 7960X, 24C/48T; Go 1.25; Valkey 9 for the redis
backend). Numbers are req/s and per-request latency:

| Scenario | bbolt (throughput / p50 / p99) | redis · valkey (throughput / p50 / p99) |
|---|---|---|
| allow     | ~79k / 0.49 ms / 3.3 ms  | ~92k / 0.64 ms / 1.5 ms |
| token     | ~71k / 0.55 ms / 3.8 ms  | ~90k / 0.65 ms / 1.5 ms |
| deny      | ~125k / 0.35 ms / 2.4 ms | ~182k / 0.12 ms / 1.8 ms |
| challenge (write) | **~1.6k / 40 ms / 42 ms** | **~25k / 2.5 ms / 4.1 ms** |

Read paths comfortably clear a 50k req/s budget on both backends. The
takeaway is the **write** path: each issued challenge carries two store
writes (the challenge CAS plus the per-IP
[farming-escalation](/guide/configuration#base-difficulty-and-max-difficulty)
counter), and embedded bbolt fsyncs those transactions through a single
writer, while redis/valkey sustains ~15x its throughput. See
[choosing a store backend](/guide/production#choosing-a-store-backend).

## Micro-benchmarks

Performance-sensitive hot paths (`Evaluate`, PoW verification, anomaly
scoring) carry Go benchmarks alongside the code:

```sh
go test -bench=. -benchmem ./core/... ./core/pow/...
```

All `guardian-loadtest` flags are listed in the
[CLI reference](/reference/cli#guardian-loadtest).
