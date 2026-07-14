# Load Testing

`guardian-loadtest` drives the `/auth` hot path the way Angie does, over
keepalive connections, and reports throughput + latency percentiles. Run it
before relying on a deployment near its throughput budget.

## Scenarios

`allow` and `token` are read-dominated (one block lookup each); a static
denylist match terminates before the store. `challenge` is the write-heavy path where bbolt's
single embedded writer trails redis/valkey.

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | 1 read (block lookup) |
| `token` | solve one PoW challenge, then hammer `/auth` with the cookie (the production common path) | 1 read |
| `deny` | denylisted client IP (deny + decision logging path) | none |
| `challenge` | issue a fresh PoW challenge per request | 1 synchronous **write** (CAS), plus coalesced background counter increments |

## Run it

```sh
# Plain allow path (full pipeline).
guardian-loadtest -url http://127.0.0.1:8071 -scenario allow -host example.com -c 64 -d 10s

# Production common path: solve one real challenge, then hammer with the cookie.
guardian-loadtest -scenario token -host example.com -c 128 -d 10s

# Static deny path; the IP must appear in this host's denylist.
guardian-loadtest -scenario deny -host example.com -ip 203.0.113.9 -c 64 -d 10s

# Write path (requires PoW enabled): one synchronous challenge CAS per request;
# per-IP counters are counted in-process and flushed to the store in background.
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
| allow     | ~78k / 0.50 ms / 3.4 ms  | ~92k / 0.64 ms / 1.5 ms |
| token     | ~71k / 0.54 ms / 3.9 ms  | ~90k / 0.65 ms / 1.6 ms |
| deny      | ~124k / 0.35 ms / 2.5 ms | ~186k / 0.12 ms / 1.8 ms |
| challenge (write) | **~4.1k / 16 ms / 19 ms** | **~26k / 2.3 ms / 4.7 ms** |

Read paths comfortably clear a 50k req/s budget on both backends. The
takeaway is the **write** path: each issued challenge writes its issuance
record through embedded bbolt's single fsync'd writer, while redis/valkey
sustains ~6x its throughput. The per-IP rate-limit and
[farming-escalation](/guide/configuration#base-difficulty-and-max-difficulty)
counters do not add write rounds: they are counted in-process and synced to
the shared store in the background. See
[choosing a store backend](/guide/production#choosing-a-store-backend).

## Micro-benchmarks

Performance-sensitive hot paths (`Evaluate`, PoW verification, anomaly
scoring) carry Go benchmarks alongside the code:

```sh
go test -bench=. -benchmem ./core/... ./core/pow/...
```

All `guardian-loadtest` flags are listed in the
[CLI reference](/reference/cli#guardian-loadtest).
