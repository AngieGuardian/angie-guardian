# Angie Guardian

A Web Application Firewall (WAF) and proof-of-work bot firewall for
[Angie](https://angie.software/), written in Go.

Guardian runs as a sidecar daemon next to Angie and is wired into the request
path with stock `auth_request` directives, so there is no custom Angie build
and no C module. Every request to a protected `server {}` block triggers a fast
internal subrequest to Guardian, which answers **allow**, **challenge**, or
**deny**.

## Features

Two cooperating subsystems sharing one config, one datastore, and one decision
pipeline. Everything is per-domain configurable.

1. **WAF layer**, runs on every request:
   - hot-reloadable keyword/regex threat signatures (RE2: no ReDoS by
     construction), matched against decoded path/query/User-Agent
   - behavioural IP blocking with exponential backoff (signature hits,
     PoW failures, tamper events)
   - honeypot trap paths: one hit = instant block
   - tamper-proof signed IDs (HMAC-bound to purpose + host)
   - statistical anomaly scoring: `guardian-train` learns per-domain
     baselines from Angie JSON access logs offline; the online scorer rates
     every request in ~260ns and drives challenge/deny + difficulty
     escalation (model artifact is versioned and hot-swapped, so an ML
     implementation can slot in behind the same seam later)

2. **Proof-of-Work challenge layer**, only for suspicious or new clients:
   - SHA-256 leading-zeros challenge with JS/WASM solver
   - Ed25519-signed JWT cookie on success; cheap re-validation afterwards
   - **persistent shared signing key**, so restarts don't log everyone out,
     and replicas behind a load balancer can share one key
   - spent-challenge tracking from day 1 (no mint-twice replay)
   - no-JS meta-refresh fallback

## Integration paths

Guardian offers two ways to run, sharing one decision core:

- **Sidecar (default, full-featured).** A Go daemon wired into Angie with
  stock `auth_request` directives. This is the complete implementation:
  proof-of-work, behavioural IP blocking, and anomaly scoring all require the
  shared store the sidecar owns. Start here.
- **WASM module (optional, stateless WAF).** The store-free checks (allowlist,
  denylist, honeypot, keyword/regex signatures) compiled to WebAssembly and run
  in-process inside Angie via its WASM support, for operators who prefer that
  integration. It is stateless WAF-only: proof-of-work, behavioural blocking,
  and anomaly scoring need the sidecar. Build it with `make wasm`; see the
  "WASM module" section of [USAGE.md](USAGE.md).

Both paths call the same store-free evaluator, so the WAF decisions are
identical; a vouched PoW token (sidecar only) never exempts a client from the
signature checks, so a stolen token can't ride past the WAF.

## Operations

- **Metrics**: Prometheus `/metrics` on the admin listener (open to
  scrapers): decisions by action/reason/domain, challenge lifecycle, PoW
  solve-time and anomaly-score histograms, blocks placed, store op latency,
  and end-to-end `Evaluate()` latency. Import `deploy/grafana-dashboard.json`.
- **Admin API**: bearer-token JSON API on the same listener: inspect/place/
  clear IP blocks, score a hypothetical request against the anomaly model
  (`GET /admin/score`), rotate the signing key, and view the active per-domain
  config. Refuses to expose itself on a non-loopback address without a token.
- **Key rotation**: `POST /admin/rotate-key` archives the current Ed25519
  key and generates a new one; tokens signed by the old key keep verifying
  until they expire, so rotation never logs anyone out.
- **Stores**: `memory` (dev), `bbolt` (single box), or `redis`/`valkey`
  (multi-instance replicas behind a load balancer, sharing blocks + spent
  challenges + the signing key).

## Testing

The full suite runs via `go test`. Unit tests cover every core package
(engine pipeline, PoW/JWT/key rotation, WAF rules + scoreboard + signed IDs,
anomaly scorer, all three stores) plus the HTTP `auth_request` and admin
transports, using `miniredis` for the redis backend so no external services
are required.

```sh
go test ./...            # whole suite
go test -race ./...      # with the race detector
go test ./core/...       # a subtree
go test -run TestEvaluate ./core   # a single test by name
```

Performance-sensitive hot paths (`Evaluate`, PoW verification, anomaly
scoring) also carry benchmarks:

```sh
go test -bench=. -benchmem ./core/... ./core/pow/...
```

## Performance

Guardian must never be the bottleneck behind Angie. On the `/auth` hot path
(single node, loopback, bbolt store, 64 connections, with the load generator
sharing the same CPU):

| Scenario | Throughput | p50 | p99 |
|---|---|---|---|
| allow (full pipeline) | ~76k req/s | 0.6 ms | 3.3 ms |
| valid-token client (common path) | ~74k req/s | 0.5 ms | 3.8 ms |
| deny + decision logging | ~100k req/s | 0.3 ms | 3.0 ms |

Verified tokens are cached in-process (~144 ns vs ~43 µs for a full Ed25519
verification), and the Angie glue uses a keepalive upstream so auth
subrequests reuse connections. Reproduce with:

```sh
go build ./cmd/guardian-loadtest
./guardian-loadtest -url http://127.0.0.1:8071 -scenario token -host example.com -c 64 -d 5s
```

## Quick start

```sh
go build ./cmd/guardiand
./guardiand -config guardian.example.yaml
```

Then include the snippet from `deploy/angie-guardian.conf` in each protected
`server {}` block of your Angie configuration.

## Usage

See **[USAGE.md](USAGE.md)** for a step-by-step guide: configuring Guardian,
wiring it into Angie, running it under systemd, operating it through the admin
API, training the anomaly model, load-testing, and multi-instance (redis)
deployment.

## Architecture

All decision logic lives behind a single transport-agnostic seam:

```go
core.Engine.Evaluate(ctx, RequestContext) Decision
```

The HTTP `auth_request` transport is a thin wrapper around it. The store-free
WAF checks live in the leaf package `core/stateless`, which the WASM guest
imports directly, so the in-process module reuses the exact same logic without
dragging in the store, PoW or anomaly dependencies.

```
core/            decision engine, pipeline, config
core/stateless/  store-free WAF checks + value types (shared by sidecar & WASM)
core/pow/        challenges, Ed25519 JWTs, token cache, key persistence + rotation
core/waf/        signature rules, signed IDs
core/anomaly/    statistical baseline model, online scorer, hot-swap cache
core/store/      TTL'd shared state: memory | bbolt | redis
core/metrics/    Prometheus instrumentation (private registry)
transport/http/  auth_request sidecar + admin/metrics
transport/wasm/  optional http-wasm guest (stateless WAF, runs inside Angie)
cmd/             guardiand (sidecar), guardian-train (offline anomaly training),
                 guardian-loadtest (stress tool)
deploy/          Angie snippets, systemd unit, rules, Grafana dashboard
web/             challenge/denied pages (self-contained HTML + JS solver)
```

## License

[AGPL-3.0](LICENSE), © Melroy van den Berg
