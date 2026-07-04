# Angie Guardian

A Web Application Firewall (WAF) and [Anubis](https://anubis.techaro.lol/)-style
proof-of-work bot firewall for [Angie](https://angie.software/), written in Go.

Guardian runs as a sidecar daemon next to Angie and is wired into the request
path with stock `auth_request` directives — no custom Angie build, no C module.
Every request to a protected `server {}` block triggers a fast internal
subrequest to Guardian, which answers **allow**, **challenge**, or **deny**.

## Features

Two cooperating subsystems sharing one config, one datastore, and one decision
pipeline — everything per-domain configurable:

1. **WAF layer** — runs on every request:
   - behavioural IP blocking (404/403 rates, honeypot hits, PoW failures)
   - hot-reloadable keyword/regex threat signatures *(P2)*
   - anomaly scoring trained offline on Angie JSON access logs *(P3)*
   - hidden honeypot form field + timing trap *(P2)*
   - tamper-proof signed tokens (UUID + HMAC/Ed25519) *(P2)*

2. **Proof-of-Work challenge layer** *(P1)* — only for suspicious/new clients:
   - SHA-256 leading-zeros challenge with JS/WASM solver
   - Ed25519-signed JWT cookie on success; cheap re-validation afterwards
   - **persistent shared signing key** (restarts don't log everyone out,
     replicas work — unlike stock Anubis)
   - spent-challenge tracking from day 1 (no mint-twice replay)
   - no-JS meta-refresh fallback

## Status

Under active development. **P0 (skeleton & seam) and P1 (proof-of-work
challenge layer) are complete and tested end-to-end**: decision pipeline,
per-domain config, memory + bbolt store, challenge page with Web Worker
solver, no-JS fallback, Ed25519 JWT cookies with a persistent shared signing
key, and replay-safe spent-challenge tracking. Next up: P2 (WAF signatures,
honeypot, behavioural scoreboard) and P3 (anomaly scoring).

## Performance

Guardian must never be the bottleneck behind Angie. On the `/auth` hot path
(single node, loopback, bbolt store, 64 connections — load generator sharing
the same CPU):

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

## Architecture

All decision logic lives behind a single transport-agnostic seam:

```go
core.Engine.Evaluate(ctx, RequestContext) Decision
```

The HTTP `auth_request` transport is a thin wrapper around it, so the same
core can later be embedded as a cgo-backed Angie module or a WASM module
without a rewrite.

```
core/        decision engine, pipeline, config
core/pow/    challenges, Ed25519 JWTs, token cache, key persistence
core/store/  TTL'd shared state: memory | bbolt (redis planned)
transport/   http (auth_request sidecar); future: cgo, wasm
cmd/         guardiand (sidecar), guardian-loadtest (stress tool),
             guardian-train (offline anomaly training, P3)
deploy/      Angie snippets, systemd unit
web/         challenge/denied pages (self-contained HTML + JS solver)
```

## License

[AGPL-3.0](LICENSE) — © Melroy van den Berg
