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
     construction), matched against the decoded path, query, User-Agent
     and any named request header, with optional HTTP-method filters
   - behavioural IP blocking with exponential backoff (signature hits,
     PoW failures, tamper events)
   - honeypot trap paths: one hit = instant block
   - verified-bot allowlisting: search crawlers (Googlebot, bingbot, ...) are
     admitted by reverse-DNS + forward-confirmed identity with store-backed
     caching, never by their forgeable User-Agent string; proven impostors
     are denied and scored
   - tamper-proof signed IDs (HMAC-bound to purpose + host)
   - statistical anomaly scoring: `guardian-train` learns per-domain
     baselines from Angie JSON access logs offline; the online scorer rates
     every request in ~260ns and drives challenge/deny + difficulty
     escalation (model artifact is versioned and hot-swapped, so an ML
     implementation can slot in behind the same seam later)

2. **Proof-of-Work challenge layer**, only for suspicious or new clients:
   - SHA-256 leading-zero-bits challenge with a parallel pure-JS solver
     (works on plain-http origins too); difficulty tunes in 2x steps
     (`base_difficulty: 5.25`) and escalates with suspicion
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
  anomaly scoring and verified-bot DNS checks need the sidecar. Build it with `make wasm`; see the
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
  clear IP blocks (`/admin/blocks/{ip}`), list all active blocks
  (`/admin/blocks`), read the recent deny/challenge feed (`/admin/decisions`)
  and its rollup (`/admin/stats`), score a hypothetical request against the
  anomaly model (`GET /admin/score`), rotate the signing key, and view the
  active per-domain config. Refuses to expose itself on a non-loopback address
  without a token.
- **Reporting dashboard** (optional, `admin.dashboard: true`): a built-in
  internal page at `/admin/dashboard`, driven entirely by the token-guarded
  admin API; guardiand prints a ready-to-open login link at startup (the
  admin token is auto-generated, see `admin.token_file`). It shows active
  blocks with one-click block/unblock, the filterable recent decisions feed,
  challenge/solve counters, and per-domain status. See USAGE.md § 4.
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

On top of the unit suite, an **end-to-end suite** (`test/e2e/`, gated behind the
`e2e` build tag) boots the real `Angie → guardiand → whoami` Docker stack with
[testcontainers-go](https://golang.testcontainers.org/) and drives traffic
*through Angie*: solving a real PoW challenge, exercising the WAF
`deny`/`block`/`challenge` actions and behavioural blocking, the fail-open mode,
and the `/metrics` + admin-API report surface. It needs Docker and is excluded
from the default `go test ./...`:

```sh
make e2e                 # or: go test -tags e2e ./test/e2e/...
```

Performance-sensitive hot paths (`Evaluate`, PoW verification, anomaly
scoring) also carry benchmarks:

```sh
go test -bench=. -benchmem ./core/... ./core/pow/...
```

## Performance

Guardian must never be the bottleneck behind Angie. `guardian-loadtest` drives
the hot path over keepalive HTTP the way Angie does and reports throughput and
latency percentiles.

**Scenarios** (the first three are read-dominated; `challenge` is the one
write-heavy path):

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | 1 read (block lookup) |
| `token` | solve one PoW challenge, then hammer `/auth` with the cookie (the production common path) | 1 read |
| `deny` | denylisted client IP (deny + decision logging path) | 1 read |
| `challenge` | issue a fresh PoW challenge per request | 1 **write** (challenge CAS); the per-IP rate-limit and escalation counters are counted in-process and flushed to the store in the background |

**Results** (single node, loopback, 64 connections, load generator sharing the
same CPU: AMD Ryzen Threadripper 7960X, 24C/48T; Go 1.25; Valkey 9 for the
redis backend). Numbers are req/s and per-request latency:

| Scenario | bbolt (throughput / p50 / p99) | redis · valkey (throughput / p50 / p99) |
|---|---|---|
| allow     | ~78k / 0.50 ms / 3.4 ms  | ~92k / 0.64 ms / 1.5 ms |
| token     | ~71k / 0.54 ms / 3.9 ms  | ~90k / 0.65 ms / 1.6 ms |
| deny      | ~124k / 0.35 ms / 2.5 ms | ~186k / 0.12 ms / 1.8 ms |
| challenge (write) | **~4.1k / 16 ms / 19 ms** | **~26k / 2.3 ms / 4.7 ms** |

The read paths all comfortably clear the ≥50k req/s budget on both backends.
The takeaway is the **write** path: issuing a challenge writes the issuance
record through embedded bbolt's single fsync'd writer (~4.1k/s, ~16 ms under
contention), while redis/valkey sustains ~6× that (~26k/s). The per-IP
rate-limit and farming-escalation counters do not add write rounds: they are
counted in-process and synced to the shared store in the background. So the
backend choice hinges on your *new-client* rate, i.e. the clients that
trigger a challenge write:

- With `pow.mode: always`, every unvouched browser is challenged, so a burst of
  fresh visitors is bounded by the write path. If that burst can exceed a few
  thousand per second, use the **redis** backend (Redis or
  [Valkey](https://valkey.io/), a drop-in replacement), or set
  `pow.mode: suspicion` so only anomalous clients are challenged and the vast
  majority of traffic does no write.
- Verified tokens are cached in-process (~144 ns vs ~43 µs for a full Ed25519
  verification), so a returning client's request stays on the fast read path
  regardless of backend.
- At these rates the read paths are bound by Go's garbage collector, not the
  store: `GOGC=800` more than doubles them (allow: ~188k req/s on bbolt). See
  "GC tuning" in the production guide.

### Reproduce

```sh
go build ./cmd/guardiand ./cmd/guardian-loadtest

# 1. Start guardiand with your store backend (bbolt shown; for redis set
#    store.backend: redis and store.addr in the config). PoW must be enabled
#    for the token/challenge scenarios.
./guardiand -config guardian.example.yaml &

# 2. Run each scenario (8s, 64 connections). Use a distinct -ip per read run so
#    a behavioural block from one run doesn't bleed into the next; the
#    challenge scenario rotates the client IP itself to dodge the issuance limit.
./guardian-loadtest -scenario allow     -host example.com -ip 198.51.100.10 -c 64 -d 8s
./guardian-loadtest -scenario token     -host example.com -ip 198.51.100.11 -c 64 -d 8s
./guardian-loadtest -scenario deny      -host example.com -ip 203.0.113.9   -c 64 -d 8s   # IP must be denylisted
./guardian-loadtest -scenario challenge -host example.com                    -c 64 -d 8s
```

Micro-benchmarks for the hot functions (`Evaluate`, PoW verification, anomaly
scoring) live alongside the code: `go test -bench=. -benchmem ./core/... ./core/pow/...`

## Quick start

```sh
go build ./cmd/guardiand
./guardiand -config guardian.example.yaml
```

Then include the snippet from `deploy/angie-guardian.conf` in each protected
`server {}` block of your Angie configuration.

## Documentation

The full documentation (guides, examples, and a complete option/API
reference) is published at:

**<https://angie-guardian-31c118.pages.melroy.org/>**

It lives in [`docs/`](docs/) as a VitePress site, published via
GitLab Pages on every push to `main`. Browse it locally with
`make docs-dev`, or build the static site with `make docs`.

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
