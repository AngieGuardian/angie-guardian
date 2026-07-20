# What is Angie Guardian?

Angie Guardian is a Web Application Firewall (WAF) and proof-of-work bot
firewall for [Angie](https://en.angie.software/), written in Go.

Guardian runs as a sidecar daemon next to Angie and is wired into the request
path with stock `auth_request` directives, so there is no custom Angie build
and no C module. Every request to a protected `server {}` block triggers a fast
internal subrequest to Guardian, which answers **allow**, **challenge**, or
**deny**.

## Two cooperating subsystems

Guardian is two subsystems sharing one config, one datastore, and one decision
pipeline. Everything is per-domain configurable.

### 1. The WAF layer, on every request

- Hot-reloadable keyword/regex threat signatures (RE2: no ReDoS by
  construction), matched against the decoded path and query, the User-Agent,
  and any named request header, optionally scoped to HTTP methods.
- Behavioural IP blocking with exponential backoff, fed by signature hits,
  PoW failures, tamper events, and bot-spoof attempts.
- Verified crawler allowlisting: Googlebot and friends are admitted by
  rDNS + forward-confirmed identity, never by their forgeable User-Agent
  string (see [Bots, GeoIP & Reputation](/guide/bots-ip-intel)).
- GeoIP/ASN scoping (deny or challenge by origin country and ASN) and
  external IP reputation feeds (FireHOL-style lists), refreshed in the
  background and hot-reloaded, with fail-open semantics throughout.
- Honeypot trap paths: one hit denies immediately and, when behavioural
  scoring is enabled, places a persistent IP block.
- Tamper detection on proof-of-work challenge IDs: each challenge is
  single-spend and bound to `{host, client IP}`, so a forged, replayed or
  cross-domain challenge ID is rejected and scored as a tamper event.
- Statistical anomaly scoring: `guardian-train` learns per-domain baselines
  from Angie JSON access logs offline; the online scorer rates each unvouched
  request that reaches it in about 260 ns and drives challenge/deny plus
  difficulty escalation. Valid PoW tokens short-circuit this stage after the
  signature checks. The
  model artifact is versioned and hot-swapped, so an ML implementation can
  slot in behind the same seam later.

### 2. The proof-of-work challenge layer, only for suspicious or new clients

- SHA-256 leading-zero-bits challenge with a parallel pure-JS solver (works
  on plain-http origins too); difficulty tunes in 2x quarter steps
  (`base_difficulty: 5.25`) and escalates with suspicion.
- Per-host-and-IP escalation against challenge farming: a client that keeps
  requesting challenges without solving them pays one extra bit (2x) per two
  abandoned challenges, capped at `max_difficulty`; a solve resets only that
  domain's counter.
- Ed25519-signed JWT cookie on success; cheap re-validation afterwards.
- A **persistent shared signing key**, so restarts don't log everyone out,
  and replicas behind a load balancer can share one key.
- Spent-challenge tracking from day one (no mint-twice replay).
- An optional no-JS meta-refresh fallback: a five-second minimum wait instead
  of hash work, so it has a weaker, more parallelizable cost model.

## Integration paths

Guardian offers two ways to run, sharing one decision core:

- **Sidecar (default, full-featured).** A Go daemon wired into Angie with
  stock `auth_request` directives. This is the complete implementation:
  proof-of-work, behavioural IP blocking, and anomaly scoring all require the
  shared store the sidecar owns. Start here.
- **WASM module (optional, stateless WAF).** The store-free checks (allowlist,
  denylist, honeypot, keyword/regex signatures) compiled to WebAssembly and run
  in-process inside Angie via its WASM support. It is stateless WAF-only. See
  the [WASM module guide](/guide/wasm).

Both paths share the same store-free matching logic. Their stateful outcomes
differ: in the sidecar, `challenge` can be satisfied by a bound PoW token and
`block`/honeypot hits persist an IP block; the stateless WASM guest returns a
plain deny for any of those matches. A vouched PoW token never exempts a
sidecar client from `deny` or `block` signature checks, so a stolen token can't
ride past the WAF.

## Architecture

All decision logic lives behind a single transport-agnostic seam:

```go
core.Engine.Evaluate(ctx, RequestContext) Decision
```

The HTTP `auth_request` transport is a thin wrapper around it. The store-free
WAF checks live in the leaf package `core/stateless`, which the WASM guest
imports directly, so the in-process module reuses the exact same logic without
dragging in the store, PoW, or anomaly dependencies.

```
core/            decision engine, pipeline, config
core/stateless/  store-free WAF checks + value types (shared by sidecar & WASM)
core/pow/        challenges, Ed25519 JWTs, token cache, key persistence + rotation
core/waf/        signature rules, signed IDs
core/anomaly/    statistical baseline model, online scorer, hot-swap cache
core/botverify/  rDNS + forward-confirm crawler identity, store-cached
core/intel/      GeoIP country/ASN lookups + reputation feed sets
core/store/      TTL'd shared state: memory | buntdb | pebble | redis
core/metrics/    Prometheus instrumentation (private registry)
transport/http/  auth_request sidecar + admin/metrics
transport/wasm/  optional http-wasm guest (stateless WAF, runs inside Angie)
cmd/             guardiand (sidecar), guardian-train (offline anomaly training),
                 guardian-loadtest (stress tool)
deploy/          Angie snippets, systemd unit, rules, Grafana dashboard
web/             challenge/denied pages (self-contained HTML + JS solver)
```

## Performance

Guardian must never be the bottleneck behind Angie. On a single node
(loopback, 64 connections, AMD Ryzen Threadripper 7960X, load generator on the
same CPU; Valkey 9 for the redis backend). Each cell is
**throughput / p50 / p99** (req/s and per-request latency):

| Backend | allow | token | deny | challenge (write) |
|---|---|---|---|---|
| `memory` (ephemeral)              | 169k / 0.15ms / 1.8ms | 159k / 0.21ms / 1.7ms | 150k / 0.14ms / 2.4ms | **156k / 0.29ms / 1.7ms** |
| `pebble` (async, default durable) | 177k / 0.14ms / 1.7ms | 154k / 0.21ms / 1.8ms | 152k / 0.14ms / 2.4ms | **39k / 0.73ms / 20ms** |
| `pebble` (sync, fully durable)    | 172k / 0.14ms / 1.8ms | 155k / 0.21ms / 1.8ms | 152k / 0.14ms / 2.4ms | **25k / 2.6ms / 7.5ms** |
| `buntdb` (async, single-file)     | 175k / 0.14ms / 1.7ms | 153k / 0.23ms / 1.8ms | 150k / 0.14ms / 2.4ms | **36k / 1.3ms / 17ms** |
| `redis`·`valkey` (fleet)          | 96k / 0.62ms / 1.4ms  | 94k / 0.63ms / 1.4ms  | 162k / 0.13ms / 2.3ms | **34k / 1.2ms / 21ms** |

The read paths clear the 50k req/s budget comfortably on every backend. On the
embedded backends the block mirror serves the reads (no store I/O after the seed
scan), which is why `allow`/`token` cluster at ~150–177k; `redis`/`valkey` stays
read-through for cross-replica correctness, so its reads land lower. The one
write-heavy path (issuing a fresh challenge) is where the backends differ; under
[attack mode](/guide/attack-mode) issuance goes stateless and skips that write
entirely. See
[choosing a store backend](/guide/production#choosing-a-store-backend)
for how to pick, and [Load Testing](/guide/load-testing) to reproduce the
numbers on your own hardware.

## License

Angie Guardian is free software, released under the
[AGPL-3.0](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/LICENSE)
license, copyright Melroy van den Berg.
