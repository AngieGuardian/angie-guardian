# Angie Guardian

A Web Application Firewall (WAF) and proof-of-work bot firewall for
[Angie](https://angie.software/), written in Go.

Guardian protects Angie-hosted websites and APIs from malicious traffic,
abusive bots, and automated attacks while legitimate visitors can continue to
the site normally. It allows trusted requests, challenges suspicious clients
with proof of work, and blocks clear threats.

## Features

Guardian combines a request-time WAF with proof-of-work challenges. Policy is
configurable per domain, so one instance can protect multiple vhosts.

- **Hot-reloadable WAF:** literal and RE2 regex rules for paths, queries,
  User-Agents, headers, and HTTP methods.
- **Adaptive bot defence:** behavioural scoring, honeypots, IP blocking,
  GeoIP/reputation checks, and verified-bot DNS validation.
- **Proof-of-work passes:** adaptive SHA-256 browser challenges followed by a
  cheaply validated Ed25519-signed cookie (7-day default, configurable up to
  30 days); an optional no-JS fallback is available.
- **Replay resistance:** challenges are single-use and bound to the domain and
  client IP.
- **Anomaly detection:** optional offline training from Angie access logs with
  fast scoring in the live request path.
- **Resilient deployment:** persistent keys, shared stores for replicas, safe
  reloads, and fail-open or fail-closed integration.

## Quick start

On Debian or Ubuntu with systemd and Angie already installed, run:

```sh
curl -fsSL https://raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh | sudo bash
```

The installer fetches the latest GitHub release, verifies its checksum, starts
Guardian, and installs the supplied Angie snippets. It preserves existing
Guardian configuration and state, and does not edit or reload Angie vhosts.
On upgrades it compares the starter rules, systemd unit, and Angie snippets
with the release; locally modified files are preserved and reported with an
`ACTION REQUIRED` notice so you can review them manually. Add the required
includes and reload Angie as described in the [Getting Started
guide](https://angieguardian.org/guide/getting-started).

For a specific pinned version, download a `linux-amd64` or `linux-arm64`
package from the [GitHub releases page](https://github.com/AngieGuardian/angie-guardian/releases)
and follow the same guide. The archive contains the binaries, example
configuration, starter WAF rules, Angie snippets, and systemd unit; operators
do not need Go or a repository checkout.

For containers and persistent state, see the
[production Docker guide](https://angieguardian.org/guide/production#docker).

## Documentation

Guides, examples, and the complete configuration and API reference are
published at **<https://angieguardian.org/>**.

## How it works

Angie remains in the request path and keeps serving the site's existing static,
`try_files`, FastCGI, or reverse-proxy handler. Guardian is a sidecar decision
service: Angie sends it a bodyless internal authorization subrequest and acts on
the resulting allow, challenge, or deny response.

See [ARCHITECTURE.md](ARCHITECTURE.md) for diagrams of the live request
lifecycle and of the supporting policy, state, training, and operations plane.

## Performance

Guardian is built for Angie's authorization hot path. A native-binary loopback
test on an AMD Ryzen Threadripper 7960X with 64 connections produced these
throughput results (median of 3 fixed-work runs each, fresh daemon and store per run;
challenge issuance is measured in its **loaded steady state**, with both
in-process counter caches pre-filled past capacity, not against an empty
store):

| Store backend | Allow/s | Returning/s | Refuse auth/s | Refuse 403/s | Challenge issue/s |
|---|---:|---:|---:|---:|---:|
| In-memory store (ephemeral) | 180,000 | 173,000 | 172,000 | 179,000 | 160,000 |
| Pebble (async, default) | 185,000 | 172,000 | 173,000 | 180,000 | 152,000 |
| Pebble (sync, fully durable) | 183,000 | 172,000 | 174,000 | 178,000 | 35,000 |
| BuntDB (async) | 182,000 | 170,000 | 179,000 | 173,000 | 56,000 |
| Redis/Valkey | 94,000 | 93,000 | 97,000 | 184,000 | 49,000 |

Read paths stayed above 93,000 requests/s on every backend. The two refusal
columns measure Guardian's hops separately, not end-to-end capacity. See the
[load-testing guide](https://angieguardian.org/guide/load-testing)
for methodology, latency, and reproduction commands.

## Integration paths

Guardian offers two ways to run, sharing one decision core:

- **Sidecar (default, full-featured).** A Go daemon wired into Angie with
  stock `auth_request` directives. This is the complete implementation:
  proof-of-work and behavioural IP blocking use the shared store it owns;
  anomaly scoring and verified-bot DNS are also sidecar-only. Start here.
- **WASM module (optional, stateless WAF).** The store-free checks (allowlist,
  denylist, honeypot, WAF rules with literal/regex matchers) are compiled to
  WebAssembly and run in-process inside Angie via its WASM support, for
  operators who prefer that integration. It is stateless WAF-only: proof-of-work, behavioural blocking,
  anomaly scoring and verified-bot DNS checks need the sidecar. Build it with `make wasm`; see the
  "WASM module" section of [USAGE.md](USAGE.md).

Both paths share the same store-free matching logic and continue to the backend
for an `allow` rule. Their stateful outcomes differ: in the sidecar, `challenge`
can be satisfied by a bound PoW token and
`block`/honeypot hits persist an IP block; the stateless WASM guest returns a
plain deny for any of those matches. A vouched PoW token never exempts a
sidecar client from `deny` or `block` WAF rule checks, so a stolen token can't
ride past the WAF.

## Operations

- **Observability:** Prometheus metrics, health/readiness checks, a bundled
  [Grafana dashboard](deploy/grafana-dashboard.json), and
  [alert rules](deploy/alerts.yaml).
- **Admin API and dashboard:** token-protected block management, recent
  decisions, anomaly/config status, and an optional air-gapped web dashboard.
- **Safe maintenance:** hot reload keeps the last-good configuration active;
  signing keys can be rotated without immediately invalidating existing passes.
- **Flexible state:** `memory`, `pebble`, or `buntdb` for one instance;
  `redis`/`valkey` for shared multi-instance deployments.

See [USAGE.md](USAGE.md) for endpoints, authentication, dashboard setup, reload,
and key-rotation details.

## Security

Guardian's [security model and limitations](https://angieguardian.org/guide/threat-model)
spell out what it defends against and what it deliberately does not. To report a
vulnerability, see [SECURITY.md](SECURITY.md); please do not open a public issue.

## License

[AGPL-3.0](LICENSE), © Melroy van den Berg

---

## Development

Everything below this line is for contributors building, testing, or changing
Angie Guardian. Operators can stop here and use the documentation linked above.

The [Development guide](https://angieguardian.org/guide/development) is the
longer form of this section: repository layout, the `curl`-only local loop
against `/auth`, what each CI job does and the two things it deliberately does
not check, the conventions a change is expected to follow, and the store,
packaging and documentation workflows.

### Testing

The default suite is self-contained; Docker is only needed for end-to-end tests.

| Check | Command | Purpose |
|---|---|---|
| Unit | `go test ./...` | Core, stores, and HTTP transports |
| Race detector | `go test -race ./...` | Concurrency regressions |
| End-to-end | `make e2e` | Real Angie → guardiand → backend stack |
| Fuzz | `make fuzz` | Untrusted and hot-reloaded parsers |
| Benchmarks | `go test -bench=. -benchmem ./core/... ./transport/http/` | Request hot paths |
| Allocation gate | `make bench-regress` | Hot-path `allocs/op` against `allocs-baseline.txt`; also a CI job |
| Hot-path snapshot | `make bench-report` | Request-path `sec/op`, `B/op` and `allocs/op` for the current tree, with the spread across runs; manual, gates nothing |

The [end-to-end suite](test/e2e/) covers proof-of-work, WAF outcomes,
behavioural blocking, fail-open, metrics, and the Admin API. CI runs it on
`main` and release tags; run it locally before merging stack-level changes.
Commit useful fuzz crashers from `testdata/fuzz/` as regression seeds.

#### Seed the dashboard

Run a throwaway instance and generate representative dashboard traffic from two
shells:

```sh
go run ./cmd/guardiand -config test/seed/guardian.seed.yaml
make seed                  # two minutes
make seed SEEDTIME=5m      # optional longer run
```

Open <http://127.0.0.1:18072/admin/dashboard#token=seed-demo-token>. The linked
[seed configuration](test/seed/guardian.seed.yaml) is memory-only and intended
for local development. `make seed` creates a realistic traffic mix; use
`guardian-loadtest` for throughput measurements.

#### Try a dashboard change against real data

The dashboard is embedded in the binary, so seeing an edit otherwise means a
rebuild and a deploy. [`make dashboard-dev`](test/dashdev/) serves
`web/dashboard.html` from the working tree and forwards every other `/admin/`
path to a guardiand that is already running, so the edit loop is save and
reload:

```sh
make dashboard-dev                                      # against the seed instance above
make dashboard-dev UPSTREAM=http://192.168.1.42:8072    # against a real deployment
```

Open <http://127.0.0.1:8073/admin/dashboard> and enter that daemon's admin
token. Nothing about the page changes: its URLs are origin-relative, so one
listener answering both the page and `/admin/*` serves it as-is, with no CORS
and no config key. Two caveats: the local page is served without the
Content-Security-Policy guardiand sets on its own dashboard route, and the
page's write actions are forwarded like everything else, so against a real
deployment an unblock is a real unblock.

Behavioural tests for the page's own logic live in
[`web/dashboard_script_test.go`](web/dashboard_script_test.go), which lifts
declarations out of `dashboard.html` and runs them in a Go JS interpreter.
Prefer adding a case there over asserting that a line of markup exists.

### Building from source

The required Go toolchain is pinned in [go.mod](go.mod). Build the three sidecar
binaries into `dist/`, or additionally build the optional WASM module:

```sh
make build
make wasm
```

The documentation site can be previewed with `make docs-dev` or built with
`make docs`.

### Performance testing

`guardian-loadtest` drives
the hot path over keepalive HTTP the way Angie does and reports throughput and
latency percentiles.

**Scenarios** (`challenge` is the one write-heavy path):

| Scenario | What it does | Store I/O per request |
|---|---|---|
| `allow` | plain request, full pipeline, ends in "default allow" | none on the embedded backends once the block mirror is seeded; 1 read on `redis` (read-through, so another replica's blocks apply immediately) |
| `token` | solve one PoW challenge, then hammer `/auth` with the cookie (the production common path) | same as `allow` |
| `deny` | denylisted client IP (deny + decision logging path) | no store I/O |
| `challenge` | issue a fresh PoW challenge per request | normally 1 **write** (challenge CAS); under [attack mode](https://angieguardian.org/guide/attack-mode), or when that stateful write fails, issuance is stateless: no write at issue, the single-spend write moves to redemption. Rate-limit and escalation counters are counted in-process and flushed in the background either way |
| `refuse-auth` | directly measure `/auth` recording `ActionRefuse` and returning the 401 Angie routes onward | same as `allow` |
| `refuse-challenge` | directly measure `/challenge` consuming the relayed refusal verdict and returning its small 403 | no store I/O |
| `refuse-angie` | point `-url` at Angie and measure the real `/auth` → `@guardian_challenge` → 403 route | combines both Guardian hops |

**Results** (single node, native binaries over loopback, 64 connections, load
generator sharing the same CPU: AMD Ryzen Threadripper 7960X, 24C/48T; Linux
6.17 for the existing non-Pebble rows and Linux 7.0.0 for the refreshed Pebble
and refusal rows; Go 1.26.5; Valkey 9 for the redis backend; fresh daemon and
store per run; median of 3 runs per cell). Reads use
`-warmup 50000 -n 500000`; challenge uses
`-warmup 150000 -n 150000`, so its warmup pushes both 131k-entry counter caches
past capacity and the measured window is the loaded steady state, not the fast
cold start an empty store serves. Each cell is **throughput / p50 / p99**
(req/s and per-request latency):

| Backend | allow | token | deny | refuse auth | refuse 403 | challenge write |
|---|---|---|---|---|---|---|
| `memory` (ephemeral)              | 180k / 0.13ms / 1.8ms | 173k / 0.16ms / 1.7ms | 157k / 0.14ms / 2.3ms | 172k / 0.15ms / 1.8ms | 179k / 0.15ms / 1.7ms | **160k / 0.29ms / 1.6ms** |
| `pebble` (async, default durable) | 185k / 0.14ms / 1.7ms | 172k / 0.15ms / 1.8ms | 188k / 0.13ms / 1.7ms | 173k / 0.15ms / 1.8ms | 180k / 0.15ms / 1.7ms | **152k / 0.32ms / 1.6ms** |
| `pebble` (sync, fully durable)    | 183k / 0.14ms / 1.7ms | 172k / 0.15ms / 1.8ms | 189k / 0.14ms / 1.7ms | 174k / 0.15ms / 1.8ms | 178k / 0.15ms / 1.7ms | **35k / 1.5ms / 5.1ms** |
| `buntdb` (async, single-file)     | 182k / 0.13ms / 1.8ms | 170k / 0.14ms / 1.8ms | 155k / 0.13ms / 2.4ms | 179k / 0.16ms / 1.7ms | 173k / 0.14ms / 1.8ms | **56k / 1.2ms / 4.8ms** |
| `redis`·`valkey` (fleet)          | 94k / 0.64ms / 1.3ms  | 93k / 0.64ms / 1.4ms  | 162k / 0.13ms / 2.3ms | 97k / 0.62ms / 1.4ms | 184k / 0.15ms / 1.7ms | **49k / 1.2ms / 2.5ms** |

Refusal is measured per Guardian hop so its cost is visible: `refuse auth` is
the `/auth` record + 401, while `refuse 403` is the small `/challenge` response.

The `/auth` hop evaluates and records the refusal, updates decision metrics,
and calls the decision logger (suppressed at the measured production-default
`warn` level). The `/challenge` hop updates the refusal outcome metric and
returns a plain-text 403 without a challenge CAS/store write or HTML rendering.
The direct `/auth` refusal outpaced direct stateful challenge issuance on every
measured backend. One original request through Angie still pays both refusal
hops plus proxy routing, so these rates must not be added or presented as
proven end-to-end DDoS capacity.

(`buntdb` + `sync: true` measured only ~0.6k challenge writes/s, because a
single-writer store fsync'ing every commit is that slow, so the combination is
**rejected at startup**; use `pebble` with `sync: true` for synchronous durability.)

Every backend clears the ≥50k req/s budget on the read paths with a wide margin.
On the **embedded** backends the in-process block mirror makes the store
authoritative, so `allow`/`token` do no store I/O at all after the seed scan,
which is why they cluster at ~154–182k. `redis`/`valkey` is the exception: it
stays read-through (one network read per request for cross-replica correctness),
so its `allow`/`token` land lower (~93–94k) while `deny` (no store read) stays fast.

The **write** path is where the backend matters. Issuing a challenge writes one
CAS record, and the durable backends absorb that far better than a synchronous
single-writer store:

- **`pebble`** (default durable) sustains ~152k challenge writes/s in async mode,
  and in fully-durable `sync: true` mode does ~35k/s. Both are far above
  a synchronously-fsync'd single-writer store. It is an LSM engine, so writes hit
  the WAL and memtable and are flushed in the background.
- **`buntdb`** sustains ~56k/s in async mode and stores everything
  in one file, which is simpler to back up. It is single-writer, so `sync: true`
  would fsync every commit and collapse to ~600/s, so guardiand **refuses to
  start** in that configuration and points you to Pebble for synchronous
  durability.
- **`memory`** has no write ceiling at all (~160k/s) but loses all state on
  restart.
- **`redis`/`valkey`** sustains ~49k challenge writes/s (comparable to the
  embedded durable backends) and is the **multi-instance** option: it is the
  shared store that lets replicas behind a load balancer see each other's blocks
  and single-spend markers. It trades some read throughput for that (one network
  read per request). The embedded backends above are single-node only. See the
  [store guide](https://angieguardian.org/guide/production#choosing-a-store-backend).

Two ways to lift the write path further when a burst of *new* clients could
exceed the durable ceiling:

- Set `pow.mode: suspicion` so there is no catch-all challenge (only explicit
  anomaly/WAF/GeoIP/reputation policies issue one), or rely on
  [attack mode](https://angieguardian.org/guide/attack-mode)'s
  **stateless** issuance, which writes nothing at issue time. The only remaining
  write is then the single-spend marker at redemption, which an attacker cannot
  trigger without actually solving the proof of work.
- Verified tokens are cached in-process (~35 ns, allocation-free, vs ~40 µs for a full Ed25519
  verification), so a returning client's request stays on the fast read path
  regardless of backend.
- At these rates the read paths are bound by Go's garbage collector, not the
  store: `GOGC=800` raises allow throughput ~20%. See "GC tuning" in the
  production guide.

The `redis` backend works with both Redis and
[Valkey](https://valkey.io/) (a drop-in replacement, same wire protocol and same
`backend: redis` value).

#### Reproduce

```sh
go build -o guardiand ./cmd/guardiand
go build -o guardian-loadtest ./cmd/guardian-loadtest
mkdir -p .guardian
sed -e 's#/etc/guardian/rules.d/common.yaml#deploy/rules-common.yaml#' \
    -e 's#/etc/guardian/#.guardian/#g' \
    -e 's#/var/lib/guardian/#.guardian/#g' \
    guardian.example.yaml > guardian.local.yaml

# 1. Start guardiand with your store backend (pebble shown; for redis set
#    store.backend: redis and store.addr in the config). PoW must be enabled
#    for the token/challenge scenarios.
./guardiand -config guardian.local.yaml &

# 2. Run each scenario with FIXED WORK (-warmup/-n), 64 connections, and a
#    fresh daemon + wiped store per run so results are comparable. Use a
#    distinct -ip per read run so a behavioural block from one run doesn't
#    bleed into the next; the challenge scenario rotates the client IP itself
#    to dodge the issuance limit, and its warmup pushes the counter caches
#    past capacity so the measured window is the loaded steady state. allow
#    uses the PoW-off host: the scenario expects 200s, and a PoW-on host
#    answers 401 (challenge) for unvouched clients.
./guardian-loadtest -scenario allow     -host api.example.com -ip 198.51.100.10 -c 64 -warmup 50000  -n 500000
./guardian-loadtest -scenario token     -host example.com     -ip 198.51.100.11 -c 64 -warmup 50000  -n 500000
./guardian-loadtest -scenario deny      -host example.com     -ip 203.0.113.9   -c 64 -warmup 50000  -n 500000   # IP must be denylisted
./guardian-loadtest -scenario refuse-auth      -host example.com -c 64 -warmup 50000  -n 500000
./guardian-loadtest -scenario refuse-challenge -host example.com -c 64 -warmup 50000  -n 500000
./guardian-loadtest -scenario challenge -host example.com                        -c 64 -warmup 150000 -n 150000
```

To measure the full production topology separately, point the dedicated Angie
scenario at its public listener. This reports original client requests/s, not
Guardian subrequests/s:

```sh
./guardian-loadtest -scenario refuse-angie -url http://127.0.0.1:8080 -host example.com -c 64 -warmup 50000 -n 500000
```

A multi-million-request duration soak is a different test: the bounded
CounterCache deliberately becomes conservative after more distinct client keys
than it can retain, so sketch collisions will eventually exercise the issuance
limiter instead of Pebble. To isolate store endurance, use a temporary test-only
config with a very high `pow.issuance_rate_limit`; do not copy that setting to
production. Fixed-work comparison runs above need no override.

The output's `per-second:` line shows whether the run reached a steady state; a
falling line means the aggregate is blending regimes and only fixed-work runs
with identical flags are comparable. `make bench-regress` is the companion CI
gate: hot-path allocs/op against the committed baselines in
`allocs-baseline.txt`, deterministic and machine-independent.
`make bench-report` is the manual counterpart: the same hot paths run several
times and summarized with their spread, so you can read `B/op` and `sec/op`
without a baseline to compare against.

Micro-benchmarks live alongside the code and cover every layer of the hot path:
the `/auth` handler and the request value it builds, `Evaluate` per verdict,
`ShedDecision`, PoW verification and anomaly scoring.

```sh
go test -bench=. -benchmem ./core/... ./transport/http/
```

Read them next to the load test rather than instead of it. On loopback at
~180k req/s the daemon spends roughly 70–80 µs of CPU per request, and the
decision itself is well under a microsecond: nearly all of that is the kernel
and `net/http`. A change that makes the decision path several times cheaper
therefore moves the end-to-end request rate by only a few percent, and is best
measured as CPU per request. See the
[load-testing guide](https://angieguardian.org/guide/load-testing#micro-benchmarks).

### Architecture

All decision logic lives behind a single transport-agnostic seam:

```go
core.Engine.Evaluate(ctx, RequestContext) Decision
```

The HTTP `auth_request` transport is a thin wrapper around it. The store-free
WAF checks live in the leaf package `core/stateless`, which the WASM guest
imports directly, so the in-process module reuses the exact same logic without
dragging in the store, PoW or anomaly dependencies.

```
core/             decision engine, pipeline, config, scoreboard, recent-decision ring
core/stateless/   store-free WAF checks + value types (shared by sidecar & WASM)
core/pow/         challenges, Ed25519 JWTs, token cache, key persistence + rotation
core/waf/         WAF rules, signed IDs
core/anomaly/     statistical baseline model, online scorer, hot-swap cache
core/store/       TTL'd shared state: memory | buntdb | pebble | redis
core/intel/       GeoIP/ASN databases and IP reputation feeds
core/botverify/   rDNS + forward-confirm crawler verification
core/attackmode/  fleet attack posture: signal aggregation and state machine
core/enforce/     block mirror and the optional nftables kernel sink
core/health/      background store probe behind /readyz
core/metrics/     Prometheus instrumentation (private registry)
transport/http/   auth_request sidecar + admin/metrics/dashboard
transport/wasm/   optional http-wasm guest (stateless WAF, runs inside Angie)
internal/         small shared helpers (bounded file reads, background-work jitter)
cmd/              guardiand (sidecar), guardian-train (offline anomaly training),
                  guardian-loadtest (stress tool)
deploy/           Angie snippets, systemd unit, rules, Grafana dashboard, alert rules
web/              challenge/denied pages and the admin dashboard, with its
                  vendored chart libraries (no CDN, works air-gapped)
```
