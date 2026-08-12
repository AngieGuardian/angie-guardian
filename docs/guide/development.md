# Development

This page is about working on Guardian itself rather than running it. Development is done on GitLab, ask me to get an account on my GitLab instance if you wish to collaborate.

Everything here needs a repository checkout and the Go toolchain selected by
`go.mod`, and the development tools are never installed on a server: they live
under `test/`, are run with `go run`, and are not compiled into `guardiand`.

```sh
git clone https://gitlab.melroy.org/melroy/angie-guardian.git
cd angie-guardian
make test        # the whole tree under -race
```

Docker is the only external service any of this needs, and only for the
end-to-end suite.

## Repository layout

| Path | What lives there |
|---|---|
| `cmd/guardiand` | The sidecar daemon. Flags, signal handling, wiring. |
| `cmd/guardian-train` | Offline anomaly-model trainer and its `compare` gate. |
| `cmd/guardian-loadtest` | Hot-path load generator. The only tool that measures throughput. |
| `core` | The decision engine (`engine.go`), the whole config surface (`config.go`), the recent-decisions ring, unblocking. |
| `core/pow` | Proof of work: challenge issue and redeem, difficulty escalation, stateless challenges, key rotation. |
| `core/waf` | WAF rules and their hot-reloading cache. |
| `core/anomaly` | The statistical baseline and scoring. |
| `core/intel` | GeoIP and IP reputation feeds. |
| `core/store` | Store backends behind one interface: sharded memory, BuntDB, Pebble, Redis/Valkey. |
| `core/enforce`, `core/attackmode`, `core/botverify`, `core/health`, `core/metrics`, `core/stateless` | Block offload, attack mode, verified-crawler checks, health probes, Prometheus metrics, the shared decision vocabulary. |
| `transport/http` | The `/auth` hot path, the challenge and redeem endpoints, and the whole Admin API. |
| `transport/wasm` | The optional http-wasm guest (`//go:build wasip1`), a stateless subset. |
| `web` | The served pages: challenge interstitial, denied page, dashboard, plus the vendored chart libraries. |
| `internal/` | Small shared helpers (duration and rate parsing, jitter, bounded file reads). |
| `deploy/` | Everything an operator installs: Angie glue configs, systemd units, Prometheus alerts, the Docker stack. |
| `test/e2e` | The end-to-end suite (`//go:build e2e`). |
| `test/seed`, `test/dashdev` | Development tools, described below. |
| `docs/` | This site (VitePress). |

## The local loop

The fastest loop needs neither Angie nor Docker: run the daemon with the seed
config and talk to `/auth` yourself.

```sh
go run ./cmd/guardiand -config test/seed/guardian.seed.yaml
```

That config is memory-only and binds `127.0.0.1:18071` for the hot path and
`127.0.0.1:18072` for the admin API, with a fixed dev token so the dashboard
link works.

`/auth` is what Angie's `auth_request` calls, and Angie supplies the request
context in headers, so a bare `curl` has to do the same:

```sh
curl -si 127.0.0.1:18071/auth \
  -H 'X-Guardian-Host: plain.test' \
  -H 'X-Guardian-Method: GET' \
  -H 'X-Guardian-URI: /' \
  -H 'X-Guardian-IP: 198.51.100.7' \
  -H 'X-Guardian-UA: curl/8'
# HTTP/1.1 200 OK
# X-Guardian-Action: allow
# X-Guardian-Reason: default
```

| Status | Meaning |
|---|---|
| `200` | Allow. Angie proceeds to the backend. |
| `401` | Challenge or refusal. Angie routes to the challenge location on this status. |
| `403` | Deny. |

Every response carries `X-Guardian-Action` and `X-Guardian-Reason`, and a
challenge adds `X-Guardian-Difficulty`, so a single `curl -i` tells you what
was decided and why without reading a log:

```sh
# A honeypot path on a PoW host: denied outright.
curl -si 127.0.0.1:18071/auth -H 'X-Guardian-Host: example.com' \
  -H 'X-Guardian-URI: /wp-admin-backup/x' -H 'X-Guardian-IP: 198.51.100.9' \
  -H 'X-Guardian-UA: curl/8'
# HTTP/1.1 403 Forbidden
# X-Guardian-Action: deny
# X-Guardian-Reason: honeypot:path
```

::: tip A bare curl gets refused, not challenged
Ask for the root of a proof-of-work host with no `Accept` header and the answer
is `401` with `X-Guardian-Action: refuse` and
`X-Guardian-Reason: pow:unchallengeable`: Guardian will not issue a puzzle to
something that cannot render the interstitial, and a client sending no `Accept`
at all is exactly that. Add a browser-shaped one and the same request is
challenged:

```sh
curl -si 127.0.0.1:18071/auth -H 'X-Guardian-Host: example.com' \
  -H 'X-Guardian-URI: /' -H 'X-Guardian-IP: 198.51.100.8' \
  -H 'X-Guardian-UA: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Firefox/153.0' \
  -H 'Accept: text/html,application/xhtml+xml'
# HTTP/1.1 401 Unauthorized
# X-Guardian-Action: challenge
# X-Guardian-Difficulty: 16
# X-Guardian-Reason: pow:no_token
```

The client's own `Accept` reaches the guard request untouched, which is why this
works from `curl` at all.
:::

`X-Guardian-IP` is not strictly required (without it Guardian falls back to the
socket address), but send it anyway: it is what per-IP counters, blocks and
token binding key on, and `require_proxied: true` rejects a guard request that
arrives without it.

Other flags worth knowing while iterating:

```sh
go run ./cmd/guardiand -config guardian.yaml -t            # validate and exit (0 ok, 1 error)
go run ./cmd/guardiand -config guardian.yaml -healthcheck  # probe the listeners and exit
go run ./cmd/guardiand -version
```

A running daemon reloads its config on `SIGHUP` or
`POST /admin/reload`, and rejects a config that fails validation while keeping
the running one active, so a bad edit does not take the daemon down.

## Test and benchmark targets

| Target | What it covers |
|---|---|
| `make test` | The whole tree under `-race`. Fast, and the one to run constantly. |
| `make e2e` | Real Angie plus guardiand plus a backend, driven through Angie. Needs Docker. |
| `make e2e-nft` | The nftables block-offload path. Needs `nf_tables` and `NET_ADMIN`, and skips cleanly without them. |
| `make fuzz` | Every fuzz target for `FUZZTIME` each (default 30s): the URI decoder, WAF rules, config, the anomaly model, PoW redeem. |
| `make vet` | `go vet ./...`. |
| `make fmt` | `gofmt -w` over exactly the directories CI checks. |
| `make bench-regress` | Hot-path `allocs/op` against `allocs-baseline.txt`. Deterministic, so it also gates CI. |
| `make bench-report` | A hot-path snapshot of the current tree (`sec/op`, `B/op`, `allocs/op`) with the spread across runs. Manual, gates nothing, wants a quiet machine. |
| `make bench-store` | The store engines on Guardian's real write workload: single-spend CAS flood, TTL counters, mixed read/write, expiry reclaim. |

Narrowing down is plain `go test`:

```sh
go test -race -run TestRedeemRecordsSolve ./transport/http/
go test -tags e2e -run TestPoWFullSolveThroughAngie ./test/e2e/
go test -run '^$' -bench BenchmarkEvaluateDeny -benchmem ./core/
```

`B/op` is worth watching on the request path even when `allocs/op` holds: a
per-request struct crossing an allocator size class costs every request more
memory while the allocation count never moves. `make bench-report` is the
target that shows it.

For throughput, use [`guardian-loadtest`](/guide/load-testing) rather than a
benchmark. Benchmarks measure a function; the loadtest measures the daemon.

## What CI checks, and what it does not

Pipelines run on branches (merge-request pipelines are disabled, so the branch
pipeline is the one that matters).

| Job | What it runs | Notes |
|---|---|---|
| `format` | `gofmt -l` over `cmd core internal transport web test`, `go vet ./...`, and `go vet -tags e2e ./test/e2e/...` | The e2e vet is the only branch-side proof that the suite still compiles. |
| `test` | `go test -race -count=1 ./...` | |
| `bench-allocs` | `make bench-regress` | A new hot-path allocation fails here in seconds. |
| `govulncheck` | A pinned `govulncheck ./...` | Call-graph aware, so it only flags vulnerabilities the code actually reaches. |
| `alerts` | `promtool check rules` and `promtool test rules` over `deploy/alerts.yaml` | Those rules ship to operators verbatim, so a typo'd expression has to fail here. |
| `docs` | The VitePress build, on branches that touch `docs/**` | Dead-link checking is part of the build. |
| `e2e` | `make e2e` on the shell-executor runner | **Protected refs only.** |
| `build`, `wasm` | The three binaries plus the WASM guest | Tag pipelines additionally cross-compile, package, checksum, smoke-test and publish. |

Two gaps to plan around:

- **`e2e` never runs on a feature branch.** The shell runners are
  `ref_protected`, so the job is not even created outside `main` and tags: a
  job that cannot be assigned a runner would hang the pipeline instead. Run
  `make e2e` locally before merging anything that touches the request path or
  the Admin API, because nothing on the branch will catch it.
- **`make fuzz` is deliberately not a CI job.** A worthwhile sweep costs around
  18 minutes of runner time and has so far found nothing. Run it locally when
  you touch a parser, and commit any crasher it produces under `testdata/fuzz/`
  as a regression seed.

## Conventions

- **Every Go file starts with the three-line AGPL header** (project line,
  copyright, `SPDX-License-Identifier: AGPL-3.0-or-later`), tests included.
- **Comments carry the reasoning, not the mechanics.** Most of this codebase is
  tradeoffs (fail-open versus fail-closed, bounded versus complete, forgeable
  client input versus server measurement), and the next reader needs to know
  which way a call went and why, or they will "fix" it.
- **The hot path does not grow allocations by accident.** `allocs-baseline.txt`
  gates the auth, challenge and token paths. When a change legitimately needs
  an allocation, raise the baseline in the same commit and say why in the
  message. Only benchmarks whose counts are genuinely deterministic belong in
  that file: anything driving background goroutines swings with `GOMAXPROCS`
  and is excluded on purpose.
- **Fail-open is a contract, and it is explicit.** An action the transport does
  not recognise serves a 200 and logs it, rather than falling through to an
  accidental allow. Keep new code in that shape.
- **A config key is never just a struct field.** Adding one touches
  `core/config.go` (parse, validate, defaults), `guardian.example.yaml`,
  `core/config_test.go`, and the docs that claim to be complete:
  [Configuration Options](/reference/configuration), the relevant guide page,
  and `USAGE.md`. `challenge_farm` is a good worked example to grep for.
- **A new metric touches `core/metrics` and
  [the metrics reference](/reference/metrics)**, and needs a label-cardinality
  answer before it lands: a label must come from a bounded set (a config key,
  for instance), never from a request header. If it deserves alerting, it also
  belongs in `deploy/alerts.yaml` with a case in `deploy/alerts.test.yaml`.
- **An Admin API change updates
  [the Admin API reference](/reference/admin-api)**, which is written to match
  the handlers field for field.
- **A dashboard change gets a behavioural test**, not a new markup needle. See
  below.

## Seed the dashboard with traffic

An empty dashboard is hard to work on. `make seed` fills a throwaway instance
with a realistic mix (solved and failed proof of work, challenges, denies,
behavioural blocks, allowed traffic), from two shells:

```sh
go run ./cmd/guardiand -config test/seed/guardian.seed.yaml
make seed                  # two minutes
make seed SEEDTIME=5m
```

Then open `http://127.0.0.1:18072/admin/dashboard#token=seed-demo-token`. This
is not a load test: it generates variety, not throughput.

## Try a dashboard change against a running daemon

The dashboard is embedded in the binary with `go:embed`, so seeing an edit
against real data would otherwise mean a rebuild and a deploy.
`make dashboard-dev` serves `web/dashboard.html` from the working tree and
forwards every other `/admin/` path to a guardiand that is already running,
wherever it is:

```sh
make dashboard-dev                                      # the seed instance above
make dashboard-dev UPSTREAM=http://192.168.1.42:8072    # a real deployment
make dashboard-dev UPSTREAM=... DASHDEV_LISTEN=127.0.0.1:9000
```

Open `http://127.0.0.1:8073/admin/dashboard` and enter that daemon's admin
token. The edit loop is then save the file and reload the tab: the HTML is read
on every request.

Nothing about the page changes to make this work. Its URLs are origin-relative
(it fetches `/admin/stats`, and loads `chart.umd.min.js` relative to
`/admin/dashboard`), so any listener answering both the page and `/admin/*`
serves it unmodified. That means no CORS, no configuration key, and no special
build: the bearer token is forwarded untouched and the upstream authenticates
it exactly as it would for its own copy of the page.

::: warning It is a real daemon on the other side
The dashboard's write actions (unblock, clearing counters, blocking an IP) are
forwarded like everything else, so against a production upstream they act on
production.

The locally served page also carries no `Content-Security-Policy`. guardiand
sets a fitted one on its own dashboard route, and reproducing it here would
only let a local experiment fail for an unrelated reason, so this proves page
logic and not the policy.
:::

Passing `-page ""` serves the copy embedded in the build instead of the working
tree, which turns the same command into a plain viewer for a remote daemon:

```sh
go run ./test/dashdev -upstream http://192.168.1.42:8072 -page ""
```

This is deliberately a development command rather than a mode of `guardiand`.
Every in-daemon alternative charges the production binary for a development
convenience: letting the page live on another origin needs CORS on a
token-guarded admin API, serving the page off disk adds a filesystem read path
plus ambiguity about which HTML is live, and a forwarding mode inside guardiand
would put an operator-authenticated reverse proxy inside a security daemon.

## Testing the dashboard's own logic

The dashboard is one self-contained page, and a fair amount of what an operator
reads is decided by its inline script: the User-Agent classification behind
"Solve time by client", the bucket walk behind every p90, the rollups over the
decisions feed. That logic is covered by `web/dashboard_script_test.go`, which
lifts named top-level declarations out of `dashboard.html` and runs them in
[goja](https://github.com/dop251/goja), a pure-Go JavaScript interpreter, with
small stubs for the page's DOM builders. It needs no browser, no headless
Chrome and no `node` in CI, and it is a test-only dependency that is absent from
the shipped binary.

```go
vm := jsRuntime(t, "millis", "UA_CLASSES", "uaClass")
var got string
call(t, vm, `uaClass("Mozilla/5.0 (Linux; Android 15; Pixel 9) ... Mobile Safari/537.36")`, &got)
// got == "mobile"
```

Prefer adding a case there over asserting that a line of markup exists.
`transport/http/admin_assets_test.go` still checks that the served page contains
the identifiers the code expects, but a needle only proves a line is present,
never that it does the right thing.

## The end-to-end suite

`test/e2e` boots the real stack from `deploy/docker/compose.yaml` with
[testcontainers-go](https://golang.testcontainers.org/), drives traffic
**through Angie**, and asserts on decisions, `/metrics` and the Admin API:

```
Angie (auth_request)  ──►  guardiand  ──►  whoami backend
```

```sh
make e2e                                                    # everything
go test -tags e2e -run TestWAFRuleDeny ./test/e2e/          # one scenario
```

The suite picks three free host ports, brings the stack up, and tears it (and
its volumes) down again. The daemon's config for the run is
`deploy/docker/guardian.e2e.yaml`, with `guardian.e2e-chaos.yaml` and
`guardian.e2e-nft.yaml` for the store-outage and offload variants.

Two things about it repeatedly surprise people:

- **Every request from the host shares one source IP**, the Docker gateway. So
  a WAF `block` blocks *the whole test run*, and the harness clears such blocks
  through the Admin API around block-placing tests. Never hardcode a gateway
  address; read the blocked IP back from `/admin/blocks`.
- **The stack is real**, so a test that asserts on a fresh restart has to
  tolerate a daemon whose first write after recovery can still fail open. That
  is designed behaviour, not a flake, and the harness retries around it.

For poking at the stack by hand rather than through Go, bring the same compose
file up yourself; `deploy/docker/README.md` covers the topology and ports.

## Store backends

`store.backend` selects one of four implementations behind one interface:
`memory` (sharded in-memory, the default), `buntdb` and `pebble` (both need
`store.path`), and `redis` (Valkey-compatible, needs `store.addr`, and the
choice for a fleet sharing state). `store.sync` is rejected on `buntdb`,
whose single writer makes fsync-per-commit orders of magnitude slower; `pebble`
is the synchronously durable option.

Touching the store means running `make bench-store`, which exercises the
workload that actually matters (a single-spend CAS flood, TTL counters, mixed
read/write, expiry reclaim) rather than generic key/value throughput.

## Build and package

```sh
make build      # the three binaries into dist/
make wasm       # the optional http-wasm guest
make all        # both
make clean
```

Releases are cut as GitLab Releases, never by pushing a tag by hand: creating
the release makes the tag, and the tag pipeline is what cross-compiles amd64
and arm64, bundles `guardian.wasm`, the example config, the rules file and
`deploy/`, smoke-tests the exact archive it is about to publish (including
`guardiand -t` against the packaged example config), writes and GPG-signs
`SHA256SUMS`, uploads everything to the package registry, attaches the release
asset links, mirrors the artifacts to GitHub, and builds, pushes and
Cosign-signs the container image by immutable digest.

### Release signing setup

The published GPG trust anchor is
`E0C7 C029 005B 0CE6 A743 8BD5 71D1 1FF2 3454 B9D7`. Do not put its primary
private key in GitLab. Add a dedicated signing-only subkey locally, then export
only that subkey (the export carries a non-secret primary-key stub so verifiers
can build the certification chain):

```sh
PRIMARY=E0C7C029005B0CE6A7438BD571D11FF23454B9D7
gpg --quick-add-key "$PRIMARY" ed25519 sign 2y
gpg --with-subkey-fingerprint --list-secret-keys "$PRIMARY"

# Replace this with the new signing subkey fingerprint, including the !.
gpg --armor --export-secret-subkeys 'SIGNING_SUBKEY_FINGERPRINT!' \
  > guardian-release-signing-subkey.asc
base64 -w0 guardian-release-signing-subkey.asc; printf '\n'
```

Paste that entire single-line Base64 output into the GitLab variable
`RELEASE_GPG_PRIVATE_KEY_B64`. It is normal for the value to be long. Do not
paste the armored `.asc` contents directly, and do not use the primary private
key export.

Generate a separate passwordless Cosign key pair with `cosign
generate-key-pair`; it is not the GPG key. At both password prompts, press
Enter without entering a value. Configure these GitLab CI/CD variables as
**protected**, **masked and hidden**, with expansion off:

| Variable | Value |
|---|---|
| `RELEASE_GPG_PRIVATE_KEY_B64` | Single-line base64 output of the signing-subkey export |
| `COSIGN_PRIVATE_KEY_B64` | `base64 -w0 cosign.key` |
| `COSIGN_PUBLIC_KEY_B64` | `base64 -w0 cosign.pub` |

Do not create a `COSIGN_PASSWORD` CI/CD variable. The tag job supplies an
explicit empty value internally so Cosign does not try to open an interactive
password prompt for this passwordless key.

#### Key lifetime and rotation

The Base64 CI/CD variables are only storage and do not expire by themselves.
The keys encoded in them have different lifetime rules:

- The GPG signing subkey created with `2y` expires two years after creation.
  GPG then refuses to make new release signatures with it. Signatures made
  while it was valid remain cryptographically verifiable, and the primary
  fingerprint does not change.
- A self-managed Cosign key pair has no built-in expiration date. It remains
  usable until it is deliberately rotated or no longer trusted.

The current release signing subkey is
`FE4C 7419 8FE6 E66E ADB3 31BF 41B8 4FC6 1861 DA1B`; it expires on
2028-08-11 at 21:08:13 UTC. The primary key and its fingerprint do not expire.

Check the GPG subkey expiry periodically and set a reminder at least 60 days
before it expires:

```sh
gpg --with-subkey-fingerprint --list-secret-keys "$PRIMARY"
```

To extend the same signing subkey for another two years, use its full
fingerprint without `!`, then export it again:

```sh
SIGNING_SUBKEY=REPLACE_WITH_FULL_SIGNING_SUBKEY_FINGERPRINT
gpg --quick-set-expire "$PRIMARY" 2y "$SIGNING_SUBKEY"
gpg --armor --export-secret-subkeys "${SIGNING_SUBKEY}!" \
  > guardian-release-signing-subkey.asc
base64 -w0 guardian-release-signing-subkey.asc; printf '\n'
```

Replace `RELEASE_GPG_PRIVATE_KEY_B64` with that new Base64 output. The secret
key material is unchanged, but the new export carries the updated expiration
metadata. Alternatively, create a new signing-only subkey and replace the
variable with its export.

To rotate Cosign, generate a new passwordless pair and replace
`COSIGN_PRIVATE_KEY_B64` and `COSIGN_PUBLIC_KEY_B64` together before creating a
release. Each existing release keeps its matching `cosign.pub`, authenticated
by that release's GPG-signed `SHA256SUMS`, so older signatures remain
verifiable with their original public key.

Delete the plaintext secret exports after the variables are configured and a
test signature succeeds; retain encrypted offline backups. Protected tag jobs
fail rather than publish an unsigned release when any signing material is
missing or mismatched. The release contains `SHA256SUMS.asc`, `RELEASE-KEY.asc`
and `cosign.pub`; `cosign.pub` is itself listed in the GPG-signed checksum file.

## Documentation

```sh
make docs-dev   # local site with hot reload
make docs       # production build, the same one CI runs
```

The site rebuilds and deploys from `main` whenever `docs/**` changes. Dead-link
checking is part of the build, so a broken cross-reference fails the branch
pipeline rather than the deploy.

The reference pages are written to match the code field for field, so
`/reference/configuration` tracks `core/config.go`, `/reference/admin-api`
tracks the admin handlers, and `/reference/metrics` tracks `core/metrics`. A
change to one of those files that leaves its reference page alone is an
incomplete change.

## Reporting a security issue

Do not open a public issue. `SECURITY.md` has the private reporting process
(email, or a confidential GitLab issue) and what to expect.
