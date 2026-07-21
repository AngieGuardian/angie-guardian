# Run it in Production

## Configuration

Guardian is driven by a single YAML file. There is no auto-detected default
location: `guardiand` requires `-config <path>`, and everything on this page
(the systemd unit, the Docker mounts, the healthcheck) uses the conventional
path **`/etc/guardian/guardian.yaml`**. Keep it root-owned and merely
*readable* by the service (`root:guardian`, mode `0640`), never writable: the
config is policy, and a compromised daemon must not be able to rewrite its own
policy. The file holds no secrets by default; the signing key and admin token
it points at do, and those live in the service-owned state directory (see
[Filesystem layout and ownership](#filesystem-layout-and-ownership)).

Two references cover the file itself, so this guide does not repeat them:

- The [configuration reference](/reference/configuration) documents every
  option, its type, default and constraints.
- The examples page ends with a
  [full annotated example](/examples#the-full-annotated-example) you can copy as
  a starting point, alongside smaller task-focused snippets.

Validate an edit before applying it with `guardiand -config
/etc/guardian/guardian.yaml -t` (the systemd unit does this on every start).
Most of the file hot-reloads on `systemctl reload guardiand` (domains, lists,
thresholds, difficulty); listeners, the store and keys need a restart.

## Installation

Run guardiand under systemd on a host, or as a container. Both load the same
config file described above.

### systemd

For the complete first-install sequence, start with the release-first
[Getting Started guide](/guide/getting-started). In short, choose a pinned
release archive from the
[releases page](https://gitlab.melroy.org/melroy/angie-guardian/-/releases)
(under **Assets -> Packages**) and unpack it; it contains the binaries,
`guardian.example.yaml`, and the `deploy/` directory (unit file and starter
WAF rules) used below. Then install it as a service:

```sh
sudo install -Dm755 guardiand /usr/local/bin/guardiand
getent group guardian >/dev/null || sudo groupadd --system guardian
id guardian >/dev/null 2>&1 || sudo useradd --system --gid guardian \
  --home-dir /var/lib/guardian --shell /usr/sbin/nologin guardian

# Immutable config: root-owned, service-readable, never service-writable.
# The dir group must be set explicitly (systemd's ConfigurationDirectory=
# applies the 0710 mode but always leaves ownership at root:root).
sudo install -d -o root -g guardian -m710 /etc/guardian
sudo install -d -o root -g guardian -m750 /etc/guardian/rules.d
sudo install -o root -g guardian -m640 guardian.yaml /etc/guardian/guardian.yaml
# The starter signature rules the example config enables; without this file,
# `guardiand -t` (and so the unit's ExecStartPre) fails with
# "open /etc/guardian/rules.d/common.yaml: no such file or directory".
# Keep this one shared file: per-host exceptions belong in guardian.yaml via
# waf.keywords.disabled_rule_ids (see the configuration guide), not in
# diverging copies.
sudo install -o root -g guardian -m640 deploy/rules-common.yaml /etc/guardian/rules.d/common.yaml

sudo install -Dm644 deploy/guardiand.service /etc/systemd/system/guardiand.service
sudo systemctl daemon-reload
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # liveness -> ok
curl -s localhost:8072/readyz          # readiness -> {"ready":true,...}
```

`guardian.yaml` here is your edited copy of the shipped
`guardian.example.yaml`. Nothing under `/var/lib/guardian` needs manual setup:
the unit's `StateDirectory=` creates it owned by the service user, and
guardiand generates the signing key and admin token there on first start.

#### Filesystem layout and ownership

The unit and the install commands above deliberately split the two directories
by who may write them:

| Path | Contents | Owner | Mode |
|---|---|---|---|
| `/etc/guardian/` | immutable configuration: `guardian.yaml`, `rules.d/` | `root:guardian` | dir `0710`, subdirs `0750`, files `0640` |
| `/var/lib/guardian/` | generated state: `ed25519.key`, `keys.d/`, `admin.token`, the store | `guardian:guardian` | dir `0700`, secrets `0600` |

Configuration is **read-only for the service**: the daemon runs as `guardian`
and reaches config files through group permissions alone, so even a fully
compromised guardiand cannot rewrite its own policy, rules, or unit-visible
paths. Directory mode `0710` gives the group traverse-only access: it can open
the known file paths the config names but cannot list the directory or create
files in it. Generated state, which the daemon must create and rotate (the
Ed25519 signing key, the retired-key archive, the auto-generated admin token,
the pebble/buntdb store), lives under the `StateDirectory` that systemd
creates and chowns to the service user.

Two systemd details make the explicit `install`/`chown` steps above
load-bearing rather than decorative. First, systemd applies
`ConfigurationDirectoryMode=` but **excludes `ConfigurationDirectory=` from
the automatic chown** it performs for `StateDirectory=`, so `/etc/guardian`
stays `root:root` unless installation sets the group; with mode `0710` and the
wrong group, the service user cannot even traverse to `guardian.yaml` and the
unit fails at `ExecStartPre`. Second, `ReadWritePaths=` is **not** a
substitute for ownership: it only relaxes the systemd sandbox
(`ProtectSystem=strict`) and never overrides normal Unix ownership and mode
checks, which is why the unit grants write access to nothing under `/etc`.

#### Startup readiness and watchdog

The shipped unit is `Type=notify`: guardiand speaks
[sd_notify](https://www.freedesktop.org/software/systemd/man/sd_notify.html)
with no extra dependency, signalling `READY=1` only once every configured
listener answers `/healthz`. That is *liveness*: it deliberately does not wait
on the store, because Guardian serves fail-open and a store outage must not
stop the unit from starting. For the "is the store actually working" question
see [`/readyz`](#probes-liveness-vs-readiness).
So `systemctl start` blocks until the service is
genuinely serving, and `systemctl status` reflects real readiness rather than
"the process forked". This matters because Guardian fails open: a daemon wedged
before it binds would otherwise look active while every request sails through
unchecked.

`WatchdogSec=30s` arms the watchdog: guardiand pings it at half that interval,
so a hung daemon is killed and restarted instead of sitting there looking
healthy. Loosen the interval if you run with an aggressive `GOGC` and very long
GC pauses, or drop the line to disable the watchdog while keeping readiness.

This is systemd-only. The daemon auto-detects `$NOTIFY_SOCKET`, so running it
by hand or under Docker (where the Compose healthcheck gates readiness instead)
needs no change.

### Docker

Every release publishes a prebuilt sidecar image (distroless, nonroot,
version-stamped) to the project container registry, so you don't have to
build anything:

```sh
export GUARDIAN_VERSION=REPLACE_WITH_RELEASE_TAG
docker pull "registry.melroy.org/melroy/angie-guardian:${GUARDIAN_VERSION}"
```

A minimal production compose service, with the store and signing key on
named volumes so blocks and issued tokens survive restarts:

```yaml
services:
  guardiand:
    image: registry.melroy.org/melroy/angie-guardian:${GUARDIAN_VERSION:?set GUARDIAN_VERSION to a release tag}
    restart: unless-stopped
    # Publish the two listeners on the host loopback only: Angie (on the
    # host or another container) talks to 8071; you talk to 8072.
    ports:
      - "127.0.0.1:8071:8071"
      - "127.0.0.1:8072:8072"
    volumes:
      - ./guardian.yaml:/etc/guardian/guardian.yaml:ro
      - ./rules-common.yaml:/etc/guardian/rules.d/common.yaml:ro
      - guardian-state:/var/lib/guardian
      - guardian-keys:/etc/guardian/keys
    healthcheck:
      test: ["CMD", "/usr/local/bin/guardiand", "-config", "/etc/guardian/guardian.yaml", "-healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 5
volumes:
  guardian-state:
  guardian-keys:
```

The built-in probe loads the mounted config and requires both configured
listeners to answer `/healthz`; merely being able to launch the binary is not
considered healthy. This is a **liveness** check on purpose: it must not follow
the store, or a store outage would restart-loop a container that is still
(fail-open) serving traffic. Point your orchestrator's readiness probe at
[`/readyz`](#probes-liveness-vs-readiness) instead.

Inside the container, set `listen: 0.0.0.0:8071` plus `trusted_proxy: true`
and `admin.listen: 0.0.0.0:8072` in `guardian.yaml` (the loopback-only
`ports:` binding above is what keeps them off the network), and point the
signing key and generated admin token at the persistent key volume:
`signing_key_file: /etc/guardian/keys/ed25519.key` and
`admin.token_file: /etc/guardian/keys/admin.token`. Otherwise a token file
outside a volume is regenerated when the container is replaced.
Hot reload works as usual: `docker kill -s HUP <container>` or
`POST /admin/reload`.

For a complete, runnable example (including Angie and a demo backend) see
`deploy/docker/compose.yaml` in the repo; it builds the image from source
because the e2e suite exercises the working tree, but swapping `build:` for
`image:` gives the production shape above.

## Running the anomaly trainer

`guardian-train` is an offline batch job, not a second daemon. It reads a
representative window of Angie JSON access logs, builds a complete replacement
baseline for every domain with enough usable requests, writes one model
artifact, and exits. `guardiand` never learns from live requests: it only reads
the artifact named by `waf.anomaly.model` and scores requests against it. See
[Train the Anomaly Model](/guide/anomaly) for the log format, features and
threshold-tuning workflow.

### Preferred systemd timer

On a systemd installation, use the shipped
[`guardian-train.service`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/guardian-train.service)
and
[`guardian-train.timer`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/guardian-train.timer)
templates. The timer runs weekly with up to 30 minutes of random delay; the
one-shot service trains at low CPU/I/O priority in a hardened, networkless
sandbox. Its update helper reads plain and gzip-compressed rotations, rejects a
trainer/daemon version mismatch, a candidate that omits an expected domain, or
one that exceeds the malformed/schema-invalid line limit. When a live artifact
already exists, it scores the configured comparison window against both the
live and candidate artifacts and rejects insufficient coverage or excessive
mean/p95 score drift. It keeps JSON reports and the previous artifact, then
promotes an accepted candidate with an atomic rename.

Install the trainer from the same release archive as the daemon, then install
and configure the templates:

```sh
sudo install -Dm755 guardian-train /usr/local/bin/guardian-train
sudo install -Dm755 deploy/guardian-train-update \
  /usr/local/libexec/guardian-train-update
sudo install -Dm644 deploy/guardian-train.service \
  /etc/systemd/system/guardian-train.service
sudo install -Dm644 deploy/guardian-train.timer \
  /etc/systemd/system/guardian-train.timer
sudo install -o root -g root -m600 deploy/guardian-train.env \
  /etc/guardian/trainer.env

# Replace the placeholder domains and align the log retention/pattern with the
# representative 7-14 day window you want to train on.
sudoedit /etc/guardian/trainer.env

sudo systemctl daemon-reload
# Run once interactively and inspect its domain/request summary before enabling
# unattended updates.
sudo systemctl start guardian-train.service
sudo journalctl -u guardian-train.service -n 50 --no-pager
```

The unit runs as root because it must read restricted Angie logs and promote a
root-owned model under `/etc`, but its systemd sandbox hides Guardian's
service-owned runtime state, removes network access and makes the rest of the
filesystem read-only. The promotion directory remains visible and writable, so
keep unrelated secrets outside `/etc/guardian` where practical. Keep
`/etc/guardian/model.json` read-only to the `guardian` daemon, just like
`guardian.yaml` and the WAF rules: a compromised daemon must not be able to
replace the baseline it enforces. The template also starts memory reclaim at
1 GiB and caps the batch at 2 GiB, so hostile high-cardinality input fails the
job instead of exhausting the host. If a measured representative run genuinely
needs more, raise `MemoryHigh` and `MemoryMax` with a systemd drop-in rather
than removing the cap.

For the first model, promote the file before enabling `waf.anomaly`, then test
and reload the config:

```sh
sudo -u guardian /usr/local/bin/guardiand \
  -config /etc/guardian/guardian.yaml -t
sudo systemctl reload guardiand
sudo systemctl enable --now guardian-train.timer
sudo systemctl list-timers guardian-train.timer
```

Later model replacements need no signal or restart. Each instance checks the
configured model every 10 seconds using a content hash and logs `anomaly model
reloaded` after accepting it. An unreadable, oversized or invalid replacement
leaves the previous model active in memory, but a future daemon restart still
needs a valid file on disk. Retain the last accepted candidate so you can
atomically promote it again if a new baseline proves bad. The shipped helper
does this at `/var/lib/guardian-training/model.previous.json`.

Before enabling the timer, define its input window and acceptance checks in
`/etc/guardian/trainer.env`:

- Rebuild from the whole representative window, including the relevant rotated
  logs. Training is not incremental; feeding only the newest file forgets the
  older traffic distribution. Segment discovery and exact aggregation make two
  complete passes, so compressed inputs are decompressed twice; size the timer's
  runtime window accordingly.
- Set `GUARDIAN_TRAIN_EXPECTED_DOMAINS` to every named domain that enables
  anomaly scoring. The job rejects the candidate if any required domain lacks
  the configured minimum number of eligible requests.
- Do not promote a window dominated by an attack, load test, launch or outage.
  Successful allowed responses below status 400 are eligible, so a successful
  bot campaign can otherwise become part of “normal”.
- Keep `GUARDIAN_TRAIN_MAX_INVALID=0` unless you have investigated and accepted
  a specific logging defect. Required fields, types, bounds, duplicate keys,
  method/URI syntax, status range, and Guardian action are validated strictly.
  If the log directory also contains unprotected vhosts, narrow
  `GUARDIAN_TRAIN_LOG_PATTERN` so their empty Guardian actions never enter this
  job.
- Size `GUARDIAN_TRAIN_MIN_SEGMENT_REQUESTS` and
  `GUARDIAN_TRAIN_MAX_SEGMENTS` so useful route/method baselines have real
  support without turning every endpoint into its own thin population.
- Prefer a held-out `GUARDIAN_TRAIN_COMPARE_LOG_PATTERN` when retention permits.
  Tune the mean and p95 delta gates from deliberate site changes, and inspect
  `/var/lib/guardian-training/comparison-report.json` before relaxing them.
- After promotion, confirm the reload log and watch the dashboard plus
  `guardian_anomaly_baseline_misses_total`, baseline-selection counters, and
  `guardian_anomaly_score` before tightening either enforcement threshold.

The timer is intentionally weekly rather than hourly or daily: refreshing too
quickly can teach a temporary event as normal before anyone notices. Retrain
manually after an intentional site change when waiting for Sunday makes no
sense. During an attack, load test, launch or outage, create
`/etc/guardian/trainer.disabled`; the service's condition then skips scheduled
training until you remove that sentinel.

The production container image contains `guardiand` only. Run the release's
`guardian-train` binary on the host or in a separate controlled batch job, then
mount a model **directory** read-only into every Guardian container:

```yaml
services:
  guardiand:
    volumes:
      - ./guardian-models:/etc/guardian/models:ro
```

Point `waf.anomaly.model` at `/etc/guardian/models/model.json` and atomically
rename the candidate inside `./guardian-models`. Mounting the directory matters:
replacing a single bind-mounted file can leave a container attached to the old
inode. In a replica fleet, distribute the same accepted artifact to every node;
the shared Redis/Valkey store does not distribute models. Confirm the reload on
each instance before considering the rollout complete.

## Choosing a store backend

Guardian keeps TTL state (IP blocks, counters, spent challenges, and bot
verdicts) in a pluggable store. Signing keys remain in
`signing_key_file`/`previous_key_dir` and replicas share those files separately:

- **memory**: single instance, state lost on restart. It is a sharded in-memory
  store (per-shard locks, not one global lock), so unlike a single-writer store
  its write path scales with cores and does not bottleneck on the spent-marker
  CAS or counter increments under a flood of *new* clients. Fine for dev, and a
  viable single-instance production choice for a site that can re-learn blocks
  and re-issue challenges after a restart (a solved challenge could be replayed
  only within its remaining, short, `challenge_ttl` window across a restart).
- **pebble**: single instance, persistent, and the **recommended durable
  backend**. Pebble is an LSM engine (CockroachDB's), so a write hits the WAL and
  an in-memory memtable and is flushed to disk in the background rather than
  fsync'ing every commit. It sustains ~39k challenge writes/s with `sync: false`
  (the default), and ~25k/s with `sync: true` (fsync every write, fully durable).
  Its state lives in a directory (set `store.path` to a directory).
- **buntdb**: single instance, persistent, stored in a **single file** (simpler
  to back up or copy). In its async default (`sync: false`) it matches Pebble
  (~36k challenge writes/s). It is a single-writer store, so `sync: true`
  (fsync-per-commit) would collapse it to a few hundred writes/s, so guardiand
  **refuses to start** with `backend: buntdb` + `sync: true` and points
  you to Pebble for synchronous durability. Set `store.path` to a file.
- **redis**: multi-instance. Works with both Redis and
  [Valkey](https://valkey.io/) (the open-source Redis fork), a drop-in
  replacement (same wire protocol, same `backend: redis` value). This is the
  shared store that lets replicas behind a load balancer see each other's blocks
  and single-spend markers; the embedded backends above are single-node only.

Both durable embedded backends take a `store.sync` flag: `false` (default) is
fast and loses only the unflushed tail on a power/OS crash (a bounded,
≤`challenge_ttl` replay window), while `true` fsyncs every write (only worth it
on Pebble).

Guardian's Redis client currently uses plaintext TCP and its keys are not
prefixed per deployment. Put Redis/Valkey on loopback or a private,
authenticated network (or reach it through a verified TLS/mTLS tunnel), and
allocate a fresh, dedicated logical database on a Redis/Valkey server to each
Guardian deployment. Never point unrelated staging/production sites at the
same database: blocks, challenges, counters, bot verdicts, and fleet posture
would collide.

`store.addr` uses the standalone Redis protocol client; Redis Cluster is not
currently supported. Guardian's atomic active-block maintenance touches a
block key and the shared index in one script, which is not a cross-slot Cluster
operation. Use a stable TCP endpoint in front of your replicated Redis/Valkey
service when you need server failover.

The rule of thumb from the
[measured numbers](/guide/what-is-guardian#performance): the backend choice only
affects your *new-client* rate, i.e. the clients that trigger a challenge write.
The read paths (`allow`/`token`/`deny`) are backend-independent at ~150–176k
req/s, because the [block mirror](/guide/block-offload) makes every embedded
backend authoritative, so after the seed scan the allow/token path does zero store
reads. redis is the exception: it stays read-through, keeping one network read
per request so a block placed by another replica applies immediately, the price
of multi-instance correctness.

So the write path is the deciding factor: `pebble` ~39k challenge writes/s
(async) or ~25k/s (sync), `buntdb` ~36k/s (async only). Under
[attack mode](/guide/attack-mode), issuance switches to a stateless path with no
write at issue time, so these numbers bound your *sustained, normal-mode*
new-client rate, not the flood case. Verified tokens are cached in-process
(~144 ns vs ~43 µs for a full Ed25519 verification), so a returning client's
request stays on the fast read path regardless of backend.

### Multi-instance (Redis/Valkey)

To run replicas behind a load balancer, point every instance at one shared
Redis or Valkey instance and share the signing key + `previous_key_dir` across
them, so any instance verifies any other's tokens and sees any other's blocks.
Valkey is a fully compatible drop-in replacement for Redis; the configuration
is identical for both.

```yaml
store:
  backend: redis            # same value for both Redis and Valkey
  addr: 127.0.0.1:6379
  # password: ""            # or the REDIS_PASSWORD env var
signing_key_file: /var/lib/guardian/ed25519.key   # same file on every replica
previous_key_dir: /var/lib/guardian/keys.d        # same lock-capable shared filesystem
```

Both key paths must be on one filesystem that provides cross-host advisory
locking and atomic rename semantics (verify those properties for your NFS or
distributed filesystem). Asynchronous copies such as rsync or Syncthing are
not safe with multiple rotators: replicas do not share Guardian's `flock` and
can create competing keys. If files must be distributed asynchronously,
designate exactly one instance as the rotator and complete distribution before
allowing another rotation.

Key refresh and token minting deliberately fail closed while either key path
is unreadable. Prefer local disk for a single-host deployment. For multiple
hosts, use a low-latency, reliably mounted shared filesystem and include mount
interruption/recovery in the soak: a flaky NFS or distributed mount can cause
a brief fleet-wide challenge/token outage.

## GC tuning for peak throughput

At tens of thousands of requests per second, guardiand's read paths are
bound by Go's garbage collector, not the store: a freshly started daemon has
a small heap, so at high allocation rates the GC runs almost continuously.
On the [benchmark machine](/guide/load-testing#benchmark-results), starting
guardiand with `GOGC=800` raised the read-path throughput by about 20%. `GOGC`
sets how much the heap grows between collections (the default is 100); raising
it runs the GC less often, so the trade is a larger heap for less GC CPU.

On a host or container where guardiand owns the memory, the
[Go GC guide](https://go.dev/doc/gc-guide) recommends pairing a high `GOGC`
with `GOMEMLIMIT`: turn `GOGC` up for the throughput win, and set `GOMEMLIMIT`
as a safety cap so the larger heap cannot OOM (the runtime does extra GC only as
it nears the limit). `GOMEMLIMIT` is a **soft** limit: leave 5-10% headroom for
memory the runtime does not track, and never set it to the machine's total RAM,
since a too-tight limit can thrash the GC into a slowdown worse than an OOM.
Skip `GOMEMLIMIT` when the host's memory is shared with other processes.

Set these in the systemd unit's `Environment=` (see
[`deploy/guardiand.service`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/guardiand.service))
and measure with `guardian-loadtest`; at typical production rates the default is
fine.

## Memory footprint

guardiand's in-process memory is bounded independently of traffic, so a flood
of distinct IPs, hosts, User-Agents or URLs cannot grow it without limit (no
remote OOM). The client-keyed structures and their caps:

- **Verified-token cache**: at most 2^17 entries (~5 MiB); wholesale-reset when
  full, entries repopulate cheaply on the next verify.
- **Counter cache** (issuance rate limit + farming escalation): at most 2^17
  entries. At capacity it reclaims only clean cached totals; entries carrying
  unapplied store work are retained. If every entry is protected, unseen keys
  remain uncached until a drainer makes room, rather than erasing pending
  reconciliation state.
- **Recent-decisions ring** (admin/dashboard feed): fixed 512 entries
  (~100 KiB), overwrite-oldest. Holds raw host/URI/UA but never grows.
- **Bot-verification in-flight map**: bounded by concurrent lookups, not
  distinct IPs (entries are added and removed within one call, and a
  concurrency cap sheds excess). The verification *results* live in the store
  with a TTL, not in-process.
- **Prometheus label cardinality**: the `domain` label collapses unconfigured
  hosts to `default`, and `reason` collapses to a fixed set of stage prefixes
  (`waf`, `denylist`, `geo`, …), so rule IDs, feed names and Host-header
  floods never create new series.

Everything else keyed by client input (blocks, spent challenges, bot verdicts)
lives in the store with a TTL, so its memory is the store's concern, not the
daemon's. A steady-state instance sits in the low tens of MiB plus whatever
`GOGC`/`GOMEMLIMIT` you allow the heap to grow to between collections.

## Dashboards and metrics

### Built-in dashboard

Guardian ships its own reporting dashboard: set `admin.dashboard: true` and open
`GET /admin/dashboard`. It gives you a live, at-a-glance view with no extra
services to run: active blocks with one-click block/unblock, the recent
deny/challenge feed, activity and distribution graphs (decisions over time, the
proof-of-work funnel, solve-time and anomaly histograms), a top-offenders panel,
per-domain feature status, and, when pointed at Angie's API, real server traffic.
For most single-instance deployments this is all you need. See
[Admin API & Dashboard](/guide/admin#the-reporting-dashboard) for the full tour.

### Prometheus + Grafana

For long-horizon history, alerting, or fleet-wide aggregation across replicas,
scrape the Prometheus metrics at `/metrics` on the admin listener (open to
scrapers, no token needed): decisions by action/reason/domain, challenge
lifecycle, PoW solve-time and anomaly-score histograms, blocks placed, store op
latency, and end-to-end `Evaluate()` latency. Import
`deploy/grafana-dashboard.json` for a ready-made Grafana dashboard. This
complements the built-in dashboard rather than replacing it: the built-in view
is per-instance and live, while Prometheus retains history and sums across a
fleet.

### Alerting

`deploy/alerts.yaml` ships ready-made Prometheus rules. Point your `rule_files`
at it:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/angie-guardian-alerts.yaml
```

Every rule selects `job="angie-guardian"`. If you scrape Guardian under a
different job name, search/replace it in the file or nothing will ever fire.
Validate after editing with `promtool check rules` and `promtool test rules`
(the shipped `deploy/alerts.test.yaml` covers the rules and their sample
floors; CI runs both on every pipeline).

| Alert | Fires on | Severity |
|---|---|---|
| `GuardianStoreDown` | `guardian_store_up == 0` for 2m | critical |
| `GuardianScrapeAbsent` | no scrape for 5m (including a vanished target) | critical |
| `GuardianStoreErrors` | >5% store op errors over 10m, at least 20 ops | warning |
| `GuardianChallengeSolveCollapse` | <30% of challenges solved over 15m, at least 50 issued | warning |
| `GuardianBlockRateSpike` | 5m block rate >5x the pre-spike hour and >1/min | warning |
| `GuardianOffloadDegraded` | an enforcement sink dropped to in-daemon | warning |
| `GuardianLoadShedding` | sustained shedding for 10m | warning |
| `GuardianStatelessSpendFallback` | single-spend CAS failing for 10m | warning |
| `GuardianAttackMode` | posture above normal for 10m | info |

**If you ship only one alert, ship `GuardianStoreDown.`** Guardian
[fails open](/guide/threat-model) by design: when the store is unreachable,
stages abstain, challenge issuance falls back to stateless minting, single-spend
degrades to per-replica, and every request sails through. The process stays up,
both listeners keep answering `/healthz`, and `systemctl status` still says
`active`. Nothing about that state is visible without this gauge.

The thresholds are starting points chosen to be quiet on a healthy instance.
Every ratio and rate rule carries an explicit sample floor (at least N
operations, at least N challenges, at least one block per minute) so a near-idle
instance cannot produce a screaming ratio from two samples; raise the floors on
busy deployments.

### Probes: liveness vs readiness

The two health endpoints answer different questions, and wiring them the same
way defeats the point:

- **`/healthz`** (both listeners) is **liveness**: is the process serving? It
  never consults the store. Use it for container health checks, systemd
  readiness sequencing, and the `-healthcheck` flag. Tying liveness to the store
  would kill containers that are still (fail-open) protecting traffic and turn a
  degradation into an outage.
- **`/readyz`** (admin listener) is **readiness**: is the shared state Guardian's
  stateful protection depends on actually working? It returns `503` when the
  background store probe is pending, failing or stale. Use it for load-balancer
  readiness, Kubernetes `readinessProbe`, and the "should this replica take
  traffic" question.

`/readyz` only reads the last probe snapshot, so probing it aggressively costs
nothing and cannot turn health checks into store traffic. A degraded nftables
sink or a raised attack posture appear in the body but never change the status
code: both still protect traffic.

## Key rotation

`POST /admin/rotate-key` archives the current Ed25519 key into
`previous_key_dir` and atomically installs a new one. A non-empty shared
`previous_key_dir` is required. Rotations are serialized on the shared key
path, archive names cannot collide, and live replicas refresh the key set
automatically. Token signing reads the current key under the shared rotation
lock; stateless challenge issuers use a rate-limited pre-issuance refresh so a
quiet replica cannot remain indefinitely on a stale key without adding a file
lock/read to every attack-path challenge. Current and still-live retired
secrets keep in-flight stateless challenges redeemable through the rotation.
Retired keys accept only tokens issued before rotation, and no accepted token
may have a lifetime longer than seven days.
Older archive files may remain for operator retention, but Guardian drops them
from the in-memory verification set once that seven-day horizon has elapsed.
Each replica still enumerates the archive directory during refresh, so archive
or delete files beyond the horizon to bound directory-scan cost. Expired
timestamped key contents are skipped before file reads and key parsing.
