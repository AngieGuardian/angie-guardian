# Run it in Production

## Configuration

Guardian is driven by a single YAML file. Unless `-config <path>` overrides
it, `guardiand` uses the conventional path **`/etc/guardian/guardian.yaml`**.
The systemd unit, Docker mounts, and healthcheck state that path explicitly.
Keep it root-owned and merely
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

For an active HTTP attack, use the
[DDoS incident runbook](/guide/ddos-incident-runbook). Rehearse its controls and
measure the target host with the [staging drill](/guide/ddos-drill) before an
incident. Guardian is a Layer-7 authorization sidecar; volumetric bandwidth,
connection, TLS-handshake, and QUIC attacks require upstream/CDN/L4 mitigation.

Validate an edit before applying it with `guardiand -t` (the systemd unit does
this on every start).
Most of the file hot-reloads on `systemctl reload guardiand` (domains, lists,
thresholds, difficulty); listeners, the store and keys need a restart.

The shipped profile uses `log_level: warn`: it retains warnings and errors
without writing a line for every routine challenge, refusal, or deny decision
to the systemd journal. For short-lived diagnosis, change it to `info` and run
`systemctl reload guardiand`; decision records include client identity and the
full raw URI/query, so restrict journal access and retention. The same setting
applies to container logs.

## Installation

Run guardiand under systemd on a host, or as a container. Both load the same
config file described above.

### systemd

#### Recommended: one-command installer

On a supported Debian or Ubuntu systemd host, install the latest GitHub release
with the host installer:

```sh
curl -fsSL https://raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh | sudo bash
```

The installer downloads and verifies the release archive, installs
`guardiand`, creates the `guardian` service account and configuration layout,
installs the systemd unit and Angie snippets, validates the configuration, and
enables and starts the service. Existing local configuration, rules, unit, and
Angie snippet files are preserved; mismatches are reported for manual review.

It does not edit Angie virtual hosts or reload Angie. After reviewing
`/etc/guardian/guardian.yaml`, wire the three required Guardian integration
snippets into your Angie configuration as described in the
[Getting Started guide](/guide/getting-started). Then run `angie -t` and reload
Angie yourself. The two Angie hardening snippets are optional.

#### Optional: manual installation

Use the manual procedure below when you need to install a pinned release or
want to perform each installation step yourself. For the complete first-install
sequence, start with the release-first [Getting Started guide](/guide/getting-started).

In short, choose a pinned release archive from
[GitHub Releases](https://github.com/AngieGuardian/angie-guardian/releases)
(under **Assets**) and unpack it; it contains the binaries,
[`guardian.example.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/guardian.example.yaml), and the `deploy/` directory (unit file and starter
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
# The starter WAF rules the example config enables; without this file,
# `guardiand -t` (and so the unit's ExecStartPre) fails with
# "open /etc/guardian/rules.d/common.yaml: no such file or directory".
# Keep this shared baseline: domain files append via waf.rules.files, while
# exceptions belong in guardian.yaml via waf.rules.disabled_ids (see the
# configuration guide), not in diverging copies.
sudo install -o root -g guardian -m640 deploy/rules-common.yaml /etc/guardian/rules.d/common.yaml

sudo install -Dm644 deploy/guardiand.service /etc/systemd/system/guardiand.service
sudo systemctl daemon-reload
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # liveness -> ok
curl -s localhost:8072/readyz          # readiness -> {"ready":true,...}
```

`guardian.yaml` here is your edited copy of the shipped
[`guardian.example.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/guardian.example.yaml). Nothing under `/var/lib/guardian` needs manual setup:
the unit's `StateDirectory=` creates it owned by the service user, and
guardiand generates the signing key and admin token there on first start.

#### Filesystem layout and ownership

The unit and the install commands above deliberately split the two directories
by who may write them:

| Path | Contents | Owner | Mode |
|---|---|---|---|
| `/etc/guardian/` | immutable configuration: `guardian.yaml`, `rules.d/` | `root:guardian` | dir `0710`, subdirs `0750`, files `0640` |
| `/var/lib/guardian/` | generated state: `ed25519.key`, `keys.d/`, `admin.token`, the store | `guardian:guardian` | dir `0700`, secrets `0600` |
| `/run/guardian/` | default host auth Unix socket | `guardian:guardian` | dir `0755`, socket `0660` by default; configurable with `socket_mode` |

Configuration is **read-only for the service**: the daemon runs as `guardian`
and reaches config files through group permissions alone, so even a fully
compromised guardiand cannot rewrite its own policy, rules, or unit-visible
paths. Directory mode `0710` is traverse-only: the group can open the file
paths the config names but cannot list the directory or create files in it.
Generated state the daemon must create and rotate (the Ed25519 signing key,
the retired-key archive, the auto-generated admin token, the pebble/buntdb
store) lives under the `StateDirectory` that systemd creates and chowns to the
service user.

Two systemd details make the explicit `install`/`chown` steps above
load-bearing rather than decorative:

- systemd applies `ConfigurationDirectoryMode=` but **never chowns
  `ConfigurationDirectory=`** (unlike `StateDirectory=`), so `/etc/guardian`
  stays `root:root` unless installation sets the group; with mode `0710` and
  the wrong group, the service user cannot even traverse to `guardian.yaml`
  and the unit fails at `ExecStartPre`.
- `ReadWritePaths=` is **not** a substitute for ownership: it only relaxes the
  systemd sandbox (`ProtectSystem=strict`) and never overrides normal Unix
  ownership and mode checks, which is why the unit grants write access to
  nothing under `/etc`.

#### Startup readiness and watchdog

The shipped unit is `Type=notify`: guardiand uses
[sd_notify](https://www.freedesktop.org/software/systemd/man/sd_notify.html)
with no extra dependency and signals `READY=1` once every configured listener
answers `/healthz`. This is intentional *liveness*: Guardian serves fail-open,
so a store outage must not prevent startup (use [`/readyz`](#probes-liveness-vs-readiness)
to check the store). `systemctl start` consequently waits for real service
availability, and `systemctl status` does not report a pre-bind, wedged daemon
as ready while requests pass through unchecked.

`WatchdogSec=30s` arms the watchdog; guardiand pings at half that interval, so
a hung daemon is killed and restarted instead of appearing healthy. Loosen the
interval for aggressive `GOGC` settings with very long GC pauses, or remove the
line to disable the watchdog while keeping readiness.

The watchdog is systemd-only. The daemon auto-detects `$NOTIFY_SOCKET`, so
running it by hand or under Docker needs no change; Docker uses the Compose
healthcheck to gate readiness instead.

### Docker

Every release publishes a prebuilt sidecar image (distroless, nonroot,
version-stamped) to both GitHub Packages and the GitLab container registry, so you don't have to
build anything:

```sh
export GUARDIAN_VERSION=REPLACE_WITH_RELEASE_TAG
docker pull "ghcr.io/angieguardian/angie-guardian:${GUARDIAN_VERSION}"
# or from GitLab:
docker pull "registry.melroy.org/melroy/angie-guardian:${GUARDIAN_VERSION}"
```

#### Production Docker Compose stack

A complete, production-ready reference Compose deployment is available in the repository at
[`deploy/docker/compose.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/docker/compose.yaml). It orchestrates:

1. **Angie** (reverse proxy) fronting HTTP traffic, configured with the official Guardian integration snippets and optional server-hardening profile.
2. **`guardiand`** (sidecar daemon) performing auth requests, PoW challenge issuance, and WAF inspection.
3. **`backend`** (application container) serving origin content.

```yaml
name: angie-guardian

services:
  guardiand:
    image: ghcr.io/angieguardian/angie-guardian:${GUARDIAN_VERSION:-latest}
    restart: unless-stopped
    command: ["-config", "/etc/guardian/guardian.yaml"]
    volumes:
      - ./guardian.docker.yaml:/etc/guardian/guardian.yaml:ro
      - ./rules-common.yaml:/etc/guardian/rules.d/common.yaml:ro
      - guardian-data:/var/lib/guardian
      - guardian-keys:/etc/guardian/keys
    expose:
      - "8071"
    ports:
      - "127.0.0.1:8072:8072"
    healthcheck:
      test: ["CMD", "/usr/local/bin/guardiand", "-config", "/etc/guardian/guardian.yaml", "-healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 5

  backend:
    image: traefik/whoami:latest
    command: ["--port", "8080"]
    restart: unless-stopped
    expose:
      - "8080"

  angie:
    image: docker.angie.software/angie:1.12.1@sha256:c9b84be14a2a584891a1ef6678d44e6d7740127e6ceddc8f2f237491ff369ce0
    restart: unless-stopped
    depends_on:
      guardiand:
        condition: service_healthy
      backend:
        condition: service_started
    volumes:
      - ./angie.docker.conf:/etc/angie/angie.conf:ro
      - ../angie-guardian-limits.conf:/etc/angie/angie-guardian-limits.conf:ro
      - ../angie-hardening-http.conf:/etc/angie/angie-hardening-http.conf:ro
      - ../angie-hardening-server.conf:/etc/angie/angie-hardening-server.conf:ro
      - ../angie-guardian.conf:/etc/angie/angie-guardian.conf:ro
      - ../angie-guardian-location.conf:/etc/angie/angie-guardian-location.conf:ro
      - ../../web/vendor/guardian-argon2:/usr/share/guardian/assets:ro
      - ./basic.htpasswd:/etc/angie/basic.htpasswd:ro
    ulimits:
      nofile:
        soft: 8192
        hard: 8192
    ports:
      - "127.0.0.1:8080:80"

volumes:
  guardian-data:
  guardian-keys:
```

#### Key architecture and security properties

- **Network isolation:** The auth hot path (`8071`) is only exposed internally on the Docker network for Angie's `auth_request` subrequests; it is deliberately not published to host ports. The Admin API and metrics listener (`8072`) is bound strictly to `127.0.0.1`.
- **State persistence:** Named volumes (`guardian-data` and `guardian-keys`) ensure behavioral blocks, store state (Pebble/BuntDB), and the Ed25519 signing keys persist across container recreation so issued client cookies remain valid after restarts and image updates.
- **Liveness probe:** The distroless healthcheck uses `/usr/local/bin/guardiand -healthcheck` to verify that configured listeners respond with `/healthz`. Because Guardian serves fail-open, liveness checks do not crash-loop on transient store disruptions (use [`/readyz`](#probes-liveness-vs-readiness) for orchestrator readiness probes).
- **Automated test separation:** Automated end-to-end testing uses a separate [`deploy/docker/compose.e2e.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/docker/compose.e2e.yaml) harness with dynamic ports and build-from-tree targets, keeping `compose.yaml` clean for production use.

Inside the container, set `listen: 0.0.0.0:8071` plus `trusted_proxy: true`
and `admin.listen: 0.0.0.0:8072` in `guardian.yaml` (the loopback-only
`ports:` binding above is what keeps them off the network), and point the
signing key and generated admin token at the persistent key volume:
`signing_key_file: /etc/guardian/keys/ed25519.key` and
`admin.token_file: /etc/guardian/keys/admin.token`, since a token file outside
a volume is regenerated when the container is replaced. Hot reload works as
usual: `docker kill -s HUP <container>` or `POST /admin/reload`.

## Optional: running the anomaly trainer

The anomaly trainer is optional; Guardian's core request protection does not
require it. Use it only when you want model-based anomaly scoring.
`guardian-train` is an offline batch job, not a second daemon. It reads a
representative window of Angie JSON access logs, builds a complete replacement
baseline for every domain with enough usable requests, writes one model
artifact, and exits. `guardiand` never learns from live requests: it only reads
the artifact named by `waf.anomaly.model` and scores requests against it. See
[Train the Anomaly Model](/guide/anomaly) for the log format, features and
threshold-tuning workflow.

### Preferred systemd timer

On a systemd installation, use the shipped
[`guardian-train.service`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/guardian-train.service)
and
[`guardian-train.timer`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/guardian-train.timer)
templates. The timer runs weekly with up to 30 minutes of random delay; the
one-shot service trains at low CPU/I/O priority in a hardened, networkless
sandbox. Its update helper reads plain and gzip-compressed rotations and
rejects: a trainer/daemon version mismatch, a candidate omitting an expected
domain, one exceeding the malformed/schema-invalid line limit, and (when a
live artifact exists, by scoring the configured comparison window against both
artifacts) insufficient coverage or excessive mean/p95 score drift. It keeps
JSON reports and the previous artifact, then promotes an accepted candidate
with an atomic rename.

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
filesystem read-only. The promotion directory remains writable, so keep
unrelated secrets outside `/etc/guardian` where practical, and keep
`/etc/guardian/model.json` read-only to the `guardian` daemon just like
`guardian.yaml` and the WAF rules (a compromised daemon must not be able to
replace the baseline it enforces). The template also starts memory reclaim at
1 GiB and caps the batch at 2 GiB, so hostile high-cardinality input fails the
job instead of exhausting the host; if a measured representative run genuinely
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

Later model replacements need no signal or restart: each instance checks the
configured model every 10 seconds by content hash and logs `anomaly model
reloaded` after accepting it. An unreadable, oversized or invalid replacement
leaves the previous model active in memory, but a future daemon restart still
needs a valid file on disk. Retain the last accepted candidate so a bad new
baseline can be atomically promoted back; the shipped helper keeps it at
`/var/lib/guardian-training/model.previous.json`.

Before enabling the timer, define its input window and acceptance checks in
`/etc/guardian/trainer.env`:

- Rebuild from the whole representative window, including the relevant rotated
  logs. Training is not incremental; feeding only the newest file forgets the
  older traffic distribution. Segment discovery and exact aggregation make two
  complete passes, so compressed inputs are decompressed twice; size the timer's
  runtime window accordingly.
- Set `GUARDIAN_TRAIN_EXPECTED_DOMAINS` to every named domain that enables
  anomaly scoring. The job rejects the candidate if any required domain lacks
  the configured minimum number of eligible requests, and the compare gate's
  hard coverage failures (a removed or uncovered baseline) apply only to this
  list: a vhost above the compare floor but below the train floor can never
  gain a baseline, and must not wedge the weekly promotion.
- Dry-run a promotion with `guardian-train-update --dry-run` (or
  `GUARDIAN_TRAIN_DRY_RUN=1`): it trains and compares as usual, writing only
  under `/var/lib/guardian-training`, and reports what would be promoted
  without touching `/etc/guardian`.
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
rename the candidate inside `./guardian-models`. The directory mount matters:
replacing a single bind-mounted file can leave a container attached to the old
inode. In a replica fleet, distribute the same accepted artifact to every node
(the shared Redis/Valkey store does not distribute models) and confirm the
reload on each instance before considering the rollout complete.

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
  fsync'ing every commit. It sustains ~152k challenge writes/s with `sync: false`
  (the default), and ~35k/s with `sync: true` (fsync every write, fully durable).
  Its state lives in a directory (set `store.path` to a directory).
- **buntdb**: single instance, persistent, stored in a **single file** (simpler
  to back up or copy). Its async default (`sync: false`) sustains ~56k challenge
  writes/s. It is a single-writer store, so `sync: true`
  (fsync-per-commit) would collapse it to a few hundred writes/s, so guardiand
  **refuses to start** with `backend: buntdb` + `sync: true` and points
  you to Pebble for synchronous durability. Set `store.path` to a file.
- **redis**: multi-instance. Works with both Redis and
  [Valkey](https://valkey.io/) (the open-source Redis fork), a drop-in
  replacement (same wire protocol, same `backend: redis` value). This is the
  shared store that lets replicas behind a load balancer see each other's blocks
  and single-spend markers; the embedded backends above are single-node only.

For durable embedded backends, `store.sync: false` (default) is fastest but can
lose only the unflushed tail after a power/OS crash (a bounded,
≤`challenge_ttl` replay window). Set it to `true` for fsync-per-write
durability; that is practical only with Pebble.

Redis/Valkey is multi-instance, but the current client uses plaintext TCP and
does not prefix keys. Use loopback, a private authenticated network, or a
verified TLS/mTLS tunnel, and give each deployment a fresh dedicated logical
database. Never share a database between unrelated staging/production sites:
blocks, challenges, counters, bot verdicts, and fleet posture would collide.

`store.addr` uses the standalone Redis protocol client; Redis Cluster is not
supported because active-block maintenance updates a block key and shared index
in one non-cross-slot script. Use a stable TCP endpoint in front of replicated
Redis/Valkey when you need server failover.

The practical performance rule from the [measured
numbers](/guide/what-is-guardian#performance) is that backend choice mainly
sets the *new-client* challenge-write rate. Embedded read paths are
backend-independent at roughly 150–176k req/s because the
[block mirror](/guide/block-offload) serves allow/token/deny decisions after
the seed scan; Redis remains read-through, with one network read per request so
blocks placed by another replica apply immediately. Challenge-write rates bound
the sustained normal-mode new-client rate, not the flood case: [attack mode](/guide/attack-mode)
uses stateless issuance with no write at issue time. Returning clients remain on
the fast path because verified tokens are cached in-process.

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

Both key paths need one filesystem with cross-host advisory locking and atomic
rename; verify both properties for NFS or other distributed filesystems.
Asynchronous rsync/Syncthing copies are unsafe with multiple rotators because
replicas do not share Guardian's `flock` and can create competing keys. If
asynchronous distribution is unavoidable, designate one rotator and finish
distribution before another rotation.

Key refresh and token minting fail closed if either path is unreadable. Prefer
local disk on one host; for multiple hosts, use a low-latency, reliably mounted
shared filesystem and test mount interruption/recovery, since a flaky mount can
briefly interrupt challenges and tokens across the fleet.

## GC tuning for peak throughput

If any effective scope uses `pow.algorithm: argon2id`, budget CPU separately
from the ordinary authorization path. Keep the `N` cores your measured hot path
needs and provision at least two additional cores for Argon2id verification
and runtime overhead (`N+2` total). Do not set systemd `CPUQuota=` or a
container CPU limit below that budget. The verifier admission pool is bounded
and is not entered by ordinary `/auth` traffic, but the work still runs in the
same Go process. Validate simultaneous token traffic and Argon2id redemptions
on the deployment hardware; a 5% maximum token-path throughput regression is
the gate for a 150k req/s target. See
[Proof-of-work algorithms](/guide/pow-algorithms).

At tens of thousands of requests per second, guardiand's read paths are
bound by Go's garbage collector, not the store: a freshly started daemon has
a small heap, so at high allocation rates the GC runs almost continuously.
On the [benchmark machine](/guide/load-testing#benchmark-results), `GOGC=800`
raised read-path throughput by about 20%. `GOGC` sets how much the heap grows
between collections (default 100); raising it trades a larger heap for less
GC CPU.

Where guardiand owns the host's or container's memory, the
[Go GC guide](https://go.dev/doc/gc-guide) recommends pairing a high `GOGC`
with `GOMEMLIMIT` as a safety cap, so the larger heap cannot OOM (the runtime
does extra GC only as it nears the limit). `GOMEMLIMIT` is a **soft** limit:
never set it to the machine's total RAM or a systemd/container memory limit.
Leave room for memory the Go runtime does not track; a too-tight limit can
make it GC nearly continuously, causing a slowdown worse than an OOM. Skip
`GOMEMLIMIT` when the host's memory is shared with other processes.

For a dedicated Guardian service, start with these conservative budgets:

```ini
# 1 GiB MemoryMax/container limit: 20% RSS headroom outside GOMEMLIMIT.
Environment=GOGC=400
Environment=GOMEMLIMIT=800MiB

# 2 GiB MemoryMax/container limit: use this pair instead.
# Environment=GOGC=800
# Environment=GOMEMLIMIT=1600MiB
```

`GOGC=400` is the starting point: it reduces GC CPU without immediately
allowing the largest heap. Raise it to `800` only for a dedicated,
high-throughput instance after measuring with the same workload you expect in
production; the benchmark's ~20% read-path gain came from that setting. The
20% gap is deliberate: `GOMEMLIMIT` covers Go-managed memory, not every byte
in the process's RSS (for example file mappings and other runtime-external
memory). When using systemd `MemoryMax=` or a container memory limit, base the
calculation on that service limit, not on the host's total RAM.

Set these in the systemd unit's `Environment=` (see
[`deploy/guardiand.service`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/guardiand.service))
and measure with `guardian-loadtest`; at typical production rates leaving both
settings at their defaults is fine.

## Memory footprint

guardiand's in-process memory is bounded independently of traffic, so a flood
of distinct IPs, hosts, User-Agents or URLs cannot grow it without limit (no
remote OOM). The client-keyed structures and their caps:

- **Verified-token cache**: at most 2^17 entries (~5 MiB); wholesale-reset when
  full, entries repopulate cheaply on the next verify.
- **Counter cache** (issuance rate limit + farming escalation): at most 2^17
  entries. At capacity a reclaim sweep runs at most once per second (an on-demand
  sweep would run a full-map scan under the hot-path mutex hundreds of times
  a second and collapse challenge issuance) and evicts clean cached totals plus
  any entry whose window has expired; entries still carrying live unapplied
  store work are retained rather than erasing pending reconciliation state.
  Keys arriving between sweeps are counted in a bounded count-min sketch, so a
  rotating-IP flood still trips the limiter (over-counting at worst) instead
  of resetting to one each time.
- **Recent-decisions ring** (admin/dashboard feed): bounded by
  `admin.recent_decisions_capacity` (default 4096, maximum 16384), overwrite-oldest. It holds
  raw host/URI/UA strings, so exact bytes vary with traffic, but entry count
  never grows past the configured cap. Proof-of-work outcomes (solves, failed
  redemptions and recovered network handovers) share it, which costs no extra
  memory (they take ring slots like any other row) but does mean a given size
  reaches back over less decision history on a site where most challenges are
  solved.
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
services to run: active blocks with one-click block/unblock, the recent feed of
non-allow decisions and PoW outcomes, activity and distribution graphs
(decisions over time, the proof-of-work funnel, solve time overall and by domain
and client class, and the anomaly histogram), a top-offenders panel,
per-domain feature status, and, when pointed at Angie's API, real server traffic.
For most single-instance deployments this is all you need. See
[Admin API & Dashboard](/guide/admin#the-reporting-dashboard) for the full tour.

### Prometheus + Grafana

For long-horizon history, alerting, or fleet-wide aggregation across replicas,
scrape the Prometheus metrics at `/metrics` on the admin listener (open to
scrapers by default, no token needed): decisions by action/reason/domain, challenge
lifecycle, PoW solve-time and anomaly-score histograms, blocks placed, store op
latency, and end-to-end `Evaluate()` latency. Import
[`deploy/grafana-dashboard.json`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/grafana-dashboard.json) for a ready-made Grafana dashboard. This
complements the built-in dashboard rather than replacing it: the built-in view
is per-instance and live, while Prometheus retains history and sums across a
fleet.

If the admin listener is bound to a routable interface, consider
`admin.metrics_auth: true`: `/metrics` then requires the admin bearer token
(it exposes every protected vhost name plus per-domain traffic and attack
posture), while `/healthz` and `/readyz` stay open for orchestrators. Pair it
with a stable `admin.token` or `admin.token_file` and give Prometheus the
token:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: angie-guardian
    authorization:
      credentials_file: /etc/prometheus/guardian-admin-token
```

### Alerting

[`deploy/alerts.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/alerts.yaml) ships ready-made Prometheus rules. Point your `rule_files`
at it:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/angie-guardian-alerts.yaml
```

Every rule selects `job="angie-guardian"`. If you scrape Guardian under a
different job name, search/replace it in the file or nothing will ever fire.
Validate after editing with `promtool check rules` and `promtool test rules`
(the shipped [`deploy/alerts.test.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/alerts.test.yaml) covers the rules and their sample
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
| `GuardianRedeemInternalErrors` | internal challenge-redemption failures for 10m | warning |
| `GuardianStatelessSpendFallback` | single-spend CAS failing for 10m | warning |
| `GuardianAttackMode` | posture above normal for 10m | info |

**If you ship only one alert, ship `GuardianStoreDown.`** Guardian
[fails open](/guide/threat-model) by design: when the store is unreachable,
stages abstain, challenge issuance falls back to stateless minting, single-spend
degrades to per-replica, and every request sails through. The process stays up,
all configured listeners keep answering `/healthz`, and `systemctl status` still says
`active`. Nothing about that state is visible without this gauge.

The thresholds are starting points chosen to be quiet on a healthy instance.
Every ratio and rate rule carries an explicit sample floor (at least N
operations, at least N challenges, at least one block per minute) so a near-idle
instance cannot produce a screaming ratio from two samples; raise the floors on
busy deployments.

### Probes: liveness vs readiness

The two health endpoints answer different questions, and wiring them the same
way defeats the point:

- **`/healthz`** (all configured auth and admin listeners) is **liveness**: is the process serving? It
  never consults the store. Use it for container health checks, systemd
  readiness sequencing, and the `-healthcheck` flag. Tying liveness to the store
  would kill containers that are still (fail-open) protecting traffic and turn a
  degradation into an outage.
- **`/readyz`** (admin listener) is **readiness**: is the shared state Guardian's
  stateful protection depends on actually working? It returns `503` when the
  background store probe is pending, failing or stale. Use it to gate rollouts
  and instance startup ordering: a freshly deployed replica should not receive
  traffic before its store connection works.

::: warning Do not gate fleet traffic on `/readyz` with a shared store
With a shared Valkey/Redis store, one store outage makes **every** replica
return `503` at the same moment (they all probe the same backend), so a load
balancer or Kubernetes `readinessProbe` wired to `/readyz` would pull the
entire fleet from rotation at once, even though every instance is still
serving and (fail-open) protecting traffic. That converts a survivable store
degradation into the full outage fail-open exists to prevent. For a shared
store, alert on `/readyz` (the shipped `GuardianStoreDown` rule already fires)
instead of routing on it; reserve routing decisions for per-instance stores,
where readiness failures are uncorrelated.
:::

`/readyz` only reads the last probe snapshot, so probing it aggressively costs
nothing and cannot turn health checks into store traffic. A degraded nftables
sink or a raised attack posture appear in the body but never change the status
code: both still protect traffic.

## Key rotation

`POST /admin/rotate-key` archives the current Ed25519 key into
`previous_key_dir` (a non-empty shared one is required) and atomically
installs a new one. Rotations are serialized on the shared key path, archive
names cannot collide, and live replicas refresh the key set automatically:
token signing reads the current key under the shared rotation lock, and
stateless challenge issuers use a rate-limited pre-issuance refresh so a quiet
replica cannot remain indefinitely on a stale key without adding a file
lock/read to every attack-path challenge. Current and still-live retired
secrets keep in-flight stateless challenges redeemable through the rotation;
retired keys accept only tokens issued before rotation, and no accepted token
may have a lifetime longer than thirty days. Older archive files may remain for
operator retention, but Guardian drops them from the in-memory verification
set once that horizon has elapsed (expired timestamped key contents are
skipped before file reads and parsing). Each replica still enumerates the
archive directory during refresh, so archive or delete files beyond the
horizon to bound the scan cost.
