# Run it in Production

## systemd

Grab the latest `guardiand` binary from the
[releases page](https://gitlab.melroy.org/melroy/angie-guardian/-/releases)
(under **Assets -> Packages**), then install it as a service:

```sh
sudo install -Dm755 guardiand /usr/local/bin/guardiand
getent group guardian >/dev/null || sudo groupadd --system guardian
id guardian >/dev/null 2>&1 || sudo useradd --system --gid guardian \
  --home-dir /var/lib/guardian --shell /usr/sbin/nologin guardian
sudo install -D -o guardian -g guardian -m600 guardian.yaml /etc/guardian/guardian.yaml
sudo install -Dm644 deploy/guardiand.service /etc/systemd/system/guardiand.service
sudo systemctl daemon-reload
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # -> ok
```

### Readiness and watchdog

The shipped unit is `Type=notify`: guardiand speaks
[sd_notify](https://www.freedesktop.org/software/systemd/man/sd_notify.html)
with no extra dependency, signalling `READY=1` only once every configured
listener answers `/healthz`. So `systemctl start` blocks until the service is
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

## Docker

Every release publishes a prebuilt sidecar image (distroless, nonroot,
version-stamped) to the project container registry, so you don't have to
build anything:

```sh
docker pull registry.melroy.org/melroy/angie-guardian:latest   # or a tag, e.g. :0.7.0
```

A minimal production compose service, with the store and signing key on
named volumes so blocks and issued tokens survive restarts:

```yaml
services:
  guardiand:
    image: registry.melroy.org/melroy/angie-guardian:0.7.0
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
considered healthy.

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

## Choosing a store backend

Guardian keeps TTL state (IP blocks, counters, spent challenges, and bot
verdicts) in a pluggable store. Signing keys remain in
`signing_key_file`/`previous_key_dir` and replicas share those files separately:

- **memory**: single instance, state lost on restart. Fine for dev or a small
  site that can re-learn blocks after a restart.
- **bbolt**: single instance, persistent. Writes are coalesced (`db.Batch`) so
  concurrent challenge/event writes share fsyncs, but it is still one embedded
  writer: under a very high sustained rate of *new* clients (each of which
  triggers a challenge write in `pow.mode: always`), the single writer becomes
  the ceiling. Load-test with `guardian-loadtest` at your expected new-client
  rate before relying on it near 50k req/s; if the writer saturates, switch to
  the `redis` backend or set `pow.mode: suspicion` (no catch-all challenge;
  only explicit anomaly/WAF/GeoIP/reputation policies cause challenge writes).
- **redis**: multi-instance and the highest write throughput. Works with both
  Redis and [Valkey](https://valkey.io/) (the open-source Redis fork), which
  is a drop-in replacement (same wire protocol, same `backend: redis` value).

The rule of thumb from the
[measured numbers](/guide/what-is-guardian#performance): the backend choice
hinges on your *new-client* rate, i.e. the clients that trigger a challenge
write. bbolt sustains ~4.1k challenge issuances/s; redis/valkey ~6x that
(~26k/s). Verified tokens are cached in-process (~144 ns vs ~43 µs for a full
Ed25519 verification), so a returning client's request stays on the fast read
path regardless of backend.

## GC tuning for peak throughput

At tens of thousands of requests per second, guardiand's read paths are
bound by Go's garbage collector, not the store: a freshly started daemon has
a small heap, so at high allocation rates the GC runs almost continuously.
On the [benchmark machine](/guide/load-testing#reference-numbers), starting
guardiand with `GOGC=800` more than doubled the read-path throughput (allow:
~78k to ~188k req/s on bbolt), at the price of a larger heap between
collections. If you chase peak throughput, set `GOGC` (or a `GOMEMLIMIT`
budget) in the systemd unit's `Environment=` and measure with
`guardian-loadtest`; at typical production rates the default is fine.

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

## Multi-instance (Redis/Valkey)

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
signing_key_file: /etc/guardian/ed25519.key   # same file on every replica
previous_key_dir: /etc/guardian/keys.d        # shared, e.g. NFS or synced
```

## Metrics and dashboards

Prometheus metrics live at `/metrics` on the admin listener (open to
scrapers, no token needed): decisions by action/reason/domain, challenge
lifecycle, PoW solve-time and anomaly-score histograms, blocks placed, store
op latency, and end-to-end `Evaluate()` latency.

Import `deploy/grafana-dashboard.json` for a ready-made Grafana dashboard, or
enable the built-in reporting page: see
[Admin API & Dashboard](/guide/admin#the-reporting-dashboard).

## Key rotation

`POST /admin/rotate-key` archives the current Ed25519 key into
`previous_key_dir` and atomically installs a new one. A non-empty shared
`previous_key_dir` is required. Rotations are serialized on the shared key
path, archive names cannot collide, and live replicas refresh the key set
automatically. Retired keys accept only tokens issued before rotation, and no
accepted token may have a lifetime longer than seven days.
Older archive files may remain for operator retention, but Guardian drops them
from the in-memory verification set once that seven-day horizon has elapsed.
