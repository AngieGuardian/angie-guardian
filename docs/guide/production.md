# Run it in Production

## systemd

```sh
sudo cp guardiand /usr/local/bin/
sudo install -Dm600 guardian.yaml /etc/guardian/guardian.yaml
sudo cp deploy/guardiand.service /etc/systemd/system/
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # -> ok
```

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
volumes:
  guardian-state:
  guardian-keys:
```

Inside the container, set `listen: 0.0.0.0:8071` plus `trusted_proxy: true`
and `admin.listen: 0.0.0.0:8072` in `guardian.yaml` (the loopback-only
`ports:` binding above is what keeps them off the network), and point the
signing key at the volume: `signing_key_file: /etc/guardian/keys/ed25519.key`.
Hot reload works as usual: `docker kill -s HUP <container>` or
`POST /admin/reload`.

For a complete, runnable example (including Angie and a demo backend) see
`deploy/docker/compose.yaml` in the repo; it builds the image from source
because the e2e suite exercises the working tree, but swapping `build:` for
`image:` gives the production shape above.

## Choosing a store backend

Guardian keeps its shared state (IP blocks, spent challenges, the signing
key) in a pluggable store:

- **memory**: single instance, state lost on restart. Fine for dev or a small
  site that can re-learn blocks after a restart.
- **bbolt**: single instance, persistent. Writes are coalesced (`db.Batch`) so
  concurrent challenge/event writes share fsyncs, but it is still one embedded
  writer: under a very high sustained rate of *new* clients (each of which
  triggers a challenge write in `pow.mode: always`), the single writer becomes
  the ceiling. Load-test with `guardian-loadtest` at your expected new-client
  rate before relying on it near 50k req/s; if the writer saturates, switch to
  the `redis` backend or set `pow.mode: suspicion` (only anomalous clients are
  challenged, so most requests do no write).
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
`previous_key_dir` and generates a new one. Tokens signed by the old key keep
verifying until they expire, so rotation never logs anyone out.
