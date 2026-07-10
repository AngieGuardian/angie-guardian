# Run it in Production

## systemd

```sh
sudo cp guardiand /usr/local/bin/
sudo install -Dm600 guardian.yaml /etc/guardian/guardian.yaml
sudo cp deploy/guardiand.service /etc/systemd/system/
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # -> ok
```

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
write. bbolt sustains ~1.6k challenge issuances/s; redis/valkey ~15x that
(~25k/s). Verified tokens are cached in-process (~144 ns vs ~43 µs for a full
Ed25519 verification), so a returning client's request stays on the fast read
path regardless of backend.

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
