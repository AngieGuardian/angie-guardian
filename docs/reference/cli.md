# CLI Tools

Three binaries live under `cmd/`; all of them accept `-version`.

## guardiand

The sidecar daemon.

```sh
guardiand -config /etc/guardian/guardian.yaml
```

| Flag | Description |
|---|---|
| `-config <path>` | Path to `guardian.yaml` (required). |
| `-healthcheck` | Load the config and require every configured listener to answer `/healthz`, then exit. Used by the distroless Compose image. |
| `-t` | Test the config and startup-required local artifacts (WAF rules, anomaly models, GeoIP databases, and file feeds), then exit. Remote URL feeds are not fetched. Exit code `0` and `ok` when valid, `1` and the reason when not (like `angie -t`). |
| `-version` | Print version and exit. |

```sh
./guardiand -config guardian.yaml -t
# config guardian.yaml: ok
# ...or, on a bad config:
# config guardian.yaml: FAILED
# config guardian.yaml: store.backend must be memory, buntdb, pebble or redis, got "etcd"
```

### Signals

| Signal | Effect |
|---|---|
| `SIGHUP` | Re-read and apply `guardian.yaml` without a restart (also available as [`POST /admin/reload`](/reference/admin-api#post-admin-reload)). Invalid config and changes to startup-only listeners, store, signing keys or admin setup are rejected; the running config stays active. |
| `SIGINT` / `SIGTERM` | Graceful shutdown (sends `STOPPING=1` under systemd). |

Under systemd (the shipped unit is `Type=notify`), guardiand speaks sd_notify:
it signals `READY=1` once both listeners answer `/healthz` and keeps a watchdog
alive. See
[Readiness and watchdog](/guide/production#readiness-and-watchdog).

### Hot-path endpoints (on `listen`)

These are Angie's side of the integration, wired by
`deploy/angie-guardian.conf`; you never call them directly.

| Endpoint | Purpose |
|---|---|
| `GET /auth` | The `auth_request` target: answers allow, challenge, or deny. |
| `GET /challenge` | Serves the PoW interstitial. |
| `POST /pass` (public path `/__guardian/pass`) | Receives the solved challenge, sets the signed cookie. `GET` serves the no-JS fallback. |
| `/denied` | The deny page. |
| `GET /healthz` | Liveness probe. |

## guardian-train

Builds per-domain anomaly baselines offline from Angie JSON access logs. See
[Train the Anomaly Model](/guide/anomaly).

```sh
guardian-train -out /etc/guardian/model.json -min-requests 5000 \
               /var/log/angie/*.access.json
```

| Flag | Default | Description |
|---|---|---|
| `-out <path>` | `model.json` | Output model artifact path. |
| `-min-requests <n>` | `1000` | Drop domains with fewer usable successful records (entries without a host and responses with status >= 400 are excluded). |
| `-version` | | Print version and exit. |

Positional arguments are the JSON access log files to read; pass `-` to read
from stdin (e.g. `zcat ... | guardian-train -out model.json -`).

## guardian-loadtest

Drives the `/auth` hot path over keepalive connections and reports throughput
and latency percentiles. See [Load Testing](/guide/load-testing).

```sh
guardian-loadtest -scenario token -host example.com -c 128 -d 10s
```

| Flag | Default | Description |
|---|---|---|
| `-url <base>` | `http://127.0.0.1:8071` | guardiand base URL. |
| `-scenario <name>` | `allow` | One of `allow`, `token`, `deny`, `challenge`. |
| `-host <host>` | `plain.test` | `X-Guardian-Host` to send. |
| `-ip <addr>` | `198.51.100.7` | `X-Guardian-IP` to send. The `challenge` scenario rotates the IP itself to spread issuance. |
| `-c <n>` | `64` | Concurrent connections. |
| `-d <duration>` | `5s` | Test duration. |
| `-version` | | Print version and exit. |
