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
| `-healthcheck` | **Liveness** check: require every configured listener to answer `/healthz`, then exit. Only the listen addresses are read from the config, leniently: a half-edited or invalid `guardian.yaml` cannot fail the probe of a healthy running daemon. Used by the distroless Compose image. It deliberately does not consult the store; see [`/readyz`](/reference/admin-api#get-readyz) for readiness. |
| `-t` | Test the config and startup-required local artifacts (WAF rules, anomaly models, GeoIP databases, and file feeds), then exit. Remote URL feeds are not fetched. Exit code `0` and `ok` when valid, `1` and the reason when not (like `angie -t`). |
| `-version` | Print version and exit. |

```sh
./guardiand -config guardian.yaml -t
```

Output on a valid config:

```
config guardian.yaml: ok
```

...or, on a bad config:

```
config guardian.yaml: FAILED
config guardian.yaml: store.backend must be memory, buntdb, pebble or redis, got "etcd"
```

### Signals

| Signal | Effect |
|---|---|
| `SIGHUP` | Re-read and apply `guardian.yaml` without a restart (also available as [`POST /admin/reload`](/reference/admin-api#post-admin-reload)). Invalid config and changes to startup-only listeners, store, signing keys or admin setup are rejected; the running config stays active. |
| `SIGINT` / `SIGTERM` | Graceful shutdown (sends `STOPPING=1` under systemd). |

Under systemd (the shipped unit is `Type=notify`), guardiand speaks sd_notify:
it signals `READY=1` once both listeners answer `/healthz` (liveness: the
sequencing intentionally does not wait on the store, since Guardian serves
fail-open) and keeps a watchdog alive. See
[Readiness and watchdog](/guide/production#readiness-and-watchdog).

### Hot-path endpoints (on `listen`)

These are Angie's side of the integration, wired by the reusable
[`deploy/angie-guardian.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian.conf)
server endpoints and
[`deploy/angie-guardian-location.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian-location.conf)
authorization directives; you never call them directly.

| Endpoint | Purpose |
|---|---|
| `GET /auth` | The `auth_request` target: answers allow, challenge, or deny. |
| `GET /challenge` | Serves the PoW interstitial. |
| `POST /pass` (public path `/__guardian/pass`) | Receives the solved challenge, sets the signed cookie. `GET` serves the no-JS fallback. |
| `/denied` | The deny page. |
| `GET /healthz` | Liveness probe. |

### Admin endpoints (on `admin.listen`)

Open (no bearer token); every other `/admin/*` route is authenticated. See the
[Admin API reference](/reference/admin-api).

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness probe. Answers while the process serves; never follows the store. |
| `GET /readyz` | Readiness probe. `503` when store readiness is not established, so a fail-open degradation is visible to an orchestrator. |
| `GET /metrics` | Prometheus metrics. |

## guardian-train

Builds per-domain anomaly baselines offline from Angie JSON access logs. See
[Train the Anomaly Model](/guide/anomaly).

```sh
guardian-train train -out model.candidate.json -min-requests 5000 \
  -require-domain example.com /var/log/angie/*.access.json*
```

### `guardian-train train`

| Flag | Default | Description |
|---|---|---|
| `-out <path>` | `model.json` | Output model artifact path. |
| `-report <path>` | | Write a machine-readable training/input report. |
| `-min-requests <n>` | `5000` | Minimum eligible records per domain. |
| `-min-segment-requests <n>` | `500` | Minimum eligible records for an automatic route/method segment. |
| `-max-segments <n>` | `128` | Maximum retained segments per domain. |
| `-max-invalid <n>` | `0` | Maximum malformed or schema-invalid log records. |
| `-require-domain <host>` | | Require this normalized domain in the artifact; repeat for multiple domains. |

Positional arguments can be plain JSON logs, `.gz` logs, or `-` for stdin. A
training stdin stream is copied uncompressed to a mode-0600 temporary file
under `$TMPDIR`, because segment discovery and exact aggregation read it twice;
ensure that filesystem has room for the complete stream. The strict input
schema and filtering rules are documented in
[Train the Anomaly Model](/guide/anomaly).

### `guardian-train compare`

Scores the same validation records against the live and candidate artifacts.
The report marks each domain as `compared`, `added`, `removed`, `skipped`, or
`uncovered`; added coverage and quiet-but-retained domains do not manufacture a
drift failure. It exits `3` when an acceptance gate rejects the candidate.

| Flag | Default | Description |
|---|---|---|
| `-current <path>` | required | Current live artifact. |
| `-candidate <path>` | required | Candidate artifact. |
| `-report <path>` | | Write the complete comparison report. |
| `-min-requests <n>` | `500` | Minimum validation records per observed domain. |
| `-max-mean-delta <score>` | `0.10` | Maximum absolute mean-score change per domain. |
| `-max-p95-delta <score>` | `0.15` | Maximum absolute p95-score change per domain. |
| `-max-invalid <n>` | `0` | Maximum malformed or schema-invalid validation records. |
| `-require-domain <host>` | | Scope hard coverage failures (a removed or uncovered baseline) to this normalized domain; repeat for multiple domains. Without any, every over-floor coverage hole fails. The systemd job passes `GUARDIAN_TRAIN_EXPECTED_DOMAINS` here. |

`guardian-train -version` (or `--version`) prints the binary version. For unattended candidate
training, comparison, and atomic promotion, use the
[preferred systemd timer](/guide/production#running-the-anomaly-trainer);
`guardian-train-update --dry-run` (or `GUARDIAN_TRAIN_DRY_RUN=1`) runs the
same train and compare steps against the staging directory and reports what
would be promoted without touching `/etc/guardian`.

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
