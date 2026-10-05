# CLI Tools

Four binaries live under `cmd/`; all of them accept `-version`.

## guardiand

The sidecar daemon.

```sh
guardiand
```

| Flag | Description |
|---|---|
| `-config <path>` | Path to `guardian.yaml`. Optional for every mode; when omitted, Guardian uses `/etc/guardian/guardian.yaml`. |
| `-healthcheck` | **Liveness** check: require every configured listener to answer `/healthz`, then exit. Without `-config`, it also uses `/etc/guardian/guardian.yaml`. Only the listen addresses are read from the config, leniently: a half-edited or invalid `guardian.yaml` cannot fail the probe of a healthy running daemon. Used by the distroless Compose image. It deliberately does not consult the store; see [`/readyz`](/reference/admin-api#get-readyz) for readiness. |
| `-profile-dir <dir>` | Diagnostic mode for a controlled benchmark run. The directory must be empty; on graceful shutdown Guardian writes CPU, heap, allocation, mutex, block, goroutine and goroutine-leak profiles, a bounded runtime flight-recorder trace, and one JSONL runtime/Pebble sample per second. It enables extra runtime sampling, so do not use it for normal serving or compare its throughput directly with a standard run. |
| `-t` | Test the config and startup-required local artifacts (WAF rules, anomaly models, GeoIP databases, and file feeds), then exit. Remote URL feeds are not fetched. Exit code `0` and `ok` when valid, `1` and the reason when not (like `angie -t`). Without `-config` it tests `/etc/guardian/guardian.yaml`. |
| `-version` | Print version and exit. |

```sh
./guardiand -config guardian.yaml -t
```

On a packaged install, where the config is already at
`/etc/guardian/guardian.yaml`, the path can be left off:

```sh
guardiand -t
```

Output on a valid config:

```
config guardian.yaml: ok
```

The path is always named in the output, so a defaulted run still tells you
exactly which file was read.

...or, on a bad config:

```
config guardian.yaml: FAILED
config guardian.yaml: store.backend must be memory, buntdb, pebble or redis, got "etcd"
```

Live goroutine captures are also available independently of `-profile-dir` through the authenticated [diagnostics API](/reference/admin-api#runtime-diagnostics), when `admin.diagnostics_enabled` is enabled.

### Signals

| Signal | Effect |
|---|---|
| `SIGHUP` | Re-read and apply `guardian.yaml` without a restart (also available as [`POST /admin/reload`](/reference/admin-api#post-admin-reload)). Invalid config and changes to startup-only listeners, store, signing keys or admin setup are rejected; the running config stays active. |
| `SIGINT` / `SIGTERM` | Graceful shutdown (sends `STOPPING=1` under systemd). |

Under systemd (the shipped unit is `Type=notify`), guardiand speaks sd_notify:
it signals `READY=1` once all configured listeners answer `/healthz` (liveness: the
sequencing intentionally does not wait on the store, since Guardian serves
fail-open) and keeps a watchdog alive. See
[Readiness and watchdog](/guide/production#probes-liveness-vs-readiness).

### Hot-path endpoints (on `listen`)

These are Angie's side of the integration, wired by the reusable
[`deploy/angie-guardian-limits.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian-limits.conf)
HTTP-scope baseline plus
[`deploy/angie-guardian.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian.conf)
server endpoints and
[`deploy/angie-guardian-location.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian-location.conf)
authorization directives; you never call them directly.

The separately optional `angie-hardening-http.conf` and
`angie-hardening-server.conf` snippets bound Angie's client-facing TLS/HTTP work;
they are documented in [Angie Server Hardening](/guide/angie-hardening)
and do not change Guardian's endpoint contract.

| Endpoint | Purpose |
|---|---|
| `GET /auth` | The `auth_request` target: answers allow, challenge, or deny. |
| `GET /challenge` | Serves the PoW interstitial. |
| `POST /pass` (public path `/__guardian/pass`) | Receives a solved challenge as `Content-Type: application/json` and sets the signed cookie. Other content types are rejected before redemption. If the address changed after issuance, a valid proof returns `409` / `network_handover` with a safe `retry_url`; the interstitial restarts authorization there without receiving a pass. `GET` serves the no-JS fallback. |
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

## guardianctl

Operate the running daemon through its direct admin listener. Installed by the
release installer, included in release archives and the container, and built
by `make build` (or `go build ./cmd/guardianctl`).

```sh
sudo guardianctl unblock 203.0.113.9
sudo guardianctl block 2001:db8::9 --reason "manual abuse" --ttl 2h
sudo guardianctl status 203.0.113.9
sudo guardianctl list --limit 1000
sudo guardianctl health
sudo guardianctl stats --json
sudo guardianctl decisions --ip 203.0.113.9 --limit 100
sudo guardianctl offenders
sudo guardianctl config show
sudo guardianctl reload --check
sudo guardianctl reload
sudo guardianctl diagnostics status
sudo guardianctl diagnostics capture --out guardian-goroutines.tar
```

| Command | Behaviour |
| --- | --- |
| `block <ip> [--reason text] [--ttl duration]` | Manual IPv4/IPv6 block. Omitted values use API defaults: reason `admin`, TTL `24h`. Accepts Guardian duration units including `d`, `w`, `mon`, `y`, with a maximum of `1y`. |
| `unblock <ip> [--keep-backoff]` | Removes the block and clears triggering counters and challenge escalation. Resets repeat-offender backoff by default; `--keep-backoff` preserves it. Reports incomplete counter resets. |
| `status <ip>` | Behavioural block state, reason, and available expiry/offense details. An unblocked IP is a successful query. |
| `list [--limit n]` | Active blocks, reasons and expiry. Default `1000`, range `1–10000`. Warns when the API reports an incomplete list; JSON preserves `complete`. |
| `health` | Reports **liveness** and **store readiness** separately. Runs both probes, requires no credentials, and fails if either probe fails or readiness is false. |
| `stats` | Running operational summary. Dotted field names preserve nested groups; `blocks_complete: false` means the block count is a lower bound (`-1` means not seeded). |
| `decisions [--ip ip] [--limit n]` | Recent retained decisions, newest first. Default `50`, range `1–10000`. Reports truncation and retained-window metadata. History is per process and resets on restart. |
| `offenders` | Top recent non-allow IPs, counts and available country/ASN details. JSON also includes the API's other rollups. |
| `config show` | Reads the daemon's running redacted view, rather than printing the local configuration or credentials. |
| `diagnostics status` | Live capture availability and cooldown; disabled diagnostics remain a successful status query. |
| `diagnostics capture --out <file>` | Capture and privately save the goroutine profile tar; see the workflow below. |
| `reload [--check]` | Preflights the daemon's on-disk configuration. `--check` applies nothing. Plain `reload` applies only after successful preflight; the daemon revalidates during application. Restart-required fields or invalid config produce a nonzero exit. |

### Runtime diagnostics

```sh
sudo guardianctl diagnostics status --json
sudo guardianctl diagnostics capture --out guardian-goroutines.tar
sudo guardianctl diagnostics capture --out guardian-goroutines.tar --timeout 30s
```

`diagnostics status` reads authenticated live availability: `enabled`,
`capturing` (capture or download active), and `retry_after_seconds`. A disabled
status is a successful query. Enable `admin.diagnostics_enabled: true` in the
daemon configuration and **restart** to allow captures; reloading does not
change this startup setting. The CLI does not enable diagnostics itself.

`diagnostics capture` checks status, then requests an on-demand archive from
`/admin/diagnostics/goroutines`. The daemon can still reject the request if
another capture starts between the status check and POST. Active captures and
cooldowns are reported, including `Retry-After` when supplied; captures are not
retried automatically. Older daemons without this API report that an upgrade
is required.

`--out <file>` is required. The CLI refuses existing files, directories and
symlinks, streams into a private temporary file, validates the content type,
length, archive structure and **32 MiB** limit, then publishes the complete
archive with permissions **0600**. Interrupted or invalid downloads remove
partial files. It ignores server-suggested filenames and never extracts the
archive automatically. Choose an existing writable destination directory.

The archive contains `goroutineleak.pprof` followed by `goroutine.pprof`:
two sequential binary snapshots, not an atomic view. Capture triggers a
leak-detecting GC cycle and may affect latency. One capture/download is allowed
per daemon, with a **60-second admission cooldown**, including failed admitted
attempts. CPU, mutex, block and trace profiling are not enabled by this command.

Human output reports the saved absolute path and byte count. `--json` returns
`{"path":"/absolute/path/guardian-goroutines.tar","bytes":12345}`; binary data
always goes to the requested file. Status/API/local-write failures exit `1`,
invalid destinations exit `2`, rejected authentication exits `3`, and
connection, timeout or cancellation failures exit `4`.

Extract into a private directory and use the matching daemon binary:

```sh
mkdir -m 700 guardian-profiles
tar -xf guardian-goroutines.tar -C guardian-profiles
go tool pprof -top /path/to/matching/guardiand guardian-profiles/goroutineleak.pprof
go tool pprof -top /path/to/matching/guardiand guardian-profiles/goroutine.pprof
```

An empty leak profile does not establish that every worker is healthy. Keep
these archives private: stack labels may contain operational information.

### Connection and output options

Shared options can appear before or after the command or IP:

| Option | Default / purpose |
| --- | --- |
| `--config <path>` | `/etc/guardian/guardian.yaml`; reads only admin connection settings, without validating unrelated WAF/store settings. |
| `--endpoint <URL>` | Overrides `admin.listen`. Must be the direct admin HTTP(S) origin, without credentials, path, query or fragment. Wildcard configured listeners resolve to loopback. |
| `--token-file <path>` | Overrides configured credentials; reads an existing file and never creates a token. |
| `--timeout <duration>` | `5s` per request; diagnostics capture defaults to `30s`. Positive and at most `1m`. Health, reload and diagnostics capture make two requests. |
| `--json` | API objects on stdout, suitable for scripts; health combines the two probes under `liveness` and `readiness`. Errors go to stderr. |
| `--help`, `--version` | Help/version without contacting the daemon or reading credentials. |

Credential order is `--token-file`, `admin.token`, `ADMIN_TOKEN`, then
`admin.token_file`, matching the daemon unless an explicit token file override
is supplied. Installed files usually require `sudo`. An ephemeral token cannot
be discovered: configure a persistent token file for terminal recovery.
Relative token paths resolve from the current directory, as they do for the
daemon; installed configurations should use absolute paths.

If the on-disk config is unavailable or malformed, supply both connection and
credential overrides:

```sh
sudo guardianctl --endpoint http://127.0.0.1:8072 \
  --token-file /var/lib/guardian/admin.token unblock 203.0.113.9
```

Requests bypass environment HTTP proxies and do not follow redirects. Use the
direct local listener for self-lockout recovery; no public dashboard route or
store edits are needed. Unblocking a behavioural block does **not** remove a
static denylist entry or override a WAF deny rule.

| Exit code | Meaning |
| --- | --- |
| `0` | Successful operation (including an unblocked `status` result). |
| `1` | API/protocol error, unhealthy readiness, rejected reload/preflight, or diagnostic download/write failure. |
| `2` | Invalid input, configuration, credential discovery or output destination. |
| `3` | Authentication/authorization rejected (`401` / `403`). |
| `4` | Connection, TLS, timeout or cancellation failure. |

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

Drives Guardian directly, or the refusal route through Angie, over keepalive
connections and reports throughput and latency percentiles. See
[Load Testing](/guide/load-testing).

```sh
guardian-loadtest -scenario token -host example.com -c 128 -d 10s
```

| Flag | Default | Description |
|---|---|---|
| `-url <base>` | `http://127.0.0.1:8071` | Target base URL: guardiand normally, or Angie's public listener for `refuse-angie`. |
| `-scenario <name>` | `allow` | One of `allow`, `token`, `deny`, `challenge`, `refuse-auth`, `refuse-challenge`, or `refuse-angie`. |
| `-host <host>` | `plain.test` | Protected host: sent as `X-Guardian-Host` to guardiand or as the real HTTP `Host` for `refuse-angie`. |
| `-ip <addr>` | `198.51.100.7` | `X-Guardian-IP` to send in direct Guardian scenarios. `challenge` rotates it to spread issuance; `refuse-angie` uses the real connection address instead. |
| `-c <n>` | `64` | Concurrent connections. |
| `-d <duration>` | `5s` | Test duration. Ignored when `-n` is set. |
| `-n <requests>` | `0` (off) | Complete exactly this many measured requests instead of running for a duration. Every run then does identical work, which is what makes results comparable across machines and commits; use it for the `challenge` scenario, whose per-run store growth makes duration averages incomparable. |
| `-warmup <requests>` | `0` | Complete and discard this many requests first, so the measured window starts from a known store and counter-cache size instead of from empty. Composes with both `-n` and `-d` (the clock starts when warmup ends). |
| `-version` | | Print version and exit. |

The output ends with a `per-second:` line, one measured-completion count per
elapsed second. A flat line means the run reached a steady state; a falling
line means the aggregate above is blending a fast cold phase with a slower
loaded one, and only a fixed-work (`-n`) comparison is meaningful.
Refusal scenarios additionally report an `unexpected-contract` count when the
status is correct but the response headers do not identify the intended hop.
