# Configuration Options

Every field of `guardian.yaml`, with types and defaults. Unknown fields are
rejected (the config is parsed with strict field checking), and semantic
errors fail at startup or under `guardiand -t`.

See the [Configuration guide](/guide/configuration) for the concepts and the
[Examples page](/examples) for complete files.

## Value formats

| Type | Format | Examples |
|---|---|---|
| Duration | Go duration string | `"30s"`, `"15m"`, `"4h"` |
| Rate | `<count>/<unit>` with unit `s`, `min`, or `h` | `"10/min"`, `"5/s"`, `"100/h"` |

## Top level

| Option | Type | Default | Description |
|---|---|---|---|
| `listen` | string | `127.0.0.1:8071` | The auth hot path (Angie's `auth_request` target). Must be loopback unless `trusted_proxy` is set. |
| `log_level` | string | `info` | One of `debug`, `info`, `warn`, `error`. |
| `trusted_proxy` | bool | `false` | Allow a non-loopback `listen`. The hot path trusts the `X-Guardian-*` client-identity headers from its caller, so only set this when the listener is isolated to Angie (private network, firewall, or mTLS). |
| `signing_key_file` | string | | Persistent Ed25519 signing key for PoW JWTs. Generated on first run if missing; never regenerated on restart. |
| `previous_key_dir` | string | | Where retired signing keys (from `POST /admin/rotate-key`) are archived; they are still accepted for verification until their tokens expire. |
| `admin` | object | | See [admin](#admin). |
| `store` | object | | See [store](#store). |
| `defaults` | object | | The base [domain config](#per-domain-options-defaults-and-domains) every domain inherits from. |
| `domains` | map | | Per-domain overrides, merged field-by-field over `defaults`. A host key normalizes case and port (`A.test:443` = `a.test`); two keys that collapse to the same host are rejected. |

## admin

| Option | Type | Default | Description |
|---|---|---|---|
| `admin.listen` | string | (empty = disabled) | Admin API + Prometheus `/metrics` listener, separate from the hot path. `/metrics` and `/healthz` are open; every `/admin/*` route requires the bearer token. Binding to a non-loopback address without a configured token is refused at startup. |
| `admin.token` | string | `$ADMIN_TOKEN` | Bearer token for `/admin/*` routes. Falls back to the `ADMIN_TOKEN` env var when empty. |
| `admin.token_file` | string | | Persists an auto-generated bearer token (created 0600 on first start, never regenerated, like the signing key). Used when `token` and `ADMIN_TOKEN` are unset. With neither `token` nor `token_file`, a loopback listener gets a fresh ephemeral token per start, printed in the startup log. |
| `admin.dashboard` | bool | `false` | Serve the built-in reporting page at `GET /admin/dashboard`. On startup guardiand logs a ready-to-open login URL carrying the token in the URL fragment. |

## store

| Option | Type | Default | Description |
|---|---|---|---|
| `store.backend` | string | `memory` | One of `memory`, `bbolt`, `redis`. See [choosing a store backend](/guide/production#choosing-a-store-backend). |
| `store.path` | string | | bbolt database file. **Required** for the `bbolt` backend. |
| `store.addr` | string | | Redis/Valkey `host:port`. **Required** for the `redis` backend. |
| `store.password` | string | `$REDIS_PASSWORD` | Redis/Valkey password. Falls back to the `REDIS_PASSWORD` env var. |
| `store.db` | int | `0` | Redis database number. |

## Per-domain options (`defaults` and `domains.<host>`)

Each domain entry has four sections: `waf`, `pow`, `allowlist`, `denylist`.

### pow

| Option | Type | Default | Description |
|---|---|---|---|
| `pow.enabled` | bool | `false` | Enable the proof-of-work challenge layer for this domain. |
| `pow.mode` | string | `always` | `always`: challenge every unvouched browser. `suspicion`: only challenge clients the anomaly scorer flags (requires `waf.anomaly.enabled`). |
| `pow.base_difficulty` | float | `5` | The floor every clean client pays. Range 1..8, in quarter steps. A difficulty of `N` requires `4 * N` leading zero bits of the SHA-256: +1 is 16x the work, +0.25 is exactly one bit (2x). Off-grid values (like `4.3`) are rejected at load. |
| `pow.max_difficulty` | float | `6` | The ceiling, reached only via anomaly-scaled difficulty. Range `base_difficulty`..8, quarter steps. |
| `pow.token_ttl` | Duration | `4h` | Lifetime of the signed JWT cookie a solved challenge earns. |
| `pow.challenge_ttl` | Duration | `30m` | How long an issued challenge stays solvable. |
| `pow.noscript_fallback` | bool | `false` | Serve a meta-refresh fallback for clients without JavaScript. |

See [base_difficulty and max_difficulty](/guide/configuration#base-difficulty-and-max-difficulty)
for which value fires when.

### waf.ip_behaviour

Behavioural IP blocking with exponential backoff.

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable behavioural blocking. |
| `block_ttl` | Duration | `15m` | First-offense block duration; doubles per repeat offense. |
| `max_block_ttl` | Duration | `4h` | Backoff cap. Must be >= `block_ttl`. |
| `thresholds` | map of Rate | `signature: 10/min`, `pow_fail: 10/min`, `tamper: 10/min` | Bad events per window before the IP is blocked, keyed by event type. |

### waf.keywords

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable keyword/regex threat signatures, matched against the decoded path, query, and User-Agent. |
| `rules_file` | string | | Rules file (start from `deploy/rules-common.yaml`). Must exist when enabled (fail-fast); hot-reloaded on change. |

### waf.anomaly

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable statistical anomaly scoring. Requires a model trained from your own logs; see [Train the Anomaly Model](/guide/anomaly). |
| `model` | string | | Path to the model artifact from `guardian-train`. Hot-swapped when the file changes. |
| `challenge_at` | float | | Score at or above this triggers a PoW challenge, with difficulty scaled by the score. Must satisfy `0 < challenge_at < deny_at <= 1`. |
| `deny_at` | float | | Score at or above this denies outright. |

### waf.honeypot

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable honeypot trap paths: one hit means an instant block. |
| `paths` | list | `[]` | Paths no legitimate client visits, e.g. `["/admin-old/"]`. Also `Disallow` them in robots.txt. |

### waf.uuid_tamper

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Detect forged or replayed signed IDs (tamper events feed `ip_behaviour`). |

### allowlist / denylist

Static lists, evaluated before everything else. Matching rules:

| Option | Type | Matching |
|---|---|---|
| `ips` | list | CIDRs or bare IPv4/IPv6 addresses. |
| `uas` | list | Case-insensitive substring match on User-Agent. |
| `paths` | list | Exact match, or prefix match when the entry ends with `/`. |

```yaml
allowlist:
  ips: [ "127.0.0.1", "::1" ]
  uas: [ "Googlebot", "bingbot" ]
  paths:
    - /robots.txt
    - /favicon.ico
    - /.well-known/         # trailing slash = prefix match (ACME http-01 etc.)
denylist:
  ips: []
```
