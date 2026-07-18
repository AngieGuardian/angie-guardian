# Admin API

The admin API lives on `admin.listen` (e.g. `127.0.0.1:8072`), separate from
the auth hot path. Every JSON/data `/admin/*` route requires the bearer token:

```
Authorization: Bearer <token>
```

The optional static `/admin/dashboard` shell is the sole exception; it contains
no data and uses the token for every API call. The authorization scheme for
protected routes must use the exact `Bearer ` prefix; another scheme
followed by the same secret is rejected.

The token comes from `admin.token` (or `ADMIN_TOKEN`), the auto-generated
`admin.token_file`, or, on a loopback listener with neither set, a fresh
per-start token printed in the startup log; see
[the token resolution order](/guide/admin).

`/metrics` and `/healthz` are open (a scraper needs no secret). Binding the
admin listener to a non-loopback address without a configured token is
refused at startup.

## Open endpoints

### `GET /healthz`

Liveness probe. Returns `ok`.

### `GET /metrics`

Prometheus metrics: decisions by action/reason/domain, challenge lifecycle,
PoW solve-time and anomaly-score histograms, blocks placed, bot verification
outcomes, reputation feed entries and refreshes, store op latency, and
end-to-end `Evaluate()` latency. Every series is listed in the
[Metrics reference](/reference/metrics). Import `deploy/grafana-dashboard.json`
for a ready-made dashboard.

## Blocks

Every `{ip}` member route requires a valid IP address and canonicalizes
equivalent spellings (including expanded or uppercase IPv6) to the same block.

### `GET /admin/blocks`

List every currently active block, with reasons and expiry.

```json
{"count":2,"blocks":[{"ip":"203.0.113.9","reason":"waf:dotfile-probe",
                      "expires_at":"2026-07-05T18:30:00Z"}]}
```

### `GET /admin/blocks/{ip}`

Is this IP currently blocked, and why?

```json
{"ip":"203.0.113.9","blocked":true,"reason":"threshold:signature"}
```

### `PUT /admin/blocks/{ip}`

Place a manual block. Body fields `reason` and `ttl` are optional; the
default TTL is `15m`. An explicit TTL must be greater than zero and at most one
year (`8760h`). Malformed or unknown JSON fields return `400` without changing
block state.

```sh
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
     -d '{"reason":"manual abuse report","ttl":"2h"}' \
     http://127.0.0.1:8072/admin/blocks/203.0.113.9
```

### `DELETE /admin/blocks/{ip}`

Lift a block.

## Decisions

### `GET /admin/decisions`

The recent deny/challenge feed, newest first, from an in-process ring buffer
(per instance, cleared on restart).

Query parameters:

| Parameter | Default | Description |
|---|---|---|
| `limit` | `50` | Maximum entries returned. |
| `action` | | Filter: `deny` or `challenge`. |
| `reason` | | Filter by reason prefix, e.g. `waf`. |

### `GET /admin/stats`

A small "right now" rollup: active blocks, recent counts by action and reason
category, and the PoW lifecycle (challenges issued/solved/failed plus average
solve seconds). Long-horizon numbers live in `/metrics`.

## Scoring

### `GET /admin/score`

Score a hypothetical request against the domain's anomaly model, for tuning
`challenge_at` / `deny_at`.

Query parameters: `host`, `uri`, `ua`.

```json
{"host":"shop.example.com","scored":true,"score":0.72}
```

## IP intelligence

### `GET /admin/intel`

The state of the IP-intelligence sources: which GeoIP databases are loaded
(type, build date) and every reputation feed's entry count, last refresh,
and last error. Returns `{"enabled": false}` when neither
[`geoip`](/reference/configuration#geoip) nor
[`reputation`](/reference/configuration#reputation) is configured.

```json
{"enabled":true,"intel":{
  "country_db":{"path":"/var/lib/GeoIP/GeoLite2-Country.mmdb",
                "type":"GeoLite2-Country","built":"2026-07-01T00:00:00Z"},
  "feeds":[{"name":"firehol-level1","action":"deny","loaded":true,
            "loaded_from":"url","entries":6512,
            "last_refresh":"2026-07-10T06:00:00Z"}]}}
```

### `GET /admin/intel/{ip}`

What do we know about this IP? Country, ASN, and the reputation feeds it
appears in, for testing geo rules and answering "why was this client
denied".

```json
{"ip":"203.0.113.9","enabled":true,
 "info":{"country":"RU","asn":64500,"as_org":"Example Carrier"},
 "feeds":[{"feed":"firehol-level1","action":"deny"}]}
```

## Enforcement offload

### `GET /admin/offload`

The state of the [block enforcement offload](/guide/block-offload): the
in-process mirror (mode, entry count, seed status, last reconcile, drop count)
and every external sink's health. Returns `{"enabled": false}` when the
offload manager is not wired.

```json
{"mirror":{"entries":12,"mode":"authoritative","seeded":true,
           "last_reconcile":"2026-07-19T10:00:00Z","reconcile_errors":0,"dropped":0},
 "sinks":[{"name":"nftables","mode":"managed","healthy":true,
           "elements":12,"last_error":""}]}
```

### `POST /admin/offload/reconcile`

Force an immediate authoritative store scan: drift repair after a manual
`nft flush` or an out-of-band store edit, without waiting for the next
reconcile tick. The scan runs asynchronously. Returns `409` when the offload
manager is not active.

```json
{"status":"reconcile scheduled"}
```

## Attack mode

### `GET /admin/attack`

The current [attack posture](/guide/attack-mode): level, since, reason,
whether it is operator-pinned, the active effects, and the current window
signal rates. Returns `{"enabled": false}` when attack mode is not active.

```json
{"level":"attack","since":"2026-07-19T10:00:00Z","reason":"challenge_rate",
 "pinned":false,
 "effects":{"extra_bits":4,"stateless":true,"force_always":true},
 "signals":{"challenge_rate":1450.0,"request_rate":0,"solve_ratio":0.02,
            "store_error_ratio":0,"store_slow_ratio":0}}
```

### `POST /admin/attack`

Pin or unpin the posture. Body `{"level": "normal"|"elevated"|"attack"|"auto", "ttl": "10m"}`.
`auto` returns to automatic detection; any other level pins (a pin wins in
both directions, so pinning `normal` is a kill switch). `ttl` is optional
(no expiry when omitted). Returns `409` when attack mode is not active.

```json
{"pinned":true,"level":"attack"}
```

## Keys and config

### `POST /admin/rotate-key`

Atomically archive the current Ed25519 signing key into `previous_key_dir` and
generate a new one. `previous_key_dir` must be configured. Live replicas that
share both key paths refresh automatically. Retired keys accept only tokens
issued before rotation, with a maximum token lifetime of seven days.
Archives older than that verification horizon are ignored in memory (they are
not automatically deleted from disk).

```json
{"rotated":true}
```

### `GET /admin/config`

The active per-domain configuration: which features are enabled where,
including PoW base/max difficulty and, when a domain defines
[per-path overrides](/reference/configuration#per-path-overrides-domains-host-paths),
a `paths` object with the same view per overlay:

```json
{
  "store": "bbolt",
  "defaults": { "pow_enabled": false, "pow_base_difficulty": 5, "...": "..." },
  "domains": {
    "example.com": {
      "pow_enabled": true,
      "pow_base_difficulty": 5,
      "pow_max_difficulty": 6,
      "paths": {
        "/api/v1/": { "pow_enabled": false, "...": "..." }
      }
    }
  }
}
```

### `POST /admin/reload`

Re-read `guardian.yaml` and apply it without a restart, exactly like sending
the daemon a `SIGHUP`. Domains, allow/denylists, thresholds, PoW settings,
rule/model file sets, GeoIP databases, reputation feeds and the log level all
take effect immediately; behavioural state (active blocks, counters, issued
tokens) is untouched. A config that fails to load or validate is rejected
with `422` and the running config stays active.

```json
{"reloaded":true}
```

Listener addresses, the store backend, signing key paths and the admin token
setup are fixed at startup; changing those fields still requires a restart
(the reload is rejected with `422`, leaving the active config unchanged).

## Dashboard

### `GET /admin/dashboard`

The built-in reporting page (only when `admin.dashboard: true`). On startup
guardiand logs a ready-to-open login URL carrying the token in the URL
fragment; opening the bare URL shows a paste-the-token gate instead. Every
data call the page makes goes to the token-guarded `/admin/*` endpoints. See
[the reporting dashboard](/guide/admin#the-reporting-dashboard).
