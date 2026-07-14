# Admin API

The admin API lives on `admin.listen` (e.g. `127.0.0.1:8072`), separate from
the auth hot path. Every `/admin/*` route requires the bearer token:

```
Authorization: Bearer <token>
```

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
default TTL is `15m`. The path must contain a valid IP address; equivalent IPv6
spellings are canonicalized. An explicit TTL must be greater than zero and at
most one year (`8760h`). Malformed or unknown JSON fields return `400` without
changing block state.

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

The active per-domain configuration: which features are enabled where.

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
