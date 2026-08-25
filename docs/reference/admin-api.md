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

Unsafe cross-origin browser requests are rejected before an admin handler runs,
even when they carry a valid token. Same-origin dashboard requests and
non-browser operator clients without browser origin headers continue normally.

The token comes from `admin.token` (or `ADMIN_TOKEN`), the auto-generated
`admin.token_file`, or, on a loopback listener with neither set, a fresh
per-start token printed in the startup log; see
[the token resolution order](/guide/admin).

`/metrics`, `/healthz` and `/readyz` are open (a scraper or an orchestrator
probe needs no secret). Binding the admin listener to a non-loopback address
without a configured token is refused at startup.

## Open endpoints

### `GET /healthz`

Liveness probe. Returns `ok`.

It answers as long as the process is serving, and deliberately does **not**
follow the store: Guardian [fails open](/guide/threat-model), so a store outage
leaves it passing traffic. Tying liveness to the store would kill containers and
flap units that are still doing useful work. Use `/readyz` for that question.

### `GET /readyz`

Readiness probe: is the shared state Guardian's stateful protection depends on
actually working? A background checker writes a nonce to the store and reads it
back every 10 seconds; this endpoint reports the last snapshot and performs no
store I/O itself, so an unauthenticated caller cannot turn readiness checks into
store traffic.

`200` with `"ready":true`:

```json
{"ready":true,
 "store":{"probed":true,"up":true,"backend":"pebble","latency_ms":0.4,
          "checked_at":"2026-07-21T20:14:03Z"},
 "enforcement":{"sinks":[{"name":"nftables","healthy":true}]},
 "attack":{"level":"normal"}}
```

`503` with `"ready":false` and one of four stable reasons:

| Reason | Meaning |
|---|---|
| `store probe pending` | The checker is wired but no probe has completed yet (startup). |
| `store probe unavailable` | No checker is attached. A wiring fault, not a store problem. |
| `store probe failed` | The write/read-back round trip failed. Guardian is failing open. |
| `store probe stale` | No probe completed for three intervals; the last snapshot is no longer trustworthy. |

Only store readiness sets the status code. The `enforcement` and `attack` blocks
are informational and never fail readiness: a degraded nftables sink or a raised
attack posture both still protect traffic, and dropping the instance out of a
load balancer during exactly that incident would be the wrong reflex. Both
blocks are omitted when unconfigured.

With a **shared** store, do not wire `/readyz` into load-balancer membership or
a Kubernetes `readinessProbe`: one store outage fails readiness on every replica
simultaneously and would pull the whole (still fail-open serving) fleet at once.
Use it for rollout gating and startup ordering, and alert on it during steady
state; see [the production guide](/guide/production#probes-liveness-vs-readiness).

The reason is deliberately coarse and the response carries no raw backend error
(those can contain addresses, DSN credentials or filesystem paths). The detail
goes to the log and to the token-guarded [`/admin/stats`](#get-admin-stats)
`health` object.

Responses are `Cache-Control: no-store`.

The probe is a write **and** a read-back requiring an exact nonce match, not a
ping: a read-only replica, a full disk or a silently lossy backend all accept a
write, and would pass a liveness-style check while losing every value Guardian
stores.

### `GET /metrics`

Prometheus metrics: decisions by action/reason/domain, challenge lifecycle,
PoW solve-time and anomaly-score histograms, blocks placed, bot verification
outcomes, reputation feed entries and refreshes, store op latency, and
end-to-end `Evaluate()` latency. Every series is listed in the
[Metrics reference](/reference/metrics). Import [`deploy/grafana-dashboard.json`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/grafana-dashboard.json)
for a ready-made dashboard.

## Blocks

Every `{ip}` member route requires a valid IP address and canonicalizes
equivalent spellings (including expanded or uppercase IPv6) to the same block.

### `GET /admin/blocks`

List a bounded page of active blocks, with reasons and expiry. `limit` defaults
to `1000`, must be `1..10000`, and `complete:false` means additional blocks
exist beyond the returned page.

```json
{"count":2,"complete":true,"blocks":[{"ip":"203.0.113.9","reason":"waf:dotfile-probe",
                      "expires_at":"2026-07-05T18:30:00Z"}]}
```

### `GET /admin/blocks/{ip}`

Is this IP currently blocked, why, until when, and how often has it been
blocked before?

```json
{"ip":"203.0.113.9","blocked":true,"reason":"threshold:rule_match",
 "expires_at":"2026-08-24T22:14:39+02:00","offenses":4}
```

| Field | Meaning |
|---|---|
| `blocked` | Whether a block is active right now. Always present. |
| `reason` | Why it was placed. Omitted when not blocked. |
| `expires_at` | When the block lapses. Omitted when not blocked, when the block has no expiry, or when the store could not report one. |
| `offenses` | Blocks placed on this IP in the last 24h, the counter behind the doubling backoff. Omitted when the IP has never tripped a threshold. |

`offenses` counts *automatic* blocks from `waf.ip_behaviour` thresholds, not
manual ones placed through this API, and it outlives the block itself, so an
IP that is clear right now can still report `"offenses":4`. That is the point:
it tells you a quiet-looking IP has been blocked four times today before you
decide whether to unblock or to block it for longer.

Both enrichments are best-effort. If the store cannot supply them the field is
simply absent, and `blocked`/`reason` still answer.

### `PUT /admin/blocks/{ip}`

Place a manual block. Body fields `reason` and `ttl` are optional; the
default TTL is `24h`. It is deliberately far longer than the behavioural
ladder's first rung (`block_ttl`, `30m`): a manual block is an operator
deciding an IP is bad, not the scoreboard reacting to one burst. Pass an
explicit `ttl` for a shorter block. An explicit TTL must be greater than zero
and at most one year (`8760h`, i.e. `1y`). JSON member names are case-sensitive;
malformed input, unknown or duplicate names, invalid UTF-8, and trailing values
return `400` without changing block state.

`ttl` takes the same units as [`guardian.yaml`
durations](/reference/configuration#duration-units): `30d`, `2w`, `1y` and
`720h` are all valid.

```sh
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
     -d '{"reason":"manual abuse report","ttl":"30d"}' \
     http://127.0.0.1:8072/admin/blocks/203.0.113.9
```

### `DELETE /admin/blocks/{ip}`

Lift a block **and clear the state that produced it**.

Lifting the block on its own would be worse than doing nothing. The
[`ev:` counter](/reference/store-keys) that crossed a `waf.ip_behaviour`
threshold stays at or above the limit for the rest of its window, so the next
scored event re-blocks the IP within seconds; the `chesc:`/`chfesc:` challenge
escalation stays pinned at the difficulty ceiling, so every further issuance
reports a `challenge_farm` event; and `blkct:` makes each re-block twice as long as the
last one, laddering toward the 30-day ceiling. So the event counters and the
escalation are always cleared.

| Parameter | Default | Description |
|---|---|---|
| `reset_backoff` | `true` | Also clear `blkct:`, the 24h repeat-offender counter behind the block-TTL doubling. Anything other than a boolean returns `400`. |

Leave `reset_backoff` at its default when the block was a mistake: the offense
it recorded is a mistake too, and the next block of that IP should start at the
base `block_ttl`. Pass `reset_backoff=false` when you are giving a borderline
client another chance and the offense history is real and worth keeping.

```sh
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE \
     'http://127.0.0.1:8072/admin/blocks/203.0.113.9?reset_backoff=false'
```

```json
{"ip":"203.0.113.9","blocked":false,
 "reset":{"event_keys":15,"escalation_keys":4,"backoff_reset":false}}
```

| Field | Meaning |
|---|---|
| `event_keys` | Old-generation `ev:` counter keys addressed, three per configured (event type, window). The final generation rotation is the authoritative clear; deleting the old exact keys reclaims them promptly. |
| `escalation_keys` | Host+IP escalation counters cleared, two per host (`chesc:` and `chfesc:`). |
| `backoff_reset` | Whether `blkct:` was cleared. |
| `incomplete` | Present and `true` when state that can re-block the IP may have survived: a challenge escalation that could not be cleared, or an IP seen on more hosts than one unblock clears. Behaviour counters do not set it, because the final commit rotates the generation their keys are named after and a counter left behind is one nothing will read again. Steps that only tidy up log their failure instead, so this stays a signal worth acting on. Omitted otherwise. |

Neither `ev:` nor the `chesc:`/`chfesc:` pair is enumerable by prefix, so the keys are rebuilt
from the running config: every `(event type, window)` pair across the defaults,
every domain and every `paths:` overlay, and, for the escalation, the hosts
this IP was acted on (from the decision ring) plus the configured vhosts, up to
128. One gap survives that: an IP challenged on a host that is *not* configured
and has since aged out of the bounded ring keeps its escalation counter until
the challenge TTL lapses.

Counters are bucketed by absolute time, so each `(event type, window)` pair
clears three buckets: the live one, the previous one (a replica whose clock
trails this instance is still writing it) and the next one (a replica whose
clock leads it has already been writing that, possibly to the threshold).

The reset uses two generation boundaries against live traffic:

1. It first writes a short `unblk:<ip>` marker and a fresh
   `unblkgen:<ip>`, then deletes the old generation's reconstructed producer
   keys. While the marker exists, instances normally skip behaviour counting
   and automatic blocks for the IP.
2. After the potentially slow reset work, one atomic store commit publishes
   another fresh marker/generation while removing `block:` and, when requested,
   `blkct:`.

The second boundary is why correctness does not depend on continuously renewing
a finite lease through an unbounded number of store round trips. Each `ev:` key
contains the generation that admitted it. An event increment that passed the
first marker check and finishes late writes only an obsolete key; traffic after
the response uses the final generation.

Automatic block placement is atomic with the same fence. The backend
transaction or Redis/Valkey script verifies the generation and previous block,
advances `blkct:`, derives the backoff TTL and writes the new block together. A
writer racing the final unblock therefore commits wholly before it and is
removed, or fails wholly after it without restoring the offense count. The
block value still carries an owner token; enforcement notifications validate
that token and are locally ordered with removals, so a delayed writer cannot
re-add an unblocked IP or replace a newer mirror entry.

`unblkgen:` is retained for one day and uses a fresh opaque value rather than a
timestamp or incrementing counter. No instance clocks are compared, and a new
unblock cannot inherit an earlier generation's almost-expired lifetime.

**Admin blocks are not affected by the marker.** `PUT /admin/blocks/{ip}`
straight after a `DELETE` does exactly what you asked; only automatic
threshold and instant blocks are held off.

The visible consequence is that an IP an operator unblocked by mistake cannot
be automatically re-blocked for a couple of seconds; blocking it by hand still
works immediately.

## Decisions

### `GET /admin/decisions`

The recent activity feed, newest first, from an in-process ring buffer (per
instance, cleared on restart, capacity set by `admin.recent_size`). It holds
three kinds of row: every non-allow decision, every redeemed proof-of-work
challenge (action `solve`), and every failed redemption attempt (action
`redeem_fail`). Allows - including explicit WAF allow rules - are never recorded;
their aggregate volume remains available through
`guardian_decisions_total{action="allow"}` and the dashboard's per-domain
traffic chart.

A solve is a separate row rather than an update of the challenge row that caused
it: the two arrive on different requests minutes apart and share no identifier.
Its `uri` is the page the client was trying to reach and it has no `method`, the
redemption itself being a POST to the pass endpoint.

A `redeem_fail` row is the per-attempt detail behind
`guardian_challenges_total{outcome="failed"}`, which counts without a reason.
Its reason mirrors the redeem errors one-to-one: `pow:bad_solution` (the nonce
misses the difficulty), `pow:binding_mismatch` (the challenge was issued to a
different host or IP, commonly a VPN or mobile handover moving the client
between issue and redeem), `pow:unknown_challenge` (unknown, expired or already
spent), `pow:too_fast` and `pow:nojs_disabled` (no-JS redemptions), or
`pow:internal_error` (Guardian failing, not the client; a burst of these is a
store-trouble signal). It carries no `uri`, `method` or solve fields: a failed
attempt usually has no verified challenge record to read them from. Failed
attempts also score against the IP (`pow_fail` or `tamper`,
[behaviour thresholds](/reference/configuration#waf-ip-behaviour)), so
repetition earns a block; a lone row costs the client one page refresh.

Solve rows carry algorithm and work fields, absent on every other row (absent
means unknown, not zero):

| Field | Meaning |
|---|---|
| `solve_ms` | What the client reported spending on the proof computation, from a `performance.now()` delta around its workers. **Unauthenticated telemetry.** It is the only measurement of pure client work, but a client can under-report it. Absent when no work was performed (a no-JS redemption) or when the reported value could not have been true, in which case `guardian_challenges_total{outcome="solve_time_implausible"}` counts it. |
| `round_trip_ms` | Issue to redeem, measured by the daemon from the challenge's own issued-at. Not forgeable, but not solve time either: it includes page load, both network legs and any time the tab spent backgrounded, so read it as an upper bound. |
| `pow_algorithm` | `sha256` or `argon2id`, authenticated by the issued challenge. |
| `bits` | For SHA-256, the leading-zero-bit difficulty actually required after escalation. Absent for Argon2id. |
| `argon2_memory_kib` | For Argon2id, the memory cost in KiB. Absent for SHA-256. |
| `argon2_iterations` | For Argon2id, the iteration count. Absent for SHA-256. |

Neither timing is evidence about a client, and neither should decide anything;
they are inputs for tuning SHA-256 difficulty or Argon2id work parameters. When
GeoIP/ASN databases are configured, each row may also contain `country`,
`city`, `subdivision`, `accuracy_radius_km`, `asn`, and `as_org`. These optional
fields are looked up when the feed is read, once per distinct IP in the
response; they do not add work to the request decision path and are omitted
when unavailable.

Query parameters:

| Parameter | Default | Description |
|---|---|---|
| `limit` | `50` | Maximum entries returned, or `all` for every entry in the configured bounded ring. |
| `action` | | Filter: `deny`, `challenge`, `refuse`, `solve` or `redeem_fail`. `refuse` means Guardian withheld a challenge after classifying the request as unable to complete it, so it is neither a block nor a puzzle anyone was asked to solve. `solve` returns only redeemed challenges, `redeem_fail` only failed redemption attempts. |
| `reason` | | Filter by reason prefix, e.g. `waf`, or `pow` for every proof-of-work verdict, which also matches the `pow:solved` and `pow:nojs` rows of solved challenges and the `pow:*` rows of failed attempts (filter on `action` to separate them). Token-related outcomes are `pow:no_token`, `pow:token_expired`, `pow:token_binding`, `pow:token_underdifficulty`, `pow:token_invalid`, and `pow:unchallengeable`; the last is paired with action `refuse` rather than `challenge` (see [Troubleshooting](/guide/troubleshooting#legitimate-visitors-get-challenged-or-blocked)). |
| `ip` | | Filter to one client IP, matched exactly after canonicalisation (`::ffff:1.2.3.4` matches `1.2.3.4`); a value that is not an IP returns `400`. Used by the dashboard's IP lookup. |
| `view` | detailed | Set to `compact` to return only `time`, `action`, and `reason` without GeoIP/ASN enrichment. Intended for live chart bucketing; `solve` and `redeem_fail` rows are returned like any other, and the dashboard's charts drop them (an outcome is the consequence of a challenge already plotted). |

Both views include retention metadata. `truncated` describes the response limit,
while `window.full` says whether the ring itself has overwritten older decisions.
Together with `started_at` and the retained oldest/newest timestamps, clients can
distinguish an empty covered interval from unavailable history.

```json
{
  "count": 1024,
  "truncated": true,
  "window": {
    "available": 4096,
    "capacity": 4096,
    "full": true,
    "started_at": "2026-07-22T00:00:00Z",
    "oldest": "2026-07-22T00:18:00Z",
    "newest": "2026-07-22T00:26:00Z"
  },
  "decisions": [
    {"time":"2026-07-22T00:26:00Z","host":"shop.example.com","ip":"198.51.100.7",
     "uri":"/checkout","ua":"Mozilla/5.0 ...","action":"solve","reason":"pow:solved",
     "solve_ms":1904,"round_trip_ms":2412,"pow_algorithm":"sha256","bits":20},
    {"time":"2026-07-22T00:25:58Z","host":"shop.example.com","ip":"203.0.113.9",
     "method":"GET","uri":"/.env","ua":"python-requests/2.31",
     "action":"deny","reason":"waf:dotfile-probe"}
  ]
}
```

### `GET /admin/stats`

A small "right now" rollup: the mirror's active-block count, recent counts by
action and reason category, and the PoW lifecycle. `blocks_complete:false`
means `blocks_active` is a lower bound (or `-1` while the mirror has not seeded),
never the result of an expensive fallback scan. Long-horizon numbers live in
`/metrics`.

The `challenges` object carries the lifecycle counters (`issued`, `solved`,
`failed`, ...), the mean client-reported solve time, and, once any redemption
has failed, a `failures` map with the per-reason split behind `failed`
(`{"bad_solution": 4, "binding_mismatch": 2}`), read from
`guardian_challenge_failures_total`. Process lifetime, like the funnel itself.

`recent.total` and `recent.by_reason` count decisions only; `recent.by_action`
covers everything the ring holds, so it also carries the `solve` and
`redeem_fail` counts. An outcome row is not a verdict, and every one of them
collapses to the `pow` reason category, so counting them there would pin the
dashboard's top-reason tile to `pow` on any healthy proof-of-work site.

It also carries a `health` object: the authenticated companion to `/readyz`,
with the raw probe error and the supporting numbers behind the dashboard's
System health card.

```json
"health":{
  "store":{"probed":true,"up":false,"backend":"redis","latency_ms":100.7,
           "checked_at":"2026-07-21T20:14:03Z",
           "error":"dial tcp 127.0.0.1:6379: connection refused"},
  "store_ops":{"total":91240,"errors":812},
  "store_signals":{"error_ratio":0.08,"slow_ratio":0.31},
  "store_thresholds":{"error_ratio":0.05,"slow_ratio":0.25},
  "shed":{"shed":19,"pass_token":4},
  "pow_fallback":{"issued_stateless_fallback":22,"spent_cas_failed":3},
  "enforcement":{"mirror":{"seeded":true,"entries":412,"complete":true},
                 "sinks":[{"name":"nftables","healthy":false,"last_error":"..."}]}
}
```

`store_ops`, `shed` and `pow_fallback` are **process-lifetime** counters: they
say what has happened since guardiand started, not what is happening now. One
failure hours ago leaves them nonzero forever. Read a component as actively
degraded only when a counter moves between two refreshes (and re-baseline when
one decreases, which means the process restarted). `store_signals` are the
detector's current-window ratios and `store_thresholds` the resolved config
values they are compared against; a threshold of `0` means that signal is
disabled. Windowed latency quantiles are deliberately absent here: Prometheus
computes those correctly and lifetime totals cannot.

The whole object is derived from a single registry gather shared with the
challenge rollup, so a dashboard refresh costs one `Gather()`, not two. The
counter blocks are omitted entirely when metrics are disabled, rather than
reported as zeroes.

### `GET /admin/distributions`

Registry-derived data the recent-decisions ring cannot supply, in one pass: the
solve-time and anomaly-score histograms (as ready-to-plot per-bucket counts, not
cumulative), anomaly baseline selections/misses, and per-domain decision totals
from `decisions_total` (allow-inclusive, since the ring holds no allows). It
reads metrics that already exist, adds no cardinality, and never touches the hot
path. Feeds the dashboard's distribution charts and anomaly coverage warning.

`solve_time` is merged across every domain; `solve_time_by_domain` is the same
observations split by the bounded domain label, which is what answers "whose
puzzle is too hard for its visitors". Both cover the process lifetime, so they
outlive the bounded ring behind `/admin/decisions`.

```json
{
  "solve_time": {"buckets":[{"le":"0.25","count":140},{"le":"+Inf","count":3}],"sum":41.2,"count":143},
  "solve_time_by_domain": {"shop.example.com":{"buckets":[{"le":"1","count":90}],"sum":38.4,"count":93}},
  "anomaly":    {"buckets":[{"le":"0.1","count":10}],"sum":3.1,"count":10},
  "anomaly_selection": {"example.com":{"exact":8,"domain":2}},
  "anomaly_misses": {},
  "per_domain": {"example.com":{"allow":349472,"challenge":30}}
}
```

### `GET /admin/offenders`

The heaviest sources of non-allow decisions in the recent window: top IPs,
reason categories, request paths, exact User-Agent strings and normalized hosts,
plus a country rollup when GeoIP is loaded.
Counts the in-process decision ring exactly (bounded by `admin.recent_size`,
with no extra hot-path work). The window is the ring, so it covers challenged/denied
traffic, not allows. Proof-of-work outcomes (`solve`, `redeem_fail`) are in that
ring too, and are excluded from every rollup here including `window`: this list
is read to decide who to block, the clients that paid their proof of work are
the last ones that belong on it, and a failed redemption is as often a VPN
moving a visitor between exit IPs as it is abuse (the abusive kind arrives here
on its own once `pow_fail`/`tamper` scoring blocks the IP). Paths are
query-stripped; GeoIP/ASN is merged for the top
IPs only, and the country rollup is omitted when no databases are loaded.

`ips`, `reasons`, `paths`, `user_agents` and `hosts` are capped at the **top
15** entries, since they are unbounded and partly attacker-controlled. An empty
User-Agent remains the empty `key` in the API so it is counted rather than
silently discarded. Host keys are lowercased with ports, IPv6 brackets and a
trailing dot removed. `countries` is **not capped**: it
covers every distinct IP in the window, sorted by count descending, so a botnet
spread thin across many addresses is reported at its true weight rather than
ranked below one noisy IP from elsewhere. It is bounded by the ring in the worst
case, and in practice by the number of countries with traffic. Country keys are
ISO 3166-1 alpha-2 codes; the dashboard expands them to English country names.

```json
{
  "window": 4096,
  "ips": [{"ip":"203.0.113.10","count":30,"country":"RU","asn":64500,"as_org":"Example Carrier"},
          {"ip":"84.86.0.1","count":12,"country":"NL","city":"Schagen",
           "subdivision":"NH","accuracy_radius_km":10,"asn":1136,"as_org":"KPN B.V."}],
  "reasons": [{"key":"denylist","count":50}],
  "paths": [{"key":"/wp-login.php","count":30}],
  "user_agents": [{"key":"sqlmap/1.7#stable","count":28}],
  "hosts": [{"key":"shop.example.com","count":45}],
  "countries": [{"key":"RU","count":30}]
}
```

`city` and `subdivision` need a City-class
[`location_db`](/reference/configuration#geoip) and are **absent** for roughly a
fifth of networks even then, so treat a missing key as normal rather than an
error. `accuracy_radius_km` is the radius of the area the record describes, not
a precision: values of 200 and up are common and mean the locality is a
region-or-larger guess. Latitude and longitude are deliberately not exposed;
see [Country or City](/guide/bots-ip-intel#country-or-city-both-go-in-location-db).

## Scoring

### `GET /admin/score`

Score a hypothetical request against the domain's anomaly model, for tuning
`challenge_at` / `deny_at`.

Query parameters: `host`, `method` (defaults to `GET`), `uri`, `ua`.

```json
{"host":"shop.example.com","method":"GET","route":"/cgi-bin","baseline":"exact","scored":true,"score":0.72}
```

When the host has no baseline it returns `scored:false` with a reason instead
of presenting the missing baseline as a zero score.

### `GET /admin/anomaly`

Returns bounded operational metadata for the loaded anomaly artifacts and all
configured default/domain/path scopes. Each enabled scope reports `observe` or
`enforce` mode, artifact path, coverage (`ready`, `dynamic`, or `missing`), and
its automatic segment count. Artifacts report their training time and domains;
learned frequencies and raw baseline values are never returned.

## IP intelligence

### `GET /admin/intel`

The state of the IP-intelligence sources: which GeoIP databases are loaded
(type, build date) and every reputation feed's entry count, last refresh,
and last error. Returns `{"enabled": false}` when neither
[`geoip`](/reference/configuration#geoip) nor
[`reputation`](/reference/configuration#reputation) is configured.

```json
{"enabled":true,"intel":{
  "location_db":{"path":"/var/lib/GeoIP/GeoLite2-Country.mmdb",
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

## Server traffic

### `GET /admin/angie`

Relays Angie's own [HTTP API][angie-api]: the real per-domain traffic, backend
health and cache behaviour that Guardian never sees on its stateless allow path.
Requires [`admin.angie_api`](/reference/configuration#admin); returns
`{"enabled": false}` when unconfigured.

[angie-api]: https://en.angie.software/angie/docs/configuration/modules/http/http_api/

guardiand fetches Angie's API server-side (keep it on loopback) and relays a
fixed set of endpoints, each under its own key, with Angie's own JSON passed
through unchanged:

| Key | Angie endpoint | Needs |
| --- | --- | --- |
| `angie` | `/angie/` | always present |
| `connections` | `/connections/` | always present |
| `server_zones` | `/http/server_zones/` | `status_zone` in a `server {}` |
| `location_zones` | `/http/location_zones/` | `status_zone` in a `location {}` |
| `caches` | `/http/caches/` | a `proxy_cache_path` |
| `limit_conns` | `/http/limit_conns/` | a `limit_conn_zone` |
| `limit_reqs` | `/http/limit_reqs/` | a `limit_req_zone` |
| `upstreams` | `/http/upstreams/` | `zone` in an `upstream {}` |
| `slabs` | `/slabs/` | any shared memory zone |

The endpoints are read concurrently and cached for ~3s. `as_of` carries the read
time per relayed key, which is what the dashboard differences Angie's cumulative
counters against to show per-second rates.

It degrades rather than fails: the response always carries `enabled`, a key is
simply absent when Angie has no such zone configured (that endpoint 404s), and
an `error` string appears only when no endpoint at all is reachable. See
[Enabling the Angie API](/guide/admin#enabling-the-angie-api).

```json
{"enabled":true,
 "angie":{"version":"1.12.1","generation":7,"load_time":"2026-07-24T20:38:03.930Z"},
 "connections":{"accepted":86880,"dropped":0,"active":39,"idle":55},
 "server_zones":{"example.com":{"requests":{"total":152340,"processing":7},
   "responses":{"200":140100,"404":8900},"data":{"received":48219000,"sent":1329000000}}},
 "location_zones":{"/api/":{"requests":{"total":88010}}},
 "upstreams":{"backend":{"peers":{"10.0.0.2:8080":{"state":"up",
   "health":{"fails":0,"downtime":0,"response_time":9}}},"keepalive":1}},
 "as_of":{"angie":"2026-07-24T22:27:40.989Z","server_zones":"2026-07-24T22:27:40.989Z"}}
```

When Angie's API is unreachable:

```json
{"enabled":true,"error":"angie api returned status Not Found"}
```

## Enforcement offload

### `GET /admin/offload`

The state of the [block enforcement offload](/guide/block-offload): the
in-process mirror (mode, entry count, seed/completeness status, last reconcile,
drop count) and every external sink's health. `complete: false` means a mirror
miss must read through to the store, even if its configured mode is
`authoritative`, because startup seeding is unfinished or capacity omitted an
active block. Returns `{"enabled": false}` when the offload manager is not
wired.

```json
{"mirror":{"entries":12,"mode":"authoritative","seeded":true,"complete":true,
           "last_reconcile":"2026-07-19T10:00:00Z","reconcile_errors":0,"dropped":0},
 "sinks":[{"name":"nftables","mode":"managed","healthy":true,
           "elements":12,"last_error":""}]}
```

### `POST /admin/offload/reconcile`

Force an immediate active-block index reconcile: drift repair after a manual
`nft flush` or an out-of-band store edit, without waiting for the next
reconcile tick. The reconcile runs asynchronously. Returns `409` when the
offload manager is not active.

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
both directions, so pinning `normal` is a local kill switch). A pin ignores
peer posture and clears this instance's shared automatic vote; apply it to
every replica for a fleet-wide override. `ttl` is optional (no expiry when
omitted); when present it must be positive and no more than one year. Unknown
JSON fields are rejected. Returns `409` when attack mode is not active.

```json
{"pinned":true,"level":"attack"}
```

## Keys and config

### `POST /admin/rotate-key`

Atomically archive the current Ed25519 signing key into `previous_key_dir` and
generate a new one. `previous_key_dir` must be configured. Live replicas that
share both key paths refresh automatically before issuing stateless challenges
or accepting JWTs. A verifier fails closed if that refresh cannot read the
shared key files. Retired keys accept only tokens issued before rotation, with
a maximum token lifetime of thirty days.
Archives older than that verification horizon are ignored in memory (they are
not automatically deleted from disk).

```json
{"rotated":true}
```

### `GET /admin/config`

The active per-domain configuration: which features are enabled where,
including PoW algorithm, SHA-256 base/max difficulty, Argon2id work parameters,
the count of configured header predicates (never their names, values, verifier
claims or key material),
and each scope's effective WAF rule
selection (`waf_rules_files` plus `waf_rules_disabled_ids`, both omitted when
empty), anomaly state (`waf_anomaly` and `waf_anomaly_observe_only`) and, when a scope defines
[per-path overrides](/reference/configuration#per-path-overrides-domains-host-paths),
a `paths` object with the same view per overlay. `defaults` carries its own
`paths` when the fleet-wide overlays are configured; a domain's `paths` lists
its effective overlays, inherited entries included:

```json
{
  "store": "pebble",
  "defaults": { "pow_enabled": false, "pow_base_difficulty": 5, "...": "..." },
  "domains": {
    "example.com": {
      "pow_enabled": true,
      "pow_algorithm": "sha256",
      "pow_base_difficulty": 5,
      "pow_max_difficulty": 6,
      "pow_argon2id_memory_kib": 32768,
      "pow_argon2id_base_iterations": 1,
      "pow_argon2id_max_iterations": 2,
      "pow_argon2id_attack_iterations_cap": 3,
      "pow_header_exemptions": 0,
      "waf_rules": true,
      "waf_anomaly": true,
      "waf_anomaly_observe_only": true,
      "waf_rules_files": [
        "/etc/guardian/rules.d/common.yaml",
        "/etc/guardian/rules.d/api.yaml"
      ],
      "waf_rules_disabled_ids": ["wp-cms-probe"],
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

Listener addresses, the store backend, signing key paths, admin token setup and
`admin.recent_size` are fixed at startup; changing those fields still requires
a restart
(the reload is rejected with `422`, leaving the active config unchanged).

### `GET /admin/reload/preflight`

Answers "would SIGHUP apply the on-disk `guardian.yaml`?" without applying
anything, so reloads become predictable instead of trial and error. It
re-reads the file and diffs the startup-fixed fields against the running
process:

```json
{"reloadable":true,"restart_required":[]}
```

```json
{"reloadable":false,"restart_required":["listen","store.backend"]}
```

A config that does not load at all is reported with `422` and the parse error
in `error`, exactly what a reload would be rejected for.

## Dashboard

### `GET /admin/dashboard`

The built-in reporting page (only when `admin.dashboard: true`). On startup
guardiand logs only the bare URL; enter the token from `admin.token_file` (or
your configured secret) into the login gate. Configured and persistent tokens
are never embedded in process logs. Every data call the page makes goes to the
token-guarded `/admin/*` endpoints. See
[the reporting dashboard](/guide/admin#the-reporting-dashboard). Headline and
recent-decision data refresh every five seconds; the active-block list is
capped at 1000 rows, cached for one minute, and refreshed immediately after a
block/unblock action. Incomplete mirror counts are reported as lower bounds
without a fallback full-store scan. The activity charts share fixed-axis
`5m / 15m / 30m / 1h / all` controls over a compact full-ring feed; detailed table
and GeoIP rows remain capped at 1024. This is a per-instance live incident view.
Use `/metrics` with Prometheus retention and Grafana for historical analysis.
