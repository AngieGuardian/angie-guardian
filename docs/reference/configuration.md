# Configuration Options

Every field of `guardian.yaml`, with types and defaults. Unknown fields and
trailing YAML documents are rejected, and semantic errors fail at startup or
under `guardiand -t`. Preflight also opens every startup-required local rules,
model, GeoIP, and reputation-feed artifact. `guardian.yaml` itself is limited
to 4 MiB.

See the [Configuration guide](/guide/configuration) for the concepts and the
[Examples page](/examples) for complete files.

## Value formats

| Type | Format | Examples |
|---|---|---|
| Duration | Go duration string | `"30s"`, `"15m"`, `"4h"` |
| Rate | `<count>/<unit>` with unit `s`/`sec`/`second`, `m`/`min`/`minute`, or `h`/`hour` | `"10/min"`, `"5/s"`, `"100/h"` |

## Top level

| Option | Type | Default | Description |
|---|---|---|---|
| `listen` | string | `127.0.0.1:8071` | Numeric `host:port` for the auth hot path (Angie's `auth_request` target). Must be loopback unless `trusted_proxy` is set. Listener syntax is checked by `guardiand -t`. |
| `log_level` | string | `info` | One of `debug`, `info`, `warn`, `error`. |
| `trusted_proxy` | bool | `false` | Allow a non-loopback `listen`. The hot path trusts the `X-Guardian-*` client-identity headers from its caller, so only set this when the listener is isolated to Angie (private network, firewall, or mTLS). |
| `signing_key_file` | string | | Persistent Ed25519 signing key for PoW JWTs. Required when any effective domain enables PoW. Generated on first run if missing; never regenerated on restart. |
| `previous_key_dir` | string | | Where retired signing keys (from `POST /admin/rotate-key`) are archived; required for rotation. Replicas must share it with `signing_key_file`. Retired keys accept only pre-rotation tokens with lifetimes up to seven days; older archives may remain on disk but are omitted from the active verification set. |
| `admin` | object | | See [admin](#admin). |
| `store` | object | | See [store](#store). |
| `geoip` | object | | GeoIP databases for the per-domain `geo` scoping. See [geoip](#geoip). |
| `reputation` | object | | Global IP reputation feeds; domains opt in via `reputation.enabled`. See [reputation](#reputation). |
| `defaults` | object | | The base [domain config](#per-domain-options-defaults-and-domains) every domain inherits from. |
| `domains` | map | | Per-domain overrides, merged field-by-field over `defaults`. Host keys and anomaly-model lookups share one normalization for case, ports, trailing dots, and bracketed IPv6 (`A.test.:443` = `a.test`); two keys that collapse to the same host are rejected. A domain entry may also carry [`paths`](#per-path-overrides-domains-host-paths) overlays scoped to URI prefixes within the host. |

## admin

| Option | Type | Default | Description |
|---|---|---|---|
| `admin.listen` | string | (empty = disabled) | Numeric `host:port` for the Admin API + Prometheus `/metrics` listener, separate from the hot path. `/metrics`, `/healthz`, and the optional static dashboard shell are open; every JSON/data `/admin/*` route requires the bearer token. Binding to a non-loopback address without a configured token is rejected by preflight. |
| `admin.token` | string | `$ADMIN_TOKEN` | Bearer token for `/admin/*` routes. Falls back to the `ADMIN_TOKEN` env var when empty. |
| `admin.token_file` | string | | Persists an auto-generated bearer token (created 0600 on first start, never regenerated, like the signing key). Used when `token` and `ADMIN_TOKEN` are unset. With neither `token` nor `token_file`, a loopback listener gets a fresh ephemeral token per start, printed in the startup log. |
| `admin.dashboard` | bool | `false` | Serve the built-in reporting page at `GET /admin/dashboard`. On startup guardiand logs the bare URL; paste the token into the login gate. Configured and persistent bearer tokens are never embedded in logs. |
| `admin.angie_api.url` | string | (empty = disabled) | Base URL of Angie's [HTTP API][angie-api] location (e.g. `http://127.0.0.1:81/status`). Enables the dashboard's **Server traffic** panels: per-domain requests, in-flight connections, response codes and bandwidth that Guardian never sees on its allow path. guardiand reads it server-side and relays only fixed traffic-zone paths behind the admin token, so keep the API on loopback. See [Enabling the Angie API](/guide/admin#enabling-the-angie-api). |
| `admin.angie_api.timeout` | duration | `2s` | Per-fetch timeout for the Angie API read. |

[angie-api]: https://en.angie.software/angie/docs/configuration/modules/http/http_api/

## store

| Option | Type | Default | Description |
|---|---|---|---|
| `store.backend` | string | `memory` | One of `memory`, `buntdb`, `pebble`, `redis`. See [choosing a store backend](/guide/production#choosing-a-store-backend). |
| `store.path` | string | | Durable store location: a **file** for the `buntdb` backend, a **directory** for the `pebble` backend. **Required** for both. |
| `store.sync` | bool | `false` | Durable embedded backends only (`buntdb`/`pebble`). `false` is fast async; `true` fsyncs every write. `buntdb` + `sync: true` is rejected at startup (buntdb is single-writer); use `pebble` for synchronous durability. |
| `store.addr` | string | | Redis/Valkey `host:port`. **Required** for the `redis` backend. |
| `store.password` | string | `$REDIS_PASSWORD` | Redis/Valkey password. Falls back to the `REDIS_PASSWORD` env var. |
| `store.db` | int | `0` | Redis database number. |

## enforcement

Moves active-block enforcement onto layers cheaper than the per-request store
lookup. See the [Block Enforcement Offload](/guide/block-offload) guide for the
full picture. Every field is restart-required.

| Option | Type | Default | Description |
|---|---|---|---|
| `enforcement.mirror.reconcile_interval` | duration | `10s` | Cadence of the bounded active-block index read that seeds the mirror, corrects entries and repairs sink drift. Minimum `1s`. |
| `enforcement.mirror.max_entries` | int | `1048576` | Mirror capacity. Overflow entries fall back to the store read path (never lost, just not cached). |
| `enforcement.mirror.mode` | string | `auto` | `auto` (authoritative for `memory`/`buntdb`/`pebble`, read-through for `redis`), `authoritative`, or `read_through`. |
| `enforcement.nftables.enabled` | bool | `false` | Enable the kernel sink. Linux only; needs `CAP_NET_ADMIN`. |
| `enforcement.nftables.mode` | string | `managed` | `managed` (own a table + port-scoped drop rule) or `sets_only` (maintain the sets, you write the rule). |
| `enforcement.nftables.table` | string | `guardian` | nftables `inet` table name. |
| `enforcement.nftables.hook` | string | `input` | Managed mode chain hook: `input` or `prerouting`. |
| `enforcement.nftables.ports` | []int | `[80, 443]` | Managed-mode drop rule matches only these TCP ports. Refused empty in managed mode (an all-ports drop could cut off SSH/admin). |
| `enforcement.nftables.netns` | string | | Network namespace file to program instead of guardiand's own. |
| `enforcement.nftables.max_entries` | int | `65536` | Kernel set size bound. |
| `enforcement.nftables.min_ttl` | duration | `0s` | Skip offloading blocks shorter than this; `0` offloads all. |
| `enforcement.nftables.never_block` | []string | `[]` | CIDRs/IPs never sent to the kernel. Put LB/CDN ranges here. Configured allowlists are excluded automatically on top. |

## attack_mode

Fleet-wide attack posture. Off when absent. See the
[Attack Mode](/guide/attack-mode) guide. Hot-reloadable.

| Option | Type | Default | Description |
|---|---|---|---|
| `attack_mode.enabled` | bool | `false` | Enable the posture state machine. |
| `attack_mode.window` | duration | `30s` | Sliding measurement window (5s buckets). Range 10s..10m. |
| `attack_mode.min_dwell` | duration | `60s` | Minimum time at a level before it decays one step. Must be >= window. |
| `attack_mode.share_posture` | bool | `true` | Publish an expiring per-replica vote and adopt the maximum live level through the shared store. Manual pins are local, ignore peers, and clear that replica's automatic vote. |
| `attack_mode.signals.challenge_rate` | rate | `200/s` | Issuance rate entering elevated. |
| `attack_mode.signals.attack_challenge_rate` | rate | `1000/s` | Issuance rate entering attack (with the solve-ratio qualifier). Must be >= challenge_rate. |
| `attack_mode.signals.min_solve_ratio` | float | `0.2` | Attack entry requires solved/issued below this (separates a flood from a flash crowd). |
| `attack_mode.signals.request_rate` | rate | (omitted = disabled) | Global Evaluate rate entering elevated. Omit to disable (a rate cannot be `0/s`). In a partial signals block, an omitted signal stays disabled; a fully-omitted block gets all defaults. |
| `attack_mode.signals.store_error_ratio` | float | `0.05` | Store op error fraction entering elevated (3x enters attack). |
| `attack_mode.signals.store_slow_ratio` | float | `0.25` | Fraction of store ops slower than 25ms entering elevated. |
| `attack_mode.effects.elevated_difficulty_raise` | float | `0.5` | Fleet difficulty raise at elevated, in 1..8 quarter steps (+2 bits). Range 0..2, multiples of 0.25. An explicit `0.0` raises nothing at elevated; omitting the field uses the default. |
| `attack_mode.effects.attack_difficulty_raise` | float | `1.0` | Fleet difficulty raise at attack (+4 bits). |
| `attack_mode.effects.difficulty_cap` | float | `7.0` | Ceiling for the shifted window (28 bits). Range 1..8. |
| `attack_mode.effects.force_always` | bool | `true` | At attack, `pow.mode: suspicion` behaves as `always`. |
| `attack_mode.effects.stateless_issuance` | bool | `true` | At attack, issue store-free HMAC challenges. |
| `attack_mode.effects.scoreboard_factor` | float | `1.0` | At attack, multiply behavioural thresholds (0 < f <= 1). |
| `attack_mode.effects.max_inflight` | int | `0` | Bound on concurrent auth evaluations for load-shedding; 0 = off. Store-free terminal policy still applies. A clean token fast-passes only when the block mirror is seeded, complete, and authoritative; otherwise the request is shed rather than performing a store read. |

## geoip

MaxMind-format (`.mmdb`) databases: MaxMind GeoLite2/GeoIP2, DB-IP, or any
other publisher of the format. The files are hot-reloaded when replaced on
disk (as long as the update lands via an atomic rename, which `geoipupdate`
and a `curl` + `mv` both do), so scheduled updates need no restart. Either may
be omitted; a `geo` rule that needs the missing database is refused at config
load. Where to download them:
[Getting the databases](/guide/bots-ip-intel#getting-the-databases).

| Option | Type | Default | Description |
|---|---|---|---|
| `geoip.location_db` | string | | Country **or** City database, for `countries:` selectors. |
| `geoip.asn_db` | string | | ASN database, for `asns:` selectors. |

`location_db` accepts either `GeoLite2-Country.mmdb` or `GeoLite2-City.mmdb`
(also GeoIP2-Enterprise and DB-IP): City is a superset of Country, so
`countries:` selectors behave the same either way. City adds city/region labels
to the admin views but no new selectors, and costs 7.5x the file size. See
[Country or City](/guide/bots-ip-intel#country-or-city-both-go-in-location-db).

## reputation

External IP reputation feeds: plain-text lists of IPs/CIDRs (one entry per
line, `#`/`;` comments), like the FireHOL netsets or a hand-maintained local
file. Feeds are defined once here; each domain opts in via
[`reputation.enabled`](#reputation-per-domain).

| Option | Type | Default | Description |
|---|---|---|---|
| `reputation.cache_dir` | string | | Persists the last good copy of every URL feed, so a restart enforces yesterday's list immediately instead of nothing until the first fetch completes. Strongly recommended with URL feeds. |
| `reputation.feeds` | list | `[]` | The feed definitions, see below. |

Each feed entry:

| Option | Type | Default | Description |
|---|---|---|---|
| `name` | string | **required** | Label in decision reasons (`reputation:<name>`), metrics, and the cache file name. 1..64 chars of `[a-zA-Z0-9._-]`, unique. |
| `url` | string | | Fetched in the background every `refresh` interval, with a 64 MiB response/cache limit. A slow, oversized, or down remote keeps the last good list and retries within 5 minutes. Hot reload preserves the in-memory last-good state when the feed name and URL are unchanged. Exactly one of `url`/`file`. |
| `file` | string | | Local list, limited to 64 MiB. Must exist at startup (fail-fast, like the WAF rules files); hot-reloaded on change and keeps the last-good list after an invalid/oversized update. |
| `refresh` | Duration | `12h` | URL feeds only. Minimum `1m`. |
| `action` | `deny` \| `challenge` | `deny` | `deny` rejects matching IPs outright; `challenge` makes them solve PoW first, one full step (+4 bits = 16x) above base, like a WAF signature hit. Challenge feeds are inert on a PoW-disabled domain. |

## Per-domain options (`defaults` and `domains.<host>`)

Each domain entry has these sections: `waf`, `pow`, `geo`, `reputation`,
`allowlist`, `denylist`, `verified_bots`. A `domains.<host>` entry (but not
`defaults`) may additionally carry a `paths` map of per-path overlays; see
[per-path overrides](#per-path-overrides-domains-host-paths).

## Per-path overrides (`domains.<host>.paths`)

A domain entry may scope any part of its configuration to a URI prefix, so one
vhost can, for example, keep PoW on for the whole site while exempting a
machine-facing API:

```yaml
domains:
  example.com:
    pow: { enabled: true }
    paths:
      "/api/v1/":
        pow: { enabled: false }
      "/admin/":
        pow: { base_difficulty: 6 }
```

Each `paths` value is a full domain-config overlay, merged in three levels:
`defaults`, then the domain's own settings, then the path's. A path entry only
overrides the fields it mentions; everything else is inherited, exactly like a
domain entry over `defaults`. An empty path body inherits everything.

Matching rules:

- A key is an exact path, or a prefix when it ends with `/` (the same
  semantics as `allowlist.paths`). A prefix key also matches its own bare
  path: `/api/` matches `/api`.
- The most specific key wins: the longest key ignoring a trailing `/`, and an
  exact key beats a prefix key of the same length. No key matching means the
  domain's own config applies.
- Matching is against the percent-decoded request path (the honeypot and WAF
  convention), so `/api%2Fv1/` cannot dodge an override. Keys must be written
  percent-decoded; an encoded key is rejected at load.
- Matching is byte-exact and case-sensitive, and dot-segments are not
  resolved. Keys must start with `/` and cannot contain `?` or `#`.
- Keys are plain prefixes: no globs or regular expressions.

Restrictions and behavior notes:

- `paths` is only valid inside a `domains.<host>` entry: not under `defaults`
  and not nested inside another path overlay. Both are load errors.
- A WAF signature with `action: challenge` degrades to a deny on a path whose
  overlay disables PoW, exactly as it does on a PoW-disabled domain.
- A PoW token records the difficulty it was solved at and only vouches where
  that difficulty meets the resolved path's `base_difficulty`. A token earned
  on a cheaper path re-challenges on a harder one, and raising
  `base_difficulty` in config invalidates outstanding weaker tokens.
- A token is also held to the resolved path's `token_ttl`: a long-lived token
  issued on a lax path is re-challenged once it is older than a stricter path's
  `token_ttl`, even though the cookie's own expiry (set on the issuing path) has
  not yet passed. The issuing-path lifetime remains the upper bound.
- Per-path overlays are a sidecar feature; the stateless WASM guest config
  does not accept `paths`.

### pow

| Option | Type | Default | Description |
|---|---|---|---|
| `pow.enabled` | bool | `false` | Enable the proof-of-work challenge layer for this domain. Requires top-level `signing_key_file`. |
| `pow.mode` | string | `always` | `always`: challenge every unvouched request regardless of method or User-Agent. `suspicion`: disable that catch-all and let anomaly or explicit WAF/GeoIP/reputation challenge policies select requests (requires `waf.anomaly.enabled`). |
| `pow.base_difficulty` | float | `5` | Baseline for an issued challenge. Must be finite and in range 1..8, in quarter steps. A difficulty of `N` requires `4 * N` leading zero bits of the SHA-256: +1 is 16x the work, +0.25 is exactly one bit (2x). Off-grid values (like `4.3`) are rejected at load. |
| `pow.max_difficulty` | float | `6` | Ceiling for escalation above `base_difficulty`. `base_difficulty` is the normal floor, not a guarantee: a challenge climbs toward `max_difficulty` when the request is scored more suspicious, by the anomaly model (score `challenge_at`→`1.0` maps to `base`→`max`), by a WAF-signature or reputation-feed hit (+1 step, capped here), or by challenge farming (escalation is scored per host+IP, so a clean visitor behind the same CGNAT/proxy IP as a farmer can inherit above-base work). This is the *normal-operation* ceiling: [attack mode](/guide/attack-mode) shifts the whole `[base, max]` window up fleet-wide, so with `attack_mode` enabled the absolute ceiling is `attack_mode.effects.difficulty_cap` (default `7`), which can exceed this value. Must be finite and in range `base_difficulty`..8, in quarter steps. |
| `pow.token_ttl` | Duration | `4h` | Lifetime of the signed JWT cookie a solved challenge earns: how long a clean visitor rides one solve before being challenged again. Two levers shape the work economy: `base_difficulty` sets the cost of one solve, `token_ttl` sets how often anyone still visiting, a legitimate client or a persistent scraper alike, pays that cost again, and it also bounds how long a captured cookie stays replayable. The token is fingerprint-bound to IP + User-Agent, so replay needs the same source IP and UA; that binding is weakest behind shared IPs (CGNAT, mobile carriers, corporate proxies), where any client on the same IP that copies the cookie and UA can ride it. A shorter TTL re-challenges legitimate visitors more often, but raises a continuing scraper's amortized cost and shrinks that replay window: the classic UX-versus-abuse-resistance trade-off. `4h` is a sensible middle for most sites; consider `1h`-`2h` when shared-IP replay worries you. Must be between `1s` and seven days when PoW is enabled; if you rotate signing keys, keep it well under seven days so a rotation does not invalidate live tokens. |
| `pow.challenge_ttl` | Duration | `30m` | How long an issued challenge stays solvable. Must be greater than zero when PoW is enabled and no more than seven days. |
| `pow.issuance_rate_limit` | rate | `60/min` | Per-IP cap on challenge issuance, so the interstitial cannot be used to flood the store. Inherited by domains and path overlays. |
| `pow.noscript_fallback` | bool | `false` | Serve a meta-refresh fallback for clients without JavaScript. It substitutes a minimum five-second wait for hash work; the wait costs an attacker no computation and parallelizes cheaply, so it is strictly weaker than PoW. Leave it `false` in production unless no-JS accessibility is a deliberate trade-off you accept. |

See [base_difficulty and max_difficulty](/guide/configuration#base-difficulty-and-max-difficulty)
for which value fires when.

### geo

GeoIP scoping by origin country and ASN. Needs the [top-level `geoip`
databases](#geoip); a selector that references a database you did not
configure is refused at load, so a country block can never be silently
inert. Deny verdicts fire right after the static denylist (a PoW token never
rides past them; an rDNS-verified crawler does); challenge verdicts fire
after the token check, so a listed client solves once and then browses on
its token. See [the guide](/guide/bots-ip-intel#geoip-scoping).

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable geo scoping for this domain. Enabled with no deny/challenge selectors and `default_action: allow` is a config error (it would never do anything). |
| `deny` | selector | | Origins never served. |
| `challenge` | selector | | Origins that must solve PoW first (inert on a PoW-less domain). |
| `allow` | selector | | Origins exempt from `default_action`. |
| `default_action` | `allow` \| `challenge` \| `deny` | `allow` | Applied to origins matching no selector, including IPs the databases have no record for (private ranges). Precedence: deny, challenge, allow, then this. |

Each selector takes `countries` (ISO 3166-1 alpha-2, any case) and/or `asns`
(plain numbers). Listing the same country or ASN in two selectors is a
config error.

```yaml
geo:
  enabled: true
  deny: { countries: [ KP ] }
  challenge: { countries: [ CN, RU ], asns: [ 4134 ] }
```

### reputation (per domain)

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enforce the [globally configured feeds](#reputation) on this domain. Enabling it requires at least one top-level `reputation.feeds` entry. Typically set once in `defaults`. |

### waf.ip_behaviour

Behavioural IP blocking with exponential backoff.

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable event counting and automatic/persistent blocks from signatures, honeypots, failed PoW, tamper, and bot spoofing. Existing and manually placed blocks are still enforced when disabled. |
| `block_ttl` | Duration | `15m` | First-offense block duration; doubles per repeat offense. Maximum one year (`8760h`). |
| `max_block_ttl` | Duration | `4h` | Backoff cap. Must be >= `block_ttl`; maximum one year (`8760h`). |
| `thresholds` | map of Rate | `signature: 10/min`, `pow_fail: 10/min`, `tamper: 10/min`, `bot_spoof: 5/min` | Bad events per window before the IP is blocked, keyed by event type. |

### waf.keywords

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable keyword/regex threat signatures. Requires `rules_file`. Rules match the targets they name: `path`, `query` (the default pair), `ua`, or `header:<name>` (e.g. `header:referer` or `header:host`; Host uses Angie's effective `X-Guardian-Host`). All inputs are lowercased; paths, queries, and targeted header values are also percent-decoded, while User-Agent values are not decoded. Every physical value of a duplicate header is inspected, and the first matching rule in file order wins. `methods: [ TRACE, TRACK ]` restricts a rule to those HTTP methods. In the sidecar, a valid bound PoW token satisfies an `action: challenge` match; without PoW that action denies. `deny` always terminates, while `block` persists only when `waf.ip_behaviour.enabled`. The stateless WASM guest has no challenge or block state, so all three matching actions return a deny. Empty or whitespace-only keywords and regexes are rejected. |
| `rules_file` | string | | Rules file (start from `deploy/rules-common.yaml`, which documents every field). Must contain exactly one YAML document, be no larger than 8 MiB, and exist when enabled (fail-fast); hot-reloaded on change. An oversized or invalid update keeps the last-good rules active, as does an update that removes or renames a rule id still listed in some scope's `disabled_rule_ids`. |
| `disabled_rule_ids` | list of string | `[]` | Exact, case-sensitive rule `id`s to remove from evaluation against this scope's effective `rules_file`, without copying the file. The remaining rules keep file order, so the next matching rule still decides; a disabled rule produces no decision, log line or metric. Overlays replace the list wholesale: omitted inherits the parent's resolved list, an explicit `[]` clears it, a non-empty list replaces it (re-list inherited ids to keep them). Effective filtered rule sets are precompiled per scope at startup/reload; there is no per-request cost. Validation is strict everywhere configuration enters the runtime (`-t`, startup, config reload, watched-file reload): empty/whitespace/duplicate entries are rejected, a non-empty list requires an effective `rules_file` even while `enabled: false`, and every id must exist in that scope's effective file, with errors naming the scope, file and unknown id. To delete a disabled rule from the file, first drop its id here and reload, then edit the file. |

### waf.anomaly

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable statistical anomaly scoring. Requires a non-empty `model` trained from your own logs; see [Train the Anomaly Model](/guide/anomaly). |
| `model` | string | | Path to the model artifact from `guardian-train`. Required when enabled, limited to 64 MiB, and hot-swapped when the file changes. An oversized or invalid update keeps the last-good model active. |
| `challenge_at` | float | | Score at or above this triggers a PoW challenge when PoW is enabled, with difficulty scaled by the score; otherwise it falls through until `deny_at`. Both thresholds must be finite and satisfy `0 < challenge_at < deny_at <= 1`. |
| `deny_at` | float | | Score at or above this denies outright. |

### waf.honeypot

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable honeypot trap paths: one hit denies immediately and, when `waf.ip_behaviour.enabled`, places a persistent IP block. Has no effect without `paths`; guardiand logs a warning at startup if enabled with none. |
| `paths` | list | `[]` | URL-decoded exact paths or prefixes no legitimate client visits, e.g. `["/admin-old/"]`. Percent-encoded equivalents match the same trap. Required for the honeypot to do anything. Entries must be absolute and specific: empty/whitespace or relative entries (which could never match) and a bare `/` (which would trap every visitor) are rejected at load. Invent paths specific to your site rather than copying generic ones, and `Disallow` them in robots.txt. |

### waf.signed_id

Reserves the signed-ID feature: opaque HMAC-bound identifiers whose forgery,
replay or cross-domain reuse is detectable. No flow mints signed IDs yet, so
this toggle is currently dormant.

This does **not** gate proof-of-work tamper detection. Forged or replayed PoW
challenge IDs always emit a tamper event, whether or not this is enabled; the
`waf.ip_behaviour` scoreboard counts it only when behavioural scoring is enabled.

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Reserve the signed-ID feature (dormant; no minting flow yet). |

### allowlist / denylist

Static lists, evaluated before everything else. An allowlist match is
terminal: denylist, behaviour blocks, GeoIP, honeypots, signatures and PoW
are all skipped for it, so reserve it for endpoints that must keep working
even for otherwise-blocked clients (ACME renewal, say) and keep every entry
as narrow as possible. To merely skip the PoW interstitial for public assets
like `/robots.txt`, prefer a
[per-path overlay](#per-path-overrides-domains-host-paths) with
`pow: { enabled: false }`: the rest of the pipeline still runs there. `ips`
match the client address Angie reports (`X-Guardian-IP`), not the
Angie-to-Guardian connection, so normal wiring needs no loopback entries;
allowlisting `127.0.0.1`/`::1` would turn a broken real-IP setup into a
total bypass. The allowlist supports:

| Option | Type | Matching |
|---|---|---|
| `ips` | list | CIDRs or bare IPv4/IPv6 addresses. |
| `uas` | list | Case-insensitive substring match on User-Agent. Empty or whitespace-only entries are rejected. |
| `paths` | list | Exact match, or prefix match when the entry ends with `/`. |

The denylist evaluates only `ips` (CIDRs or bare IPv4/IPv6 addresses).
Although `uas` and `paths` are accepted by the shared list schema, they are
not deny conditions; do not configure them under `denylist`.

`uas` is a plain substring match on a client-controlled, freely forgeable
header. Reserve it for UAs you control (an internal uptime monitor, say).
**Never** put search-crawler names here (`uas: [ Googlebot ]`): any scraper
can claim that UA and skip the entire pipeline. Use `verified_bots` below
for crawlers instead; loading a config where an `allowlist.uas` entry
overlaps a configured bot fails fast for exactly this reason.

```yaml
allowlist:
  ips: []
  uas: []
  paths:
    - /.well-known/acme-challenge/   # ACME http-01 only, NOT all of /.well-known/
denylist:
  ips: []
```

### verified_bots

Allowlists well-known crawlers by **verified identity** instead of by their
forgeable User-Agent string. A client claiming a listed bot's UA is admitted
only after its IP reverse-DNS (PTR) resolves under the bot's published
domains **and** that hostname forward-resolves back to the same IP, the
verification Google/Bing/Apple themselves document. Results are cached in
the shared store, so DNS runs once per crawler IP, not per request.

A confirmed identity is a **terminal allow**: it skips GeoIP, reputation,
behaviour blocks, signatures and PoW for that request. Verified identity is
not authorization for every vhost, so configure `verified_bots` per domain
(the public HTML sites you want crawled) rather than in `defaults`, where an
API host, a static-assets host and every unknown host would inherit it.

| Option | Type | Default | Description |
|---|---|---|---|
| `bots` | list | `[]` | Bots to verify. Each entry needs `name`, plus non-empty `uas` and `domains` unless `name` is a built-in preset. Empty or whitespace-only UA needles are rejected. |
| `dns_timeout` | duration | `1s` | DNS budget for one first-sight verification. |
| `cache_ttl` | duration | `12h` | How long a confirmed identity is cached; maximum one year (`8760h`). |
| `negative_ttl` | duration | `1h` | How long a proven impostor is cached; maximum one year (`8760h`). |
| `spoof_action` | `deny` \| `continue` | `deny` | What happens to a client that claims a listed UA but definitively fails verification (no PTR, or rDNS owned by someone else). `deny` rejects and scores a `bot_spoof` behaviour event (see `waf.ip_behaviour.thresholds`); `continue` just withholds the allowlist skip and lets the rest of the pipeline handle the request. |

Built-in presets (need only `name`): `googlebot`, `google-special`,
`bingbot`, `applebot`, `yandexbot`, `baiduspider`. DuckDuckBot publishes a
static IP list instead of rDNS domains; allowlist it with `allowlist.ips`.

Google's crawler categories are kept apart on purpose. `googlebot` verifies
under `googlebot.com` only (the published domain for common crawlers, i.e.
everything with a Googlebot UA). `google-special` covers the special-case
crawlers (AdsBot, Mediapartners-Google, APIs-Google) under `google.com`;
enable it if you run Google Ads. User-triggered fetchers (Feedfetcher,
Read-Aloud, Apps Script) are deliberately not a preset, because third
parties can aim them at any site on demand; add a custom bot entry if you
really want them allowlisted.

```yaml
domains:
  example.com:                    # the public HTML site you want crawled
    verified_bots:
      bots:
        - name: googlebot
        - name: bingbot
        - name: mybot             # custom bots: spell out both fields
          uas: [ "MyBot/1.0" ]
          domains: [ "crawler.example.net" ]
      spoof_action: deny
```

A transient DNS failure proves nothing and falls through unverified: it
never blocks a real crawler or admits a scraper.
