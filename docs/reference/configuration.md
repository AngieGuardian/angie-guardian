# Configuration Options

Every field of `guardian.yaml`, with types and defaults. Unknown fields and
trailing YAML documents are rejected, and semantic errors fail at startup or
under `guardiand -t`. Preflight also opens every startup-required local rules,
model, GeoIP, and reputation-feed artifact.

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
| `signing_key_file` | string | | Persistent Ed25519 signing key for PoW JWTs. Required when any effective domain enables PoW. Generated on first run if missing; never regenerated on restart. |
| `previous_key_dir` | string | | Where retired signing keys (from `POST /admin/rotate-key`) are archived; required for rotation. Replicas must share it with `signing_key_file`. Retired keys accept only pre-rotation tokens with lifetimes up to seven days; older archives may remain on disk but are omitted from the active verification set. |
| `admin` | object | | See [admin](#admin). |
| `store` | object | | See [store](#store). |
| `geoip` | object | | GeoIP databases for the per-domain `geo` scoping. See [geoip](#geoip). |
| `reputation` | object | | Global IP reputation feeds; domains opt in via `reputation.enabled`. See [reputation](#reputation). |
| `defaults` | object | | The base [domain config](#per-domain-options-defaults-and-domains) every domain inherits from. |
| `domains` | map | | Per-domain overrides, merged field-by-field over `defaults`. Host keys and anomaly-model lookups share one normalization for case, ports, trailing dots, and bracketed IPv6 (`A.test.:443` = `a.test`); two keys that collapse to the same host are rejected. |

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

## geoip

MaxMind-format (`.mmdb`) databases: MaxMind GeoLite2/GeoIP2, DB-IP, or any
other publisher of the format. The files are hot-reloaded when replaced on
disk (geoipupdate does this atomically), so scheduled updates need no
restart. Either may be omitted; a `geo` rule that needs the missing database
is refused at config load.

| Option | Type | Default | Description |
|---|---|---|---|
| `geoip.country_db` | string | | Country database, for `countries:` selectors. |
| `geoip.asn_db` | string | | ASN database, for `asns:` selectors. |

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
| `url` | string | | Fetched in the background every `refresh` interval. A slow or down remote never blocks startup; a failed refresh keeps the last good list and retries within 5 minutes. Exactly one of `url`/`file`. |
| `file` | string | | Local list. Must exist at startup (fail-fast, like the WAF rules files); hot-reloaded on change. |
| `refresh` | Duration | `12h` | URL feeds only. Minimum `1m`. |
| `action` | `deny` \| `challenge` | `deny` | `deny` rejects matching IPs outright; `challenge` makes them solve PoW first, one full step (+4 bits = 16x) above base, like a WAF signature hit. |

## Per-domain options (`defaults` and `domains.<host>`)

Each domain entry has these sections: `waf`, `pow`, `geo`, `reputation`,
`allowlist`, `denylist`, `verified_bots`.

### pow

| Option | Type | Default | Description |
|---|---|---|---|
| `pow.enabled` | bool | `false` | Enable the proof-of-work challenge layer for this domain. Requires top-level `signing_key_file`. |
| `pow.mode` | string | `always` | `always`: challenge every unvouched request regardless of method or User-Agent. `suspicion`: only challenge clients the anomaly scorer flags (requires `waf.anomaly.enabled`). |
| `pow.base_difficulty` | float | `5` | The floor every clean client pays. Must be finite and in range 1..8, in quarter steps. A difficulty of `N` requires `4 * N` leading zero bits of the SHA-256: +1 is 16x the work, +0.25 is exactly one bit (2x). Off-grid values (like `4.3`) are rejected at load. |
| `pow.max_difficulty` | float | `6` | The ceiling, reached only via anomaly-scaled difficulty. Must be finite and in range `base_difficulty`..8, in quarter steps. |
| `pow.token_ttl` | Duration | `4h` | Lifetime of the signed JWT cookie a solved challenge earns. Must be between `1s` and seven days when PoW is enabled. |
| `pow.challenge_ttl` | Duration | `30m` | How long an issued challenge stays solvable. |
| `pow.noscript_fallback` | bool | `false` | Serve a meta-refresh fallback for clients without JavaScript. |

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
| `enabled` | bool | `false` | Enable behavioural blocking. |
| `block_ttl` | Duration | `15m` | First-offense block duration; doubles per repeat offense. Maximum one year (`8760h`). |
| `max_block_ttl` | Duration | `4h` | Backoff cap. Must be >= `block_ttl`; maximum one year (`8760h`). |
| `thresholds` | map of Rate | `signature: 10/min`, `pow_fail: 10/min`, `tamper: 10/min`, `bot_spoof: 5/min` | Bad events per window before the IP is blocked, keyed by event type. |

### waf.keywords

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable keyword/regex threat signatures. Requires `rules_file`. Rules match the targets they name: `path`, `query` (the default pair), `ua`, or `header:<name>` (e.g. `header:referer`), all URL-decoded and lowercased; every physical value of a duplicate header is inspected. `methods: [ TRACE, TRACK ]` restricts a rule to those HTTP methods. A valid bound PoW token satisfies an `action: challenge` match, while `deny` and `block` remain terminal. Empty or whitespace-only keywords and regexes are rejected. |
| `rules_file` | string | | Rules file (start from `deploy/rules-common.yaml`, which documents every field). Must exist when enabled (fail-fast); hot-reloaded on change. |

### waf.anomaly

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable statistical anomaly scoring. Requires a non-empty `model` trained from your own logs; see [Train the Anomaly Model](/guide/anomaly). |
| `model` | string | | Path to the model artifact from `guardian-train`. Required when enabled; hot-swapped when the file changes. |
| `challenge_at` | float | | Score at or above this triggers a PoW challenge, with difficulty scaled by the score. Both thresholds must be finite and satisfy `0 < challenge_at < deny_at <= 1`. |
| `deny_at` | float | | Score at or above this denies outright. |

### waf.honeypot

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable honeypot trap paths: one hit means an instant block. |
| `paths` | list | `[]` | Paths no legitimate client visits, e.g. `["/admin-old/"]`. Also `Disallow` them in robots.txt. |

### waf.signed_id

Reserves the signed-ID feature: opaque HMAC-bound identifiers whose forgery,
replay or cross-domain reuse is detectable. No flow mints signed IDs yet, so
this toggle is currently dormant.

This does **not** gate proof-of-work tamper scoring. Forged or replayed PoW
challenge IDs are always scored via the `waf.ip_behaviour` `tamper` threshold,
whether or not this is enabled.

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Reserve the signed-ID feature (dormant; no minting flow yet). |

### allowlist / denylist

Static lists, evaluated before everything else. Matching rules:

| Option | Type | Matching |
|---|---|---|
| `ips` | list | CIDRs or bare IPv4/IPv6 addresses. |
| `uas` | list | Case-insensitive substring match on User-Agent. Empty or whitespace-only entries are rejected. |
| `paths` | list | Exact match, or prefix match when the entry ends with `/`. |

`uas` is a plain substring match on a client-controlled, freely forgeable
header. Reserve it for UAs you control (an internal uptime monitor, say).
**Never** put search-crawler names here (`uas: [ Googlebot ]`): any scraper
can claim that UA and skip the entire pipeline. Use `verified_bots` below
for crawlers instead; loading a config where an `allowlist.uas` entry
overlaps a configured bot fails fast for exactly this reason.

```yaml
allowlist:
  ips: [ "127.0.0.1", "::1" ]
  uas: []
  paths:
    - /robots.txt
    - /favicon.ico
    - /.well-known/         # trailing slash = prefix match (ACME http-01 etc.)
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
verified_bots:
  bots:
    - name: googlebot
    - name: bingbot
    - name: mybot                 # custom bots: spell out both fields
      uas: [ "MyBot/1.0" ]
      domains: [ "crawler.example.net" ]
  spoof_action: deny
```

A transient DNS failure proves nothing and falls through unverified: it
never blocks a real crawler or admits a scraper.
