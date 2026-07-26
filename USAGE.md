# Angie Guardian: Usage

A step-by-step guide to configuring, deploying and operating Angie Guardian.
For an overview of what Guardian is and how it works, see the
[README](README.md).

For a first host installation, start with the release-first
[Getting Started guide](https://angieguardian.org/guide/getting-started):
it selects a prebuilt archive and installs the config, rules, Angie snippets,
and systemd unit at the exact paths used below. This file is the deeper
configuration and operations reference after that initial flow.

## Contents

1. [Configure Guardian](#1-configure-guardian) (including
   [difficulty tuning](#base_difficulty-and-max_difficulty))
2. [Wire it into Angie](#2-wire-it-into-angie)
3. [Run it (systemd)](#3-run-it-systemd)
4. [Operate it via the admin API](#4-operate-it-via-the-admin-api) (including
   [the reporting dashboard](#the-reporting-dashboard))
5. [Train the anomaly model](#5-train-the-anomaly-model)
6. [Load-test your deployment](#6-load-test-your-deployment)
7. [Choosing a store backend](#choosing-a-store-backend)
8. [Multi-instance (Redis/Valkey)](#multi-instance-redisvalkey)
9. [WASM module (optional)](#wasm-module-optional)

## 1. Configure Guardian

Copy `guardian.example.yaml` and adjust it. The minimum viable config is tiny;
everything else inherits from `defaults`:

```yaml
listen: 127.0.0.1:8071            # Angie's auth_request target
signing_key_file: /var/lib/guardian/ed25519.key   # generated state, not /etc
store:
  backend: pebble
  path: /var/lib/guardian/pebble

defaults:
  pow: { enabled: true, base_difficulty: 5 }
  waf:
    ip_behaviour: { enabled: true }

domains:
  example.com: {}                 # inherits all defaults
```

Per-domain entries are merged field-by-field over `defaults`, so a domain only
names what it changes. Unknown hosts fall back to `defaults`.

```yaml
domains:
  # HTML site behind PHP/Node: all Guardian layers, PoW + the URI/header
  # WAF (request bodies never reach Guardian; payload validation stays with
  # the backend). Difficulty takes quarter steps: each +0.25 doubles the
  # work, so 5.5 is 4x the default 5 (see the difficulty table below).
  # token_ttl inherits the 4h default.
  example.com:
    pow: { enabled: true, base_difficulty: 5.5 }
    # Honeypot: no generic trap path is safe to copy (one hit persistently
    # blocks the source IP when ip_behaviour is on). Invent a path specific
    # to YOUR site that nothing links to, then enable:
    # waf: { honeypot: { enabled: true, paths: [ "/your-own-trap/" ] } }

  # API host: WAF only, no interstitial a machine client can't solve. With
  # PoW off, challenge-action rules degrade to deny (nothing to challenge
  # with); give APIs their own rules file if that is too blunt.
  api.example.com:
    pow: { enabled: false }

  # Static assets: no PoW, no behavioural scoring. Signature rules still
  # apply from defaults; override waf.keywords too for a minimal policy.
  static.example.com:
    pow: { enabled: false }
    waf: { ip_behaviour: { enabled: false } }

  # Disable the catch-all challenge; this fragment defines only an anomaly
  # challenge policy. Requires a trained model (see below).
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 observe_only: true, challenge_at: 0.5, deny_at: 0.85 }
```

Set `observe_only: false` after tuning the thresholds from
`guardian_anomaly_score`.

Validate a config without starting the daemon with `-t` (like `angie -t`). It
loads and validates the file (YAML syntax, trailing documents, unknown fields,
and semantic checks) plus every startup-required local rules, anomaly-model,
GeoIP, and file-feed artifact. Remote URL feeds are not fetched. It then exits:
`0` and `ok` when valid, `1` and the reason when not.

```sh
./guardiand -config guardian.yaml -t
# config guardian.yaml: ok
# ...or, on a bad config:
# config guardian.yaml: FAILED
# config guardian.yaml: store.backend must be memory, buntdb, pebble or redis, got "etcd"
```

### Signature rules

`waf.keywords.rules_file` points at a YAML rules file (start from
`deploy/rules-common.yaml`, which documents every field). Rules are keyword
and RE2-regex signatures with an `action` of `deny`, `challenge` or `block`,
hot-reloaded on change. Empty keyword/regex entries and trailing YAML documents
are rejected. The first matching rule in file order wins. With PoW enabled, a
valid bound token satisfies `challenge`; without PoW, `challenge` denies.
`deny` remains terminal, while `block` persists an IP block only when
`waf.ip_behaviour.enabled`. A rule matches against the targets it names:

- `path`, `query` (the default pair) and `ua`, all lowercased; paths and queries
  are URL-decoded, while the User-Agent is not percent-decoded;
- `header:<name>` for any request header, e.g. `header:referer` to catch
  Log4Shell-style payloads hiding in URL-shaped headers (values are
  percent-decoded too, so encoding is no escape hatch); every physical value
  of a duplicate header is inspected;
- `methods: [ TRACE, TRACK ]` restricts a rule to those HTTP methods, and a
  rule with only `methods` fires on the method alone.

The file must be installed and named explicitly (the systemd recipe in step 3
does both): nothing under `/etc/guardian/rules.d/` is auto-discovered, and a
configured `rules_file` that is missing fails `-t` and startup rather than
silently matching nothing. `defaults.waf.keywords` is inherited by every
domain and path overlay unless overridden there; a scope can point at a
different `rules_file`, set `enabled: false`, or disable selected rules from
its effective file by exact, case-sensitive `id` with `disabled_rule_ids`
(the `id` is also the log/reason label, `waf:<id>`). A disabled rule falls
through to the next matching rule in file order. The list overlays wholesale
(omitted inherits, `[]` clears, non-empty replaces); unknown, empty or
duplicate ids fail `-t`, startup and reload naming the scope, file and id,
and a watched rules-file update that removes a still-excluded id is rejected
with the last-good rules kept active. To delete a disabled rule on purpose,
drop its id from `guardian.yaml` and reload first, then edit the rules file.

**Request bodies are never inspected.** Angie's `auth_request` subrequest
carries only the request line and headers, never the body, so no rule can see
POST payloads. That is a deliberate design boundary, not a missing feature:
inspecting bodies would mean buffering every upload through the sidecar.
Body-borne attacks are for your backend's input validation or a full inline
WAF; Guardian's job is keeping bots and scanners from reaching it at all.
In `pow.mode: always`, an unvouched POST/PUT/DELETE is diverted before its body
reaches the backend. Angie fetches the interstitial internally with GET;
Guardian never stores or replays the body, so the browser/client must retry or
confirm resubmission after solving. Machine APIs that cannot do that should
disable PoW or use `mode: suspicion` with an appropriate policy.

Honeypot traps use the same URL-decoded path identity: encoded equivalents of
an exact or prefix trap still deny immediately and, when behavioural scoring
is enabled, persist an IP block.

### base_difficulty and max_difficulty

`base_difficulty` is the baseline for an issued challenge; `max_difficulty` is
the normal-operation ceiling. Anomaly score, WAF/reputation policy, and
challenge-farming escalation decide where in `[base, max]` a request lands.
One exception: attack mode shifts the whole `[base, max]` window up
fleet-wide, so with `attack_mode` enabled the absolute ceiling is
`attack_mode.effects.difficulty_cap` (default `7`), not `max_difficulty`.

A difficulty of `N` requires `4 * N` leading zero **bits** in the SHA-256, so a
full step (+1) is 16x the work, and the scale takes **quarter steps**: each
+0.25 is exactly one bit, doubling the expected work. `5.25` is twice as hard
as `5`, `5.5` four times, giving fine-grained control between the huge full
steps. Values off the quarter grid (like `4.3`) are rejected at load.

Which value fires:

- **`mode: always` (the default):** every unvouched request, regardless of HTTP
  method or User-Agent, pays exactly `base_difficulty`, once, then rides a
  `token_ttl` cookie. The token lifetime must be at least one second and at
  most seven days.
- **A WAF signature hit:** one full step over base (`base + 1`, i.e. +4 bits =
  16x, capped at `max`). A valid bound token satisfies challenge-only rules;
  deny/block rules still apply.
- **The anomaly scorer:** scales the difficulty across the `[base, max]` range
  with the score, so a more bot-like client pays more. Requires `waf.anomaly`
  enabled with a trained model.
- **Challenge farming:** a host+IP pair that keeps requesting challenges
  without ever solving one gets escalated on top of whichever value above
  applied. The first 4 unsolved challenges are free (multiple tabs, reloads),
  then every 2 further abandoned challenges add one bit (2x work), capped at
  `max`. Any successful solve resets only that domain's counter. The counter
  lives for `challenge_ttl`, and escalated issuances show up in Prometheus as
  `guardian_challenges_total{outcome="escalated"}`.

  Once the escalation is pinned at `max` and the client still keeps farming,
  each further issuance is additionally counted as
  `guardian_challenges_total{outcome="farm_detected"}` and reported as a
  `challenge_farm` behaviour event: past the `challenge_farm` threshold
  (default `80/h`, tunable under `waf.ip_behaviour.thresholds` in `defaults`
  or per domain, `off` disables) the farmer is temporarily blocked with the
  usual exponential backoff. The default is deliberately generous: a block
  takes 12+ abandoned challenges within `challenge_ttl` to pin the ceiling,
  then 80 more within an hour, all with zero successful solves, and one
  solve resets the counter. Ordinary visitors (even many behind one NAT, or
  with JavaScript off) do not get near it; tighten to e.g. `30/h` when
  farmers are a problem.

  Requests that cannot run the interstitial are never issued one, so they are
  never counted here at all. The challenge page needs a same-origin document
  context: it renders markup, runs an inline script and spawns a Web Worker to
  search for the nonce. A request whose `Sec-Fetch-Dest` names a subresource
  (`image`, `style`, `script`, `font`, `empty` for `fetch()`/XHR, and the rest)
  gets markup it cannot parse, so it is answered with a plain `403` instead,
  counted as `guardian_challenges_total{outcome="subresource_refused"}`. Without
  this an ordinary browser polling `/favicon.ico` escalates itself into a
  `challenge_farm` block within the hour, having abandoned nothing.

  A missing or unrecognized `Sec-Fetch-Dest` keeps the ordinary challenge path,
  so old clients and non-browsers are unaffected, and stripping the header is
  not a way around escalation. Claiming a subresource destination is not one
  either: that client is refused the challenge, so it has nothing to farm.

  **Framed navigations that may not render are never blocked for it.** A framed
  destination (`iframe`, `frame`, `embed`, `object`) whose `Sec-Fetch-Site` is
  `cross-site` or `same-site`, and `fencedframe` in every case, may be refused
  rendering by the interstitial's own `frame-ancestors 'self'` policy; the
  `SameSite=Lax` token cookie is not sent on a cross-site frame load either, so
  even a visitor already holding a token arrives looking unvouched. Blocking on
  those issuances lets any third-party page frame a protected URL in a loop and
  drive an arbitrary visitor's IP (and, behind a NAT, everyone sharing it) into
  a `challenge_farm` block on a site the attacker does not control. They are
  counted as `guardian_challenges_total{outcome="frame_unscored"}`.

  Three things are true of these at once, and all three are needed:

  - They **are issued** a challenge, unlike subresources. `Sec-Fetch-Site` is
    not proof the frame is foreign: it is computed over the request's whole
    redirect chain against the initiator's origin and says nothing about the
    frame ancestor, so a same-origin iframe reached through a cross-site
    redirect (an SSO callback) arrives tagged `cross-site` while
    `frame-ancestors 'self'` renders it perfectly well. Refusing would break
    those logins. This is also why the metric alone does not prove a hostile
    third party: your own embedded login callback appears here too.
  - They **are escalated**, on a separate counter, so difficulty still ramps.
    Any HTTP client can send these headers, and without the ramp the pair would
    be a cheap-challenge exemption. A solve clears both counters.
  - They are **never reported** as `challenge_farm`, which is the part that
    cannot be aimed safely when the signal is ambiguous.

  A same-origin frame is scored exactly as before, and a top-level navigation is
  never treated as framed, so an inbound cross-site link is unaffected.

  **HTTPS only.** Browsers send `Sec-Fetch-*` only to potentially-trustworthy
  origins (HTTPS and localhost). A site served over plain HTTP receives neither
  header, so every request reads as unknown and none of the protection above
  applies there.

#### Measured solve times and recommended values

The interstitial solves in parallel web workers (up to 8) with a pure-JS
SHA-256. Measured throughput in Chrome on a fast desktop is ~1.1 million
hashes/s per worker, ~9 MH/s with 8 workers; scale down for weaker devices.
For comparison, a native (Go) solver does ~7.6 MH/s **per core**, so a bot
pays the same order of work a real browser does.

Expected (mean) solve times by device class:

| difficulty | bits | expected hashes | desktop (9 MH/s) | laptop (3 MH/s) | phone (1 MH/s) |
|-----------:|-----:|----------------:|-----------------:|----------------:|---------------:|
| 4.0        | 16   | 66 k            | 0.01 s           | 0.02 s          | 0.07 s         |
| 4.5        | 18   | 262 k           | 0.03 s           | 0.09 s          | 0.26 s         |
| 5.0        | 20   | 1.0 M           | 0.12 s           | 0.35 s          | 1.0 s          |
| 5.25       | 21   | 2.1 M           | 0.23 s           | 0.7 s           | 2.1 s          |
| 5.5        | 22   | 4.2 M           | 0.47 s           | 1.4 s           | 4.2 s          |
| 5.75       | 23   | 8.4 M           | 0.9 s            | 2.8 s           | 8.4 s          |
| 6.0        | 24   | 16.8 M          | 1.9 s            | 5.6 s           | 17 s           |
| 6.5        | 26   | 67 M            | 7.5 s            | 22 s            | 67 s           |

Solve time is exponentially distributed around the mean: the median visitor
waits ~0.7x the mean, but ~5% wait 3x and ~1% wait 4.6x. Budget for the tail,
not the mean.

Recommendations:

- **`base_difficulty: 5`** (the default): imperceptible on desktop, about a
  second on a mid-range phone. A sensible tax for `mode: always`, paid once
  per `token_ttl`.
- **`5.25`–`5.5`** when you are actively being scraped and can accept a few
  seconds on phones.
- **`4`–`4.5`** only when the interstitial itself (not the work) is the
  deterrent you want; the computation is near instant everywhere.
- **`max_difficulty: 6`** (the default) for anomaly escalation. `6.5` and up
  is effectively a soft deny: a minute of hashing on a phone. Values above 7
  mostly punish real visitors on slow devices.
- Watch `guardian_challenge_solve_seconds` in Prometheus (or the average on
  the dashboard) after changing values: it is the real-world solve time of
  *your* visitors' devices.

Note that PoW only taxes clients that solve the puzzle. A client that farms
challenges without solving them is throttled (60 issuances per IP per minute),
escalated (see challenge farming above), and eventually blocked outright via
the `challenge_farm` threshold, but a raw flood that never even follows the
challenge redirect is **not** PoW's problem: see
[Rate limiting](#rate-limiting-volumetric-ddos) below.

### Search crawlers: verified_bots, not allowlist.uas

Search crawlers won't solve a PoW puzzle, so they need an allowlist entry or
your site drops out of the index. **Do not** allowlist them by User-Agent
(`allowlist.uas: [ Googlebot ]`): the UA string is freely forgeable, and such
an entry lets any scraper skip the entire pipeline by claiming to be
Googlebot. Guardian refuses to load a config where an `allowlist.uas` entry
overlaps a configured bot for exactly this reason.

Instead, `verified_bots` admits a crawler only after proving its identity the
way the search engines themselves document:

1. reverse-DNS (PTR) lookup on the client IP,
2. the returned hostname must be under one of the bot's published domains
   (e.g. `crawl-66-249-66-1.googlebot.com`),
3. forward-confirm: that hostname must resolve back to the same IP, so an
   attacker who controls the PTR of their own IP space can't fake step 2.

```yaml
domains:
  example.com:                     # scope to the domains you want crawled: a
    verified_bots:                 # confirmed identity is a terminal allow,
      bots:                        # not authorization for every vhost
        - name: googlebot          # presets: googlebot, google-special,
        - name: bingbot            #   bingbot, applebot, yandexbot, baiduspider
        - name: mybot              # custom bots: spell out both fields
          uas: [ "MyBot/1.0" ]
          domains: [ "crawler.example.net" ]
      spoof_action: deny           # or: continue
```

Google splits its traffic into three rDNS categories, and the presets keep
them apart deliberately. The `googlebot` preset verifies under
`googlebot.com` only, Google's published domain for its **common crawlers**
(everything presenting a Googlebot UA). Google's **special-case crawlers**
(AdsBot, Mediapartners-Google, APIs-Google) verify under `google.com` via
the separate `google-special` preset; enable it if you run Google Ads, since
AdsBot can't solve PoW and blocking it hurts ad quality. Google's
**user-triggered fetchers** (Feedfetcher, Read-Aloud, Apps Script fetches)
are deliberately not a preset: third parties can point them at any site on
demand, so allowlisting them is an explicit operator decision (write a
custom bot entry if you need it).

A verified crawler is allowed with reason `verified_bot:<name>` and skips the
rest of the pipeline, including behavioural IP blocks (admin-placed or
automatic), so a scoring mishap can never knock a search crawler offline.
Static `allowlist`/`denylist` entries still run first: an explicit denylist
entry is the one thing that outranks a verified bot. A client that claims a listed UA but
**definitively** fails verification, meaning its IP has no PTR record or its
rDNS belongs to someone else, is an impostor: with `spoof_action: deny` (the
default) it is rejected and scored as a `bot_spoof` behaviour event (5/min
blocks the IP, tune under `waf.ip_behaviour.thresholds`); with `continue` it
is simply not allowlisted and the normal WAF/PoW pipeline applies. Transient
DNS failures prove nothing and just fall through unverified, so a flaky
resolver can neither block Googlebot nor admit a scraper.

Verification costs two DNS lookups (budget: `dns_timeout`, default 1s) the
first time an IP claims a bot UA. The result is cached in the shared store
(`cache_ttl` 12h for confirmed crawlers, `negative_ttl` 1h for impostors; both
accept at most one year / `8760h`), so
the hot path stays DNS-free; in-flight lookups are deduplicated per IP and
capped process-wide, degrading to "unverified" under a spoof flood rather
than amplifying it into a DNS storm. Watch it via the
`guardian_bot_verifications_total{bot,result}` metric.

DuckDuckBot publishes a static IP list instead of rDNS domains; allowlist it
with `allowlist.ips`.
### GeoIP scoping and IP reputation feeds

Guardian can scope traffic by origin (country and ASN) and consume external
IP reputation feeds. Both are optional and slot into the pipeline in two
places: **deny** verdicts fire right after the static denylist (a PoW token
never rides past them; only an rDNS-verified crawler does, so a feed false
positive can't deindex you), while **challenge** verdicts fire after the PoW token
check, so a listed client solves once and then browses normally until its
token expires.

**GeoIP databases.** Point `geoip:` at MaxMind-format `.mmdb` files. Guardian
hot-reloads them when they are replaced on disk, so a scheduled update cron
needs no restart.

```yaml
geoip:
  location_db: /var/lib/GeoIP/GeoLite2-Country.mmdb  # 8.8 MB, recommended
  # location_db: /var/lib/GeoIP/GeoLite2-City.mmdb   # 66 MB, adds city/region
  asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb           # optional, for asns:
```

Quickest way to get the files, no account needed: the
[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb/releases) mirror
republishes MaxMind's GeoLite2 builds every three days behind stable
`latest/download` URLs.

```sh
base=https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download
for db in GeoLite2-Country GeoLite2-ASN; do
  curl -fsSL -o "/tmp/$db.mmdb" "$base/$db.mmdb"
  sudo mv "/tmp/$db.mmdb" "/var/lib/GeoIP/$db.mmdb"   # atomic, no half-written file
done
```

That is a third-party mirror. For a first-party chain of custody use a free
[MaxMind licence key](https://www.maxmind.com/en/geolite2/signup) with
`geoipupdate`; [DB-IP lite](https://db-ip.com/db/lite.php) is another
account-free publisher of the same format.

`location_db` accepts a Country **or** a City database: City is a superset
(same country data plus city/region detail), so `countries:` selectors behave
identically either way. City adds city/region labels to the admin views but no
new selectors, and is 7.5x the size.

Then scope per domain (or in `defaults`):

```yaml
defaults:
  geo:
    enabled: true
    deny: { countries: [ KP ] }                    # never served
    challenge: { countries: [ CN, RU ], asns: [ 4134 ] }  # PoW first
```

Or invert it and serve only your home market, challenging the rest:

```yaml
domains:
  shop.example.nl:
    geo:
      enabled: true
      allow: { countries: [ NL, BE, DE ] }
      default_action: challenge     # allow | challenge | deny for the rest
```

Semantics worth knowing:

- Precedence is deny, then challenge, then allow, then `default_action`.
  Listing the same country/ASN in two selectors is a config error.
- An IP the database has no record for (private ranges, brand-new
  allocations) matches no selector and gets `default_action`. Keep internal
  ranges on the static `allowlist` before tightening `default_action`.
- Challenge policies need PoW enabled on the domain; on a PoW-less domain
  they are inert rather than degrading to a deny (a typo should not cut off
  a whole country). Denies apply everywhere, PoW or not.
- Config is refused when a selector needs a database you did not configure,
  so a country block can never be silently inert.

**Reputation feeds.** Feeds are plain-text IP/CIDR lists, one entry per line
with `#`/`;` comments: the format of the FireHOL netsets, blocklist.de
exports, and simple hand-maintained files. Define them once at the top
level; every domain that sets `reputation: { enabled: true }` (typically in
`defaults`) enforces them. Enabling reputation without at least one global feed
is rejected instead of silently disabling the policy.

```yaml
reputation:
  cache_dir: /var/lib/guardian/feeds    # survive restarts; recommended
  feeds:
    - name: firehol-level1              # reason becomes reputation:firehol-level1
      url: https://iplists.firehol.org/files/firehol_level1.netset
      refresh: 12h                      # default 12h
      action: deny                      # deny (default) | challenge
    - name: local-badnets
      file: /etc/guardian/badnets.txt   # hot-reloaded local list
```

URL feeds are fetched in the background: startup never blocks on a remote,
a failed refresh keeps the last good list (and retries within 5 minutes),
and `cache_dir` seeds the list at boot so a restart doesn't open a window.
A local `file:` feed must exist at startup (fail-fast, like the WAF rules
files) and is hot-reloaded on change. Matching is a binary search over
merged ranges, so six-figure feeds are fine on the hot path.

Watch feeds via `guardian_feed_entries` and `guardian_feed_refresh_total`
in `/metrics`, or `GET /admin/intel` (below). To ask "what would Guardian
make of this IP?", use `GET /admin/intel/<ip>`.

## 2. Wire it into Angie

Add the keepalive upstream once in the `http {}` context. Then include both
reusable files once in each protected vhost. The handler-neutral protection
directives are inherited by its content locations:

```nginx
# http {} context, REQUIRED for throughput (connection reuse to the sidecar):
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}

# each protected server {} block:
include /etc/angie/angie-guardian.conf;
include /etc/angie/angie-guardian-location.conf;

location / {
    proxy_pass http://my_application;     # or keep try_files/static/FastCGI
}
```

One daemon/upstream serves every vhost: `$host` selects its `domains:` policy,
and unknown hosts use `defaults`. `deploy/angie-guardian.conf` owns only the
internal auth/challenge/pass/denied routes; it no longer assumes the site is a
reverse proxy. `deploy/angie-guardian-location.conf` adds protection without
choosing a content handler. At server scope it also covers sibling locations
created by includes such as `snippets/general.conf`, so it need not be repeated
for robots.txt, favicon, manifests, or static-asset regexes. For a `try_files`
front controller, add `auth_request off` to the `internal` FastCGI target to
avoid a second auth subrequest; never do that if the PHP location is externally
reachable.

For a static-only `try_files $uri $uri/ =404` location, Guardian runs first,
then Angie serves the file/directory or returns the normal 404. Public sibling
locations inherit the same check automatically.

Fail-open is handled inside the auth subrequest: a Guardian timeout or 5xx is
converted to `204`, so Angie resumes the original static, FastCGI, or proxy
handler. Application-origin errors are untouched. Comment out the 5xx
`error_page` in `/__guardian/auth` to fail closed instead; the unused
`@guardian_fail_open` location can then also be commented out.

Two header relays in the snippets matter beyond routing:
`X-Guardian-Difficulty` carries an
escalated difficulty (WAF signature hit, anomaly score) from the auth decision
into the issued challenge, and `X-Guardian-Proto` (`$scheme`) tells Guardian
whether the token cookie may carry the `Secure` flag; without it a plain-http
site would loop on the challenge. If you wrote your own glue before these
lines existed, copy them over.

If Angie is behind a CDN, ingress, or load balancer, restore the real client
address before including Guardian (`set_real_ip_from` for only the proxy's
trusted networks plus the provider's `real_ip_header`, or PROXY protocol).
Otherwise `$remote_addr` is the proxy for every visitor and one attacker can
trigger a block or rate limit affecting all of them. Never trust forwarded-IP
headers from arbitrary internet sources.

To feed the anomaly trainer, switch protected vhosts to the JSON access log
from `deploy/angie-json-log.conf`:

```nginx
access_log /var/log/angie/example.com.access.json guardian_json;
```

### Rate limiting (volumetric DDoS)

PoW taxes bots that speak HTTP and solve the puzzle; it does **not** absorb a raw
flood. Every request still costs an `auth_request` subrequest; requests not
terminated by early static allow/deny policy also reach the shared-state lookup.
A client that follows the
challenge redirect also makes the sidecar issue and persist a challenge. Under
enough load the sidecar saturates and fail-open (the default) sends the flood
straight to your backend. Volumetric DDoS is Angie's job, in front of the
`auth_request`, so a flood is dropped before it reaches the sidecar at all. The
two layers are complementary: rate limits absorb volume, PoW taxes the bots that
get through. Tune the rates to your real traffic before enabling.

```nginx
# http {} context: one shared zone per limiter.
limit_req_zone  $binary_remote_addr zone=guard:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=gconn:10m;

# in each protected server {} (or the location / block). limit_req runs in an
# earlier phase than auth_request, so a rejected flood never reaches the sidecar.
limit_req  zone=guard burst=60 nodelay;   # smooth spikes, reject sustained floods
limit_conn gconn 20;                       # cap concurrent connections per client
limit_req_status  429;
limit_conn_status 429;
```

## 3. Run it (systemd)

```sh
sudo install -Dm755 guardiand /usr/local/bin/guardiand
getent group guardian >/dev/null || sudo groupadd --system guardian
id guardian >/dev/null 2>&1 || sudo useradd --system --gid guardian \
  --home-dir /var/lib/guardian --shell /usr/sbin/nologin guardian

# Immutable config: root-owned, service-READABLE only (the group must be set
# by hand; systemd's ConfigurationDirectory= never chowns /etc/guardian).
sudo install -d -o root -g guardian -m710 /etc/guardian
sudo install -d -o root -g guardian -m750 /etc/guardian/rules.d
sudo install -o root -g guardian -m640 guardian.yaml /etc/guardian/guardian.yaml
# The starter WAF rules the example config enables; without this file the
# unit's ExecStartPre `-t` preflight fails on the missing rules_file.
# Per-host exceptions to this shared file belong in guardian.yaml
# (waf.keywords.disabled_rule_ids), not in diverging copies of the file.
sudo install -o root -g guardian -m640 deploy/rules-common.yaml /etc/guardian/rules.d/common.yaml

sudo install -Dm644 deploy/guardiand.service /etc/systemd/system/guardiand.service
sudo systemctl daemon-reload
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # liveness -> ok
curl -s localhost:8072/readyz          # readiness -> {"ready":true,...}
```

Generated state (the signing key, retired-key archive, admin token, and the
store) lives under `/var/lib/guardian`, which the unit's `StateDirectory=`
creates and owns for the service user; nothing there needs manual setup. The
split is deliberate: config under `/etc/guardian` stays read-only for the
daemon, so a compromised process cannot rewrite its own policy. See
"Filesystem layout and ownership" in the production guide on the docs site
for the full reasoning and exact ownership details.

The shipped `Type=notify` unit reports `READY=1` only after every configured
listener answers `/healthz`, then services the systemd watchdog. The distroless
Compose deployment uses `guardiand -healthcheck` for the same readiness
contract.

Prefer containers? Every release publishes a prebuilt image (distroless and
nonroot). Pull the same pinned tag selected for the deployment, for example
`docker pull registry.melroy.org/melroy/angie-guardian:${GUARDIAN_VERSION}`.
See the production guide on the docs site for a compose service with
persistent volumes, or `deploy/docker/` for the full demo stack.

## 4. Operate it via the admin API

The admin API + `/metrics` live on `admin.listen` (e.g. `127.0.0.1:8072`),
separate from the auth hot path. `/metrics`, `/healthz`, `/readyz`, and the optional static
dashboard shell are open; every JSON/data `/admin/*` route needs an
`Authorization: Bearer <token>` header with that exact scheme prefix. The
dashboard authenticates every API call.

You never have to invent that token yourself. It resolves in this order:

1. `admin.token` (or the `ADMIN_TOKEN` env var), if set;
2. `admin.token_file`: auto-generated on first start (0600) and reused
   forever after, like the PoW signing key;
3. neither set: a loopback listener gets a fresh ephemeral token each start,
   printed in the startup log. A non-loopback bind refuses to start without
   an explicitly configured token (1 or 2).

```sh
TOKEN=$(sudo cat /var/lib/guardian/admin.token)   # or your admin.token value
A=http://127.0.0.1:8072

# Is an IP currently blocked, and why?
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks/203.0.113.9
# {"ip":"203.0.113.9","blocked":true,"reason":"threshold:signature"}

# List a bounded page of active blocks. Default 1000, maximum 10000;
# complete=false means additional blocks exist.
curl -s -H "Authorization: Bearer $TOKEN" "$A/admin/blocks?limit=1000"
# {"count":2,"complete":true,"blocks":[{"ip":"203.0.113.9","reason":"waf:dotfile-probe",
#                       "expires_at":"2026-07-05T18:30:00Z"}, ...]}

# What did the guardian just challenge or deny? Newest first, from an
# in-process ring buffer (per instance, cleared on restart). Filters:
# ?limit= (default 50), ?action=deny|challenge, ?reason=<prefix e.g. waf>.
curl -s -H "Authorization: Bearer $TOKEN" "$A/admin/decisions?action=deny&limit=20"

# A small "right now" rollup: active blocks, recent counts by action and
# reason category, and the PoW lifecycle (challenges issued/solved/failed +
# average solve seconds). (Long-horizon numbers live in /metrics.)
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/stats

# Block an IP for two hours (reason + ttl optional; default 15m, max 8760h).
# All block member routes validate the IP and canonicalize equivalent IPv6
# spellings to one key.
# NOTE: a crawler that passes verified_bots outranks these blocks (so a
# behavioural mishap can never knock Googlebot offline). To hard-block an
# IP even against a verified crawler, use the static denylist, which runs
# before everything.
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
     -d '{"reason":"manual abuse report","ttl":"2h"}' \
     $A/admin/blocks/203.0.113.9

# Lift a block.
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE $A/admin/blocks/203.0.113.9

# "Why would this request be challenged?" Score it against the domain's
# anomaly model, for tuning challenge_at / deny_at.
curl -s -H "Authorization: Bearer $TOKEN" \
     "$A/admin/score?host=shop.example.com&method=GET&uri=/cgi-bin/x%3Fa=1&ua=curl/8"
# {"host":"shop.example.com","method":"GET","route":"/cgi-bin","baseline":"exact","scored":true,"score":0.72}

# Loaded anomaly artifacts plus coverage/mode for every configured scope.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/anomaly

# Rotate the Ed25519 signing key. Requires previous_key_dir; shared live
# replicas refresh automatically. Pre-rotation tokens remain valid for at most
# seven days; older archive files are ignored in memory, not auto-deleted.
curl -s -H "Authorization: Bearer $TOKEN" -X POST $A/admin/rotate-key
# {"rotated":true}

# Reload guardian.yaml without a restart (same as sending SIGHUP). A config
# that fails validation, or changes a startup-only listener/store/key/admin
# field, is rejected and the running config stays active.
curl -s -H "Authorization: Bearer $TOKEN" -X POST $A/admin/reload
# {"reloaded":true}

# See which features are active per domain.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/config

# IP intelligence status: GeoIP database types and build dates, plus every
# reputation feed's entry count, last refresh and last error.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/intel

# What do we know about an IP? Country, ASN and feed membership, for testing
# geo rules and answering "why was this client denied".
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/intel/203.0.113.9
# {"ip":"203.0.113.9","enabled":true,
#  "info":{"country":"RU","asn":64500,"as_org":"Example Carrier"},
#  "feeds":[{"feed":"firehol-level1","action":"deny"}]}

# Prometheus scrape (no token needed).
curl -s $A/metrics | grep guardian_
```

### The reporting dashboard

Set `admin.dashboard: true`, start guardiand, and open the URL it prints:

```
INFO admin dashboard ready url=http://127.0.0.1:8072/admin/dashboard
```

Paste the token from `admin.token_file` (or your configured secret) into the
login gate. Configured and persistent bearer credentials are never embedded
in process logs; the page keeps the token in the tab's sessionStorage.

The dashboard shows active blocks (with one-click unblock and a block-an-IP
form), the recent deny/challenge feed (filterable by action and free text),
challenge lifecycle counters with the average solve time, per-domain feature
status, anomaly baseline coverage and segment health, IP intelligence health
(loaded GeoIP databases plus each reputation feed's entries, refresh age and
last error), and headline counters, auto-refreshing every 5 seconds. The page is a
static shell: it stores no secrets, stays off unless enabled, and every data
call goes to the token-guarded `/admin/*` endpoints. The shell can still be
publicly reachable on an external admin bind, so keep this listener on
loopback or a firewalled management network.

## 5. Train the anomaly model

Once JSON logs have accumulated, build a candidate domain and route/method
baseline offline.
Inspect it before atomically promoting it to the path configured by
`anomaly.model`; `guardiand` hot-swaps a valid replacement without a restart:

```sh
guardian-train train \
  -out model.candidate.json \
  -report training-report.json \
  -min-requests 5000 \
  -min-segment-requests 500 \
  -max-segments 128 \
  -max-invalid 0 \
  -require-domain example.com \
  /var/log/angie/*.access.json*
```

For production, use the shipped `deploy/guardian-train.service` and
`deploy/guardian-train.timer` instead of a bare cron entry. The helper validates
the strict log schema, verifies expected domains, compares the candidate with
the active artifact, and promotes atomically while retaining the last-good
artifact; see
the [production guide](https://angieguardian.org/guide/production#running-the-anomaly-trainer).
The CLI reads plain and gzip-compressed logs directly. Responses with status
400 or higher and requests Guardian challenged, denied, or shed are excluded.
Malformed or schema-invalid records reject training by default. Training and
scoring normalize host and percent-decode path/query identically before deriving
features.

## 6. Load-test your deployment

`guardian-loadtest` drives the `/auth` hot path the way Angie does, over
keepalive connections, and reports throughput + latency percentiles:

```sh
# Plain allow path (full pipeline).
guardian-loadtest -url http://127.0.0.1:8071 -scenario allow -host example.com -c 64 -d 10s

# Production common path: solve one real challenge, then hammer with the cookie.
guardian-loadtest -scenario token -host example.com -c 128 -d 10s

# Static deny path; the IP must appear in this host's denylist.
guardian-loadtest -scenario deny -host example.com -ip 203.0.113.9 -c 64 -d 10s

# Write path (requires PoW enabled): one synchronous challenge CAS per request,
# plus coalesced background counter increments. This separates the store
# backends; the scenario rotates client IPs to avoid the issuance limit.
#
# Use FIXED WORK here, not a duration: every request grows the store, so
# throughput falls as the run proceeds and a duration average depends on
# machine speed and run length. -warmup starts the measured window past the
# in-process counter caches' capacity, i.e. in the loaded steady state a real
# flood produces.
guardian-loadtest -scenario challenge -host example.com -c 64 -warmup 150000 -n 150000
```

Every run ends with a `per-second:` line, one measured-completion count per
second. Read it before trusting the aggregate: flat means a steady state, and
falling means only fixed-work (`-n`) runs with identical flags are comparable.

The `allow` and `token` scenarios do one block lookup; a static `deny` match
does no store I/O. `challenge` is the write-heavy path and the only one whose
throughput really separates the backends: measured per instance, `pebble`
async leads (~61k/s), then `buntdb` async (~56k/s), then redis/valkey
(~49k/s), then `pebble` with `sync: true` (~34k/s). See
[Choosing a store backend](#choosing-a-store-backend).

In normal operation challenge issuance uses that stateful write. If it fails,
Guardian preserves availability by issuing the authenticated stateless format;
the single-spend write moves to redemption and the fallback is visible through
the `issued_stateless_fallback` challenge metric outcome.

## Choosing a store backend

- **memory**: single instance, state lost on restart. Fine for dev or a small
  site that can re-learn blocks after a restart.
- **buntdb**: single instance, persistent. Stores state in a single file
  (`store.path` is that file). `store.sync: true` is rejected on buntdb (it is
  single-writer); leave `sync: false` for fast async durability, or use
  `pebble` when you need synchronous fsync-per-write.
- **pebble**: single instance, persistent, and the recommended single-box
  production choice (the configuration default is `memory`). An LSM engine
  whose `store.path` is a directory. `store.sync: false` (the default) is fast
  async durability; `store.sync: true` fsyncs every write. Under a very high
  sustained rate of *new* clients (each of which triggers a challenge write in
  `pow.mode: always`), a single-box durable backend eventually becomes the
  ceiling. Load-test with `guardian-loadtest` at your expected new-client rate
  before relying on it near 50k req/s. If one box saturates, set
  `pow.mode: suspicion` (no catch-all challenge, so only explicit policies
  cause challenge writes), lean on attack mode's stateless issuance (no write
  at issue at all), or scale out to replicas on `redis`. Note that moving to
  redis does not make a single instance write faster — it measures somewhat
  slower per instance than `pebble` async — what it buys is running several
  instances against one shared store.
- **redis**: the multi-instance option. Works with both Redis and
  [Valkey](https://valkey.io/) (the open-source Redis fork), which is a drop-in
  replacement (same wire protocol, same `backend: redis` value). Choose it to
  share blocks, counters and spent challenges across replicas, not for raw
  speed: one network round trip per request puts its read paths below the
  embedded backends, and its challenge write path measures ~49k/s against
  `pebble` async's ~61k/s. Aggregate capacity comes from running more
  instances. See below.

## Multi-instance (Redis/Valkey)

To run replicas behind a load balancer, point every instance at one shared
Redis or Valkey instance and share the signing key + `previous_key_dir` across
them, so any instance verifies any other's tokens and sees any other's blocks.
Live replicas notice rotations automatically; token signing reads the current
key under the rotation lock, while stateless challenge issuance and JWT
verification perform bounded, rate-limited key-set refreshes. Verification
fails closed when the shared key files cannot be refreshed, including before
accepting a cached token. The archive directory is required
before `POST /admin/rotate-key` is allowed. Retired archives verify
pre-rotation tokens for at most seven days and in-flight stateless challenges
through a rolling rotation; older files may remain on disk but are ignored by
the active verifier.
Valkey is a fully compatible drop-in replacement for Redis; the configuration
is identical for both.

```yaml
store:
  backend: redis            # same value for both Redis and Valkey
  addr: 127.0.0.1:6379
  # password: ""          # or the REDIS_PASSWORD env var
signing_key_file: /var/lib/guardian/ed25519.key   # same file on every replica
previous_key_dir: /var/lib/guardian/keys.d        # same lock-capable shared filesystem
```

Use a fresh, dedicated logical database on a Redis/Valkey server per Guardian
deployment and keep the plaintext connection on loopback/private networking or
inside a verified TLS/mTLS tunnel. Guardian keys are not deployment-prefixed,
so sharing one database across unrelated sites mixes their security state.

`store.addr` uses the standalone Redis protocol client. Redis Cluster is not
currently supported (Guardian's atomic block-index scripts intentionally touch
the block key and its shared index together); put a stable TCP endpoint in
front of a replicated service if you need server failover.

The signing paths must share cross-host advisory locks and atomic renames.
Asynchronous rsync/Syncthing copies do not share the rotation `flock`; when
asynchronous distribution is unavoidable, designate exactly one rotator and
finish distribution before another rotation.

Key refresh and token minting deliberately fail closed when either key path is
temporarily unreadable. On a single host, keep both paths on local disk. Across
hosts, use a low-latency, reliably mounted shared filesystem whose advisory
locks and atomic renames work across clients; a flaky NFS/distributed mount can
cause a brief fleet-wide challenge/token outage. Include mount interruption
and recovery in the pre-production soak. Guardian enumerates the retirement
directory during refresh, so archive or delete files older than the seven-day
verification horizon to keep directory scans bounded; expired key contents are
not read by the verifier.

## WASM module (optional)

Instead of the sidecar, you can run Guardian's **stateless WAF checks**
in-process inside Angie via its WebAssembly support. This path does the
store-free checks only (allowlist, denylist, honeypot, keyword/regex
signatures); proof-of-work and behavioural IP blocking need sidecar state,
while anomaly scoring also remains sidecar-only. Use it when you want the WASM
integration and the stateless WAF subset is enough, or alongside a backend
that handles the rest.

Build the module (architecture-independent):

```sh
make wasm        # -> dist/guardian.wasm
# or: GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
```

Requires an Angie build with WASM support (wasmtime or WAMR). Load it and wire
the handler using the snippet in `deploy/angie-wasm.conf`:

```nginx
# http {} context: load the module once, with the guest config inline.
wasm_modules {
    load /etc/guardian/guardian.wasm id=guardian type=reactor
      config='
        domains:
          example.com:
            allowlist: { paths: [ "/robots.txt" ] }
            # invent your own trap path; a guest honeypot hit denies only
            # that request (no persistent block), but a copied generic path
            # can still deny a route your site really serves
            honeypot:  { enabled: true, paths: [ "/your-own-trap/" ] }
            rules:
              - { id: dotfile, action: deny, keywords: [ "/.env", "/.git/" ] }
      ';
}

# location {}: run the guest as the content handler.
location / {
    wasm_content handler "ngx:wasi/http-handler-entry#handle-request" module=guardian;
    # ... your normal proxy_pass / root handling continues when allowed ...
}
```

The guest reads its per-domain config from the module `config=` blob (YAML or
JSON) via the http-wasm `get_config` call. It returns *allow* to continue to
your backend, or a `403` to block. Editing the rules means updating the Angie
config and reloading Angie (the `.wasm` itself does not need rebuilding for a
config change).

**A config error fails closed.** If the `config=` blob does not parse (a
typo'd field, an invalid CIDR, or two domain keys that collapse to the same
host after normalization: `a.test` vs `A.test:443`) the guest denies **every
request on every host** with `500 Guardian WASM misconfigured`, and the only
signal is one line in Angie's error log. Unlike the sidecar, which refuses to
start on a bad `guardian.yaml`, a bad guest config only surfaces at request
time. The guest schema uses inline `rules` and is not accepted by
`guardiand -t`, so exercise a request against a staging WASM instance before
reloading production Angie.
