# Bots, GeoIP & Reputation

Three features decide who gets in based on **who the client is** rather than
what it sends: verified search crawlers (rDNS identity instead of a forgeable
User-Agent), GeoIP scoping (country and ASN), and external IP reputation
feeds.

## Search crawlers: verified_bots, not allowlist.uas

Search crawlers won't solve a PoW puzzle, so they need an allowlist entry or
your site drops out of the index. **Do not** allowlist them by User-Agent
(`allowlist.uas: [ Googlebot ]`): the UA string is freely forgeable, and such
an entry lets any scraper skip the entire pipeline by claiming to be
Googlebot. Guardian refuses to load a config where an `allowlist.uas` entry
overlaps a configured bot for exactly this reason.

Instead, `verified_bots` admits a crawler only after proving its identity the
way the search engines themselves document:

1. reverse-DNS (PTR) lookup on the client IP;
2. the returned hostname must be under one of the bot's published domains
   (e.g. `crawl-66-249-66-1.googlebot.com`);
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

::: tip Google's three crawler categories
The presets keep Google's rDNS categories apart deliberately. `googlebot`
verifies under `googlebot.com` only, the published domain for its **common
crawlers** (everything presenting a Googlebot UA). The **special-case
crawlers** (AdsBot, Mediapartners-Google, APIs-Google) verify under
`google.com` via the separate `google-special` preset; enable it if you run
Google Ads, since AdsBot can't solve PoW and blocking it hurts ad quality.
Google's **user-triggered fetchers** (Feedfetcher, Read-Aloud, Apps Script)
are deliberately not a preset: third parties can point them at any site on
demand, so allowlisting them is an explicit operator decision.
:::

A verified crawler is allowed with reason `verified_bot:<name>` and skips the
rest of the pipeline, including behavioural IP blocks and reputation feeds,
so a scoring mishap or a feed false positive can never knock a search crawler
offline. Static `allowlist`/`denylist` entries still run first: an explicit
denylist entry is the one thing that outranks a verified bot.

A client that claims a listed UA but **definitively** fails verification,
meaning its IP has no PTR record or its rDNS belongs to someone else, is an
impostor: with `spoof_action: deny` (the default) it is rejected and emits
a `bot_spoof` event. When `waf.ip_behaviour.enabled`, 5/min blocks the IP
(tune under `waf.ip_behaviour.thresholds`); with `continue` it is simply not allowlisted
and the normal WAF/PoW pipeline applies. Transient DNS failures prove nothing
and just fall through unverified, so a flaky resolver can neither block
Googlebot nor admit a scraper.

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

Every field: [verified_bots reference](/reference/configuration#verified-bots).

## GeoIP scoping

Guardian can scope traffic by origin country and ASN. Point `geoip:` at
MaxMind-format `.mmdb` files. Guardian hot-reloads the files when they are
replaced on disk, so a scheduled update cron needs no restart.

```yaml
geoip:
  location_db: /var/lib/GeoIP/GeoLite2-Country.mmdb  # 8.8 MB, recommended
  # location_db: /var/lib/GeoIP/GeoLite2-City.mmdb   # 66 MB, adds city/region
  asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb           # optional, for asns:
```

### Getting the databases

Free options, easiest first:

| Source | What you need | Notes |
|---|---|---|
| [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb/releases) | nothing | Unofficial GeoLite2 mirror, no account, plain HTTPS download. |
| [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) | free account + licence key | The upstream source; use [`geoipupdate`](https://github.com/maxmind/geoipupdate). |
| [DB-IP lite](https://db-ip.com/db/lite.php) | nothing | Different publisher, monthly builds, filenames differ. |

The quickest start is the P3TERX mirror. It republishes MaxMind's own GeoLite2
files unchanged, on a GitHub Actions cron that runs every three days, and the
`releases/latest/download/` URLs always resolve to the newest build:

```sh
sudo mkdir -p /var/lib/GeoIP
cd /var/lib/GeoIP
sudo curl -fsSL -o GeoLite2-Country.mmdb.new https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb
sudo curl -fsSL -o GeoLite2-ASN.mmdb.new https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb
sudo mv GeoLite2-Country.mmdb.new GeoLite2-Country.mmdb
sudo mv GeoLite2-ASN.mmdb.new GeoLite2-ASN.mmdb
```

That is Country (8.8 MB) plus ASN (12 MB); swap Country for `GeoLite2-City.mmdb`
if you want city and region labels, as the next section explains.

Guardian polls both files once a minute and reloads on any size or timestamp
change, so updates need no restart, and a failed reload keeps the previously
loaded data. Downloading to `.new` and `mv`-ing it into place matters for that
reason: the rename is atomic, so the poll never catches a half-written database.
Re-run the snippet from a weekly cron to stay current, or use
[`geoipupdate`](https://github.com/maxmind/geoipupdate) with a free MaxMind
licence key, which replaces files the same way. The data is MaxMind's, under the
[GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula).

### Country or City: both go in `location_db`

GeoLite2 ships three files, and two of them belong in `location_db`. That one
key takes either because **City is a superset of Country**: it carries the same
`country.iso_code`, plus city, region and postal detail on top. Country rules
behave identically whichever you load, which is why the key is not named after
either product. GeoIP2-Enterprise and DB-IP files work here too.

| | `GeoLite2-Country.mmdb` | `GeoLite2-City.mmdb` |
|---|---|---|
| Size (memory-mapped) | 8.8 MB | **66 MB** (7.5x) |
| `countries:` selectors | yes | yes, identical |
| City / region in admin views | no | yes |

**Use Country unless you specifically want city labels.** City costs 7.5x the
size and buys no new rules: there is no `cities:` or `subdivisions:` selector,
by design. What it adds is visibility. Offender rows read
`Schagen, NH · NL · KPN B.V.` instead of `NL · KPN B.V.`, which helps when you
are working out whether traffic is one datacentre or a whole region.

::: warning A GeoLite2 location is an area, not an address
City data is a *hint*, and often a very coarse one. MaxMind defines a location
as a circle with an accuracy radius "from a few kilometers to 1000 kilometers",
and says it "should not be used to identify a particular address or household".

Measured over all 5.8M networks in the City database: only ~17% resolve to
within 10 km, while **~29% carry a radius of 200 km or worse** and 12.5% sit at
the 1000 km floor. `8.8.8.8` is the classic case: it resolves to the geographic
centre of the United States at a 1000 km radius, which means "somewhere in the
US", not a place.

So Guardian never exposes latitude/longitude, and marks any locality resolved
to 200 km or worse as approximate in the dashboard. Roughly a fifth of networks
have no city at all, which shows as country only rather than a guess.
:::

Whichever file you load, the dashboard also draws a
[world map](/guide/admin) of where non-allow decisions come from.

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

Where it sits in the pipeline matters:

- **Deny** verdicts fire right after the static denylist. A PoW token never
  rides past them; only an rDNS-verified crawler does.
- **Challenge** verdicts fire after the PoW token check, so a listed client
  solves once and then browses normally until its token expires.

Semantics worth knowing:

- Precedence is deny, then challenge, then allow, then `default_action`.
  Listing the same country or ASN in two selectors is a config error.
- An IP the database has no record for (private ranges, brand-new
  allocations) matches no selector and gets `default_action`. Keep internal
  ranges on the static `allowlist` before tightening `default_action`.
- Challenge policies need PoW enabled on the domain; on a PoW-less domain
  they are inert rather than degrading to a deny (a typo should not cut off
  a whole country). Denies apply everywhere, PoW or not.
- Config is refused when a selector needs a database you did not configure,
  so a country block can never be silently inert.

## IP reputation feeds

Feeds are plain-text IP/CIDR lists, one entry per line with `#`/`;`
comments: the format of the FireHOL netsets, blocklist.de exports, and
simple hand-maintained files. Define them once at the top level; every
domain that sets `reputation: { enabled: true }` (typically in `defaults`)
enforces them.

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

URL feeds are fetched in the background: startup never blocks on a remote, a
failed refresh keeps the last good list (and retries within 5 minutes), and
`cache_dir` seeds the list at boot so a restart doesn't open a window. A
hot config reload also carries the in-memory last-good state forward when a
URL feed keeps the same name and URL, before the replacement provider starts
its asynchronous refresh. This avoids a temporary enforcement gap even when
`cache_dir` is unset and the remote is down during reload. A local `file:`
feed must exist at startup (fail-fast, like the WAF rules files) and is
hot-reloaded on change. URL responses, local files, and persisted caches are
limited to 64 MiB; an oversized update keeps the last-good list. Matching is a
binary search over merged ranges, so
six-figure feeds are fine on the hot path.

An `action: deny` feed rejects matching IPs outright; `action: challenge`
makes them prove work first, one full difficulty step (+4 bits = 16x) above
base, like a WAF signature hit. Challenge feeds are inert on PoW-disabled
domains.

## Watching it run

- `guardian_feed_entries` and `guardian_feed_refresh_total` in `/metrics`
  track feed health; `guardian_bot_verifications_total` tracks crawler
  verification outcomes.
- `GET /admin/intel` reports the loaded GeoIP databases and every feed's
  entry count, last refresh, and last error.
- `GET /admin/intel/<ip>` answers "what would Guardian make of this IP?":
  country, ASN, and feed membership.
- The [reporting dashboard](/guide/admin#the-reporting-dashboard) shows the
  same in its IP intelligence panel.

## Next steps

- Every field, type, and default:
  [geoip](/reference/configuration#geoip),
  [reputation](/reference/configuration#reputation),
  [geo](/reference/configuration#geo), and
  [verified_bots](/reference/configuration#verified-bots)
- The intel endpoints: [Admin API reference](/reference/admin-api#ip-intelligence)
