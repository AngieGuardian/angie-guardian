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
defaults:
  verified_bots:
    bots:
      - name: googlebot            # presets: googlebot, google-special,
      - name: bingbot              #   bingbot, applebot, yandexbot, baiduspider
      - name: mybot                # custom bots: spell out both fields
        uas: [ "MyBot/1.0" ]
        domains: [ "crawler.example.net" ]
    spoof_action: deny             # or: continue
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
impostor: with `spoof_action: deny` (the default) it is rejected and scored
as a `bot_spoof` behaviour event (5/min blocks the IP, tune under
`waf.ip_behaviour.thresholds`); with `continue` it is simply not allowlisted
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
MaxMind-format `.mmdb` files. Free options: [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) (free account
plus `geoipupdate`) or the [DB-IP lite](https://db-ip.com/db/lite.php) downloads. Guardian hot-reloads the
files when they are replaced on disk, so a weekly `geoipupdate` cron needs no
restart.

```yaml
geoip:
  country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
  asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb   # optional, for asns: selectors
```

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
local `file:` feed must exist at startup (fail-fast, like the WAF rules
files) and is hot-reloaded on change. Matching is a binary search over
merged ranges, so six-figure feeds are fine on the hot path.

An `action: deny` feed rejects matching IPs outright; `action: challenge`
makes them prove work first, one full difficulty step (+4 bits = 16x) above
base, like a WAF signature hit.

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
