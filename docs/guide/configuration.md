# Configuration

Guardian reads a single YAML file (`guardian.yaml`). Per-domain settings are
merged **field-by-field** over `defaults`: a domain only names what it
changes. Unknown hosts fall back to `defaults`.

This page covers the concepts; the
[Configuration Options reference](/reference/configuration) lists every field
with its default.

## The per-domain model

```yaml
domains:
  # HTML site behind PHP/Node: all Guardian layers, PoW + the URI/header
  # WAF (request bodies never reach Guardian; payload validation stays with
  # the backend). Difficulty takes quarter steps: 5.25 is exactly 2x the
  # work of 5 (see the difficulty table below).
  example.com:
    pow: { enabled: true, base_difficulty: 5.25 }   # token_ttl inherits 7d
    # Honeypot: no generic trap path is safe to copy (one hit persistently
    # blocks the source IP when ip_behaviour is on). Invent a path specific
    # to YOUR site that nothing links to, then enable:
    # waf: { honeypot: { enabled: true, paths: [ "/your-own-trap/" ] } }

  # API host: WAF only, no interstitial a machine client can't solve. With
  # PoW off, challenge-action rules degrade to deny (nothing to challenge
  # with); append API rules and disable selected shared IDs if that is too blunt.
  api.example.com:
    pow: { enabled: false }

  # Static assets: no PoW, no behavioural scoring. WAF rules still
  # apply from defaults; disable matching or selected IDs for a minimal policy.
  static.example.com:
    pow: { enabled: false }
    waf: { ip_behaviour: { enabled: false } }

  # Disable the catch-all challenge. Requests below the anomaly threshold are
  # not challenged by this policy. Requires a trained model.
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 challenge_at: 0.5, deny_at: 0.85 }
```

For a non-enforcing rollout, add `observe_only: true` to the anomaly settings,
tune the thresholds from `guardian_anomaly_score`, then remove it or set it to
`false`.

## Per-path overrides

When a site and its machine endpoints share one host, a domain entry can scope
any setting to a URI prefix with a `paths` map. The most specific key wins, and
matching is against the percent-decoded path:

```yaml
domains:
  example.com:
    pow: { enabled: true }
    paths:
      "/api/v1/":
        pow: { enabled: false }   # no interstitial; the WAF stays on, but
                                  # challenge-action rules degrade to deny here
      "/account/login":
        pow: { base_difficulty: 6 }
```

The same map under `defaults` is fleet-wide: every domain and every unknown
host inherits it, merged over that domain's own settings. That is the place
for files a crawler must be able to fetch but can never solve a challenge for:

```yaml
defaults:
  pow: { enabled: true }
  paths:
    "/robots.txt": { pow: { enabled: false } }
    "/sitemap.xml": { pow: { enabled: false } }
    "/favicon.ico": { pow: { enabled: false } }
    "/favicon.svg": { pow: { enabled: false } }
    "/apple-touch-icon.png": { pow: { enabled: false } }
    "/apple-touch-icon-precomposed.png": { pow: { enabled: false } }
    "/manifest.json": { pow: { enabled: false } }
    "/manifest.webmanifest": { pow: { enabled: false } }
    "/site.webmanifest": { pow: { enabled: false } }
```

Leaving PoW on at `/robots.txt` means well-behaved crawlers get the
interstitial instead of your `Disallow` rules, including the ones steering
them away from [honeypot](/reference/configuration#waf-honeypot) traps; the
file also carries the `Sitemap:` line, so exempting it while the URL it
advertises still challenges just moves the dead end one hop further. This is
narrower than an `allowlist.paths` entry, which ends the pipeline outright:
here blocks, GeoIP, reputation and the WAF still apply. A single host
overrides an inherited entry by naming the same key in its own `paths`.

Keys match exactly, so `"/sitemap.xml"` covers a flat sitemap and nothing
else: add the paths yours actually uses when they differ (WordPress core
serves `/wp-sitemap.xml`, Yoast `/sitemap_index.xml`), including per-type
children named by an index, or the index resolves while every child it points
at is challenged. The listed manifest, icon and browser-metadata files are
only conventional root URLs; add your site's own asset URLs explicitly rather
than exempting a broad asset prefix. This hands an anonymous client your URL
list; the pages themselves still cost a solve, and one solve buys `token_ttl`
of crawling either way.

See [per-path overrides](/reference/configuration#per-path-overrides-domains-host-paths)
in the reference for the exact matching and inheritance rules.

## WAF rules

The `waf.rules` layer matches literal and regex rules against the request line and
headers. Getting from the shipped starter file to a running configuration
takes three explicit steps; none of them happen automatically:

1. **Install the starter rules file.** The release archive (and the repo) ships
   [`deploy/rules-common.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/rules-common.yaml), a commented starter set (dotfile probes,
   path traversal, SQLi heuristics, scanner UAs). The
   [production install recipe](/guide/production#systemd) copies it to
   `/etc/guardian/rules.d/common.yaml`; nothing is auto-discovered from that
   directory, it is just the conventional location.
2. **Point the config at it** and enable matching:

   ```yaml
   defaults:
     waf:
       rules:
         enabled: true
         files: [ /etc/guardian/rules.d/common.yaml ]
   ```
3. **Validate**: `guardiand -config guardian.yaml -t`. A configured file that
   does not exist while `enabled: true` fails fast, at preflight and at
   startup, rather than silently matching nothing.

Inside a rules file, each rule has an `id`, an `action`
(`allow` | `deny` | `challenge` | `block`), optional `targets` (`path`, `query`, `ua`,
`header:<name>`; default `[path, query]`), optional `methods`, and `keywords`
(case-insensitive literals) and/or `regexes` (Go RE2, linear-time). Rules are
evaluated **in effective file order, then file order, and the first match
wins**, so put narrow allow
exceptions before the broader deny, challenge or block rules they override.
An allow match is terminal at the WAF stage and does not feed the
`rule_match` behaviour counter. Earlier denylist, deny-intel, active-block and
honeypot stages still win; later PoW, challenge-intel and anomaly stages are
skipped. The decision is still counted as `action="allow", reason="waf"` in
Prometheus, with full reason `waf:<id>` in structured decision logs. Like every
allow, it is omitted from the bounded recent-decisions ring. The `id` does
double duty: a matching decision carries `waf:<id>` in response headers and
logs, and the ID is the exact, case-sensitive selector for per-scope exclusions
(below). The starter file documents
every field; the [reference](/reference/configuration#waf-rules) lists the
exact matching semantics.

Like every `waf` setting, `defaults.waf.rules` is inherited by **every domain
and path overlay**, so the file above applies to your whole estate, including
unknown Hosts that fall back to `defaults`. `files` has intentionally
cumulative inheritance: files named by a domain are appended after the
defaults, and files named by a matching path are appended after those. Common
protection therefore cannot disappear merely because a narrower scope adds its
own policy. Scoping works three ways:

- Extend a domain (or path overlay) with additional `files`. The combined
  order is defaults, domain, path; within each file, document order is kept.
- Turn matching off for a scope with `enabled: false`.
- Disable **individual rules** for a scope with `disabled_ids`, without
  copying the file.

Because inherited rules run first, a shared deny/block cannot be bypassed by a
later domain allow. When that exception is intentional, disable the shared
rule's ID for that scope; evaluation then falls through to the domain rules.
Duplicate paths and duplicate rule IDs across an effective file set are
rejected so file order, exclusions, logs, and decision reasons stay
unambiguous.

### Per-scope rule exclusions (`disabled_ids`)

A shared rules file rarely fits every host exactly: the starter set's
`wp-cms-probe` rule is right on non-WordPress hosts and wrong on a real WordPress
domain. Instead of maintaining a diverging copy of the file for one exception,
list the rule's exact `id` in that scope's `disabled_ids`:

```yaml
defaults:
  waf:
    rules:
      enabled: true
      files: [ /etc/guardian/rules.d/common.yaml ]

domains:
  wordpress.example.com:
    waf:
      rules:
        disabled_ids: [ wp-cms-probe ]
```

A disabled rule is removed from evaluation for that resolved scope only; the
remaining rules keep their effective file and document order, so the next matching rule still
decides. Like every list in the overlay model, the field replaces wholesale:
omitted inherits the parent's resolved list, an explicit `[]` clears inherited
exclusions, and a non-empty list replaces the inherited one (re-list inherited
IDs to keep them). Effective sets are precompiled at startup/reload, so
exclusions add no per-request work.

Validation is deliberately strict, so a typo can never silently leave a
dangerous rule enabled: empty, whitespace-only or duplicate entries, an
exclusion list with no effective `files` (even while `enabled: false`),
and any ID absent from the scope's combined rules are all rejected at
`guardiand -t`, startup and reload, with the error naming the scope, files and
unknown ID.

The [examples page](/examples#waf-rules-shared-protection-with-domain-additions)
has a complete copyable config combining a shared file, per-domain exclusions,
domain additions and a fully disabled scope. It also includes the full
contents of the referenced `api.yaml`, including an allow rule.
[`GET /admin/config`](/reference/admin-api#get-admin-config) shows every
scope's ordered effective `files` and exclusions together.

Rules files hot-reload two ways: they are watched on disk (edits apply within
seconds, no signal needed), and a SIGHUP/`/admin/reload` re-reads
`guardian.yaml` including any changed `files` paths. A file that fails to
parse or exceeds the 8 MiB bound keeps the previous rules active; only a cold
start hard-fails. A watched update that removes or renames a rule ID some
scope still excludes is rejected the same way, so a renamed formerly-disabled
rule can never become active silently: to delete a disabled rule
intentionally, first remove its ID from `guardian.yaml` and reload
successfully, then remove the rule from the watched file.

## Validating a config

`-t` validates a config without starting the daemon (like `angie -t`): YAML
syntax, unknown fields and semantic checks, plus every startup-required local
artifact (WAF rules, anomaly models, GeoIP databases, file-based reputation
feeds). Listener `host:port` syntax and the non-loopback admin-token
requirement are checked here too, so a config cannot pass preflight and then
fail that policy during restart. It exits `0` and `ok` when valid, `1` and the
reason when not; remote URL feeds remain non-blocking.

```sh
./guardiand -config guardian.yaml -t
```

Output on a valid config:

```
config guardian.yaml: ok
```

...or, on a bad config:

```
config guardian.yaml: FAILED
config guardian.yaml: store.backend must be memory, buntdb, pebble or redis, got "etcd"
```

## base_difficulty and max_difficulty

`base_difficulty` is the baseline for an issued challenge;
`max_difficulty` is the normal-operation ceiling. Anomaly score,
WAF/reputation policy, and challenge-farming escalation can raise work within
`[base, max]`. One exception: [attack mode](/guide/attack-mode) shifts the
whole `[base, max]` window up fleet-wide, so with `attack_mode` enabled the
absolute ceiling is `attack_mode.effects.difficulty_cap` (default `7`), not
`max_difficulty`. Pick the cap, not the domain max, as your "worst case a
visitor can ever be asked" number.

A difficulty of `N` requires `4 * N` leading zero **bits** in the SHA-256, so
a full step (+1) is 16x the work, and the scale takes **quarter steps**: each
+0.25 is exactly one bit, doubling the expected work. `5.25` is twice as hard
as `5`, `5.5` four times, giving fine-grained control between the huge full
steps. Values off the quarter grid (like `4.3`) are rejected at load.

Which value fires:

- **`mode: always` (the default):** every unvouched request, regardless of
  HTTP method or User-Agent,
  pays exactly `base_difficulty`, once, then rides a `token_ttl` cookie (by default 7 days).
  The cookie token lifetime must be at least one second and at most thirty days. An issued
  challenge remains solvable for `challenge_ttl`, which defaults to 30 minutes.
- **A WAF rule hit:** one full step over base (`base + 1`, i.e. +4 bits
  = 16x, capped at `max`). A valid bound token satisfies rules whose action is
  `challenge`; it never bypasses `deny` or `block` rules. On a domain or path
  where PoW is disabled there is nothing to challenge with, so
  challenge-action rules degrade to deny there.
- **The anomaly scorer:** scales the difficulty across the `[base, max]`
  range with the score, so a more bot-like client pays more. Requires
  `waf.anomaly` enabled with a trained model.
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

  A missing or unrecognized `Sec-Fetch-Dest` is not refused by this rule, so a
  destination the Fetch standard adds later is never condemned by a list
  written before it existed, and stripping the header is not a way around
  escalation. That is not the same as being challenged: such a request falls
  through to the `Accept` heuristic below, which then judges it on its own
  terms, so an unrecognized destination or none at all, arriving with
  `Accept: */*` and no `Sec-Fetch-Mode: navigate`, is refused there. What the
  allowlist direction buys is that the unknown case is decided by the weaker
  signal an operator can turn off, not by this one. Claiming a subresource
  destination is no way out either: that client is refused the challenge, so
  it has nothing to farm.

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

  - They **are issued** a challenge, unlike subresources: `Sec-Fetch-Site` is
    not proof the frame is foreign. It is computed over the request's whole
    redirect chain against the initiator's origin and says nothing about the
    frame ancestor, so a same-origin iframe reached through a cross-site
    redirect (an SSO callback) arrives tagged `cross-site` while
    `frame-ancestors 'self'` renders it perfectly well; refusing would break
    those logins. This is also why the metric alone does not prove a hostile
    third party: your own embedded login callback appears here too.
  - They **are escalated**, on a separate counter, so difficulty still ramps.
    Any HTTP client can send these headers, and without the ramp the pair would
    be a cheap-challenge exemption. A solve clears both counters.
  - They are **never reported** as `challenge_farm`, which is the part that
    cannot be aimed safely when the signal is ambiguous.

  A same-origin frame is scored exactly as before, and a top-level navigation is
  never treated as framed, so an inbound cross-site link is unaffected.

  **When no Fetch metadata arrives at all, `Accept` is the last signal left.**
  The browser's favicon service refreshes an icon URL it already knows on a
  system principal: no cookie, no `Sec-Fetch-*` even over HTTPS, and
  `Accept: */*`. Nothing above sees it, so it was issued a challenge on every
  page render and escalated for abandoning one it could never run. A request
  whose `Accept` is present and names neither `text/html` nor `text/*` is
  therefore refused a challenge too, counted as
  `guardian_challenges_total{outcome="accept_heuristic_refused"}`.

  This one is a heuristic and is treated as one. RFC 9110 makes `*/*` formally
  accept every media type, HTML included, and the Fetch standard only says
  browsers *should* send the document `Accept` value for a navigation, so the
  claim is behavioural rather than semantic: mainstream browsers do include an
  explicit `text/html` range on a navigation, and something that does not is
  very unlikely to be one. It never overrides a stronger signal: a
  document-like `Sec-Fetch-Dest`, a `Sec-Fetch-Mode: navigate`, an absent
  `Accept`, or an `Accept` that cannot be parsed all keep the ordinary path.

  Like every other refusal it is sent `no-store`; a cacheable 403 would not
  help, since the Firefox favicon service it is aimed at requests a
  `private, max-age=30, must-revalidate` 403 just as often as a `no-store`
  one (a measured result about that client and that path, not a general rule
  about error statuses). The refusal ends the escalation, but does not by
  itself guarantee the client stops repeating the request.

  ::: warning A compatibility tradeoff
  On modern HTTPS browsers a recognized document destination protects customized
  `Accept` values. When Fetch metadata is unavailable, which means plain HTTP,
  older clients, or a proxy that strips the headers, the heuristic can refuse an
  unusual real navigation whose `Accept` lacks `text/html`. That is deliberate.
  Opt out per site, per path, or fleet-wide with
  `pow: { refuse_unchallengeable: false }`. The auth subrequest decides and
  relays its verdict to the challenge hop, so the recorded decision and the
  served response agree even if you flip the key while a request is between the
  two. Clearing the header in `location @guardian_challenge` is not the same
  thing and does not roll anything back: it changes only what the second hop
  serves, leaving the log describing a response nobody received, and it hides
  `Accept` from WAF `header:accept` rules besides.
  :::

  ::: warning HTTPS only, except for that one
  Browsers send `Sec-Fetch-*` only to potentially-trustworthy origins (HTTPS and
  localhost). A site served over plain HTTP receives none of them, so every
  destination reads as unknown and the subresource and frame protections above do
  not apply there. The `Accept` refusal needs no Fetch metadata, so it is the
  only one that does work over plain HTTP, and equally the only one whose
  false-positive risk is higher there.
  :::

### Measured solve times and recommended values

The interstitial solves in parallel web workers (up to 8) with a pure-JS
SHA-256. Measured throughput in Chrome on a fast desktop is ~1.1 million
hashes/s per worker, ~9 MH/s with 8 workers; scale down for weaker devices.
For comparison, a native (Go) solver does ~7.6 MH/s **per core**, so a bot
pays the same order of work a real browser does.

The browser matters as much as the hardware: on one 48-thread desktop,
Firefox 153 measures ~0.55 MH/s per worker (~4.4 MH/s at the 8-worker cap)
against Chrome 151's ~0.96 MH/s (~7.7 MH/s), the same silicon 1.75x apart.
Read the table below by hash rate, not device name: a fast desktop running
Firefox lands between the desktop and laptop columns, so tuning off the
desktop column alone understates what most visitors actually pay.

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

::: warning Budget for the tail, not the mean
Solve time is exponentially distributed around the mean: the median visitor
waits ~0.7x the mean, but ~5% wait 3x and ~1% wait 4.6x.
:::

Recommendations:

- **`base_difficulty: 5`** (the default): imperceptible on desktop, about a
  second on a mid-range phone. A sensible tax for `mode: always`, paid once
  per `token_ttl`.
- **`5.25`-`5.5`** when you are actively being scraped and can accept a few
  seconds on phones.
- **`4`-`4.5`** only when the interstitial itself (not the work) is the
  deterrent you want; the computation is near instant everywhere.
- **`max_difficulty: 6`** (the default) for all escalation. `6.5` and up
  is effectively a soft deny: a minute of hashing on a phone. Values above 7
  mostly punish real visitors on slow devices.
- Watch `guardian_challenge_solve_seconds` in Prometheus (or the dashboard
  average) after changing values: it is the real-world solve time of *your*
  visitors' devices. The metric carries a `domain` label, read by the
  dashboard's "Solve time by domain" card, so a difficulty that only hurts one
  site stands out; its neighbour "Solve time by client" answers the same
  question per device class from a sample of the recent decisions feed (a
  User-Agent taxonomy is a guess and has no business being a Prometheus
  label). For a single slow visitor, `GET /admin/decisions?action=solve` names
  the host, path, IP and User-Agent behind each solve.

::: tip PoW is not a flood defense
PoW only taxes clients that solve the puzzle. A client that farms challenges
without solving them is throttled (60 issuances per IP per minute), escalated
(see challenge farming above), and eventually blocked outright via the
`challenge_farm` threshold, but a raw flood that never even follows the
challenge redirect is **not** PoW's problem. Put Angie's own rate limiting in
front: see [Rate limiting](/guide/angie#rate-limiting-volumetric-ddos).
:::

## Loopback and trusted proxies

The sidecar trusts the `X-Guardian-*` headers Angie sets on the subrequest
(client IP, host, cookie). Keep `listen` on loopback so no client can reach it
directly and forge them. To bind a non-loopback address (Angie on another
host), isolate the listener to Angie (private network, firewall, or mTLS) and
set `trusted_proxy: true`, otherwise `guardiand` refuses to start.

## The signing key

`signing_key_file` holds the persistent Ed25519 key that signs PoW JWTs:
generated on first run if missing and **never** regenerated on restart, so
restarts don't log clients out and replicas can share it. Retired keys (from
`POST /admin/rotate-key`) are archived in `previous_key_dir` and accepted only
for bounded, pre-rotation token lifetimes (at most thirty days); expired
archives may remain on disk but drop out of the active verification set after
that horizon. Rotation requires a non-empty `previous_key_dir`; replicas must
share both paths and automatically refresh their verification set when
another replica rotates.

## Hot reload

Config edits do not need a restart. After changing `guardian.yaml`, either
signal the daemon or call the admin API:

```bash
# Validate config and all startup-required local artifacts first, then reload.
# -t reads /etc/guardian/guardian.yaml; pass -config for a file elsewhere.
guardiand -t
kill -HUP $(pidof guardiand)          # or: systemctl reload guardiand

# Equivalent over the admin API:
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8072/admin/reload
```

Domains, allow/denylists, thresholds, PoW difficulty and TTLs, WAF rules and
model file sets, GeoIP databases, reputation feeds and `log_level` all apply
immediately. Behavioural state survives the reload (active blocks, counters,
issued/spent challenge records and bot verdicts live in the store; signed
tokens remain client cookies), and a config that fails validation is rejected
while the running config stays active, so a bad edit cannot take the daemon
down.

Not reloadable (fixed at startup; a reload that changes one is rejected):
`listen`, `admin.listen`, `trusted_proxy`, the `store` block,
`signing_key_file`, `previous_key_dir`, `admin.recent_size`, and the admin
token/dashboard setup.

WAF rules files, anomaly model artifacts, `.mmdb` databases and file-based
reputation feeds are also watched on disk and reload on change by themselves;
SIGHUP/`/admin/reload` is only needed for edits to `guardian.yaml` itself.
Reads are bounded so an accidental or compromised artifact publisher cannot
exhaust daemon memory (`guardian.yaml` 4 MiB, WAF rules 8 MiB, anomaly models
and reputation feeds/caches 64 MiB each); an oversized hot update is rejected
while the last-good artifact remains active.

## Next steps

- Every field, type, and default: [Configuration Options](/reference/configuration)
- Verified crawlers, GeoIP scoping, and reputation feeds:
  [Bots, GeoIP & Reputation](/guide/bots-ip-intel)
- Full annotated example: [Examples](/examples)
- Suspicion-based challenges: [Train the Anomaly Model](/guide/anomaly)
