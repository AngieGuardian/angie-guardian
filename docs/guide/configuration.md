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
  # HTML site behind PHP/Node: full protection. Difficulty takes quarter
  # steps: 5.25 is exactly 2x the work of 5 (see the difficulty table below).
  example.com:
    pow: { enabled: true, base_difficulty: 5.25, token_ttl: 2h }
    waf: { honeypot: { enabled: true, paths: [ "/wp-admin-old/" ] } }

  # API host: WAF only, no interstitial a machine client can't solve.
  api.example.com:
    pow: { enabled: false }

  # Static assets: keep it light.
  static.example.com:
    pow: { enabled: false }
    waf: { ip_behaviour: { enabled: false } }

  # Only challenge clients the anomaly scorer flags; ordinary visitors
  # never see an interstitial. Requires a trained model.
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 challenge_at: 0.5, deny_at: 0.85 }
```

## Validating a config

Validate a config without starting the daemon with `-t` (like `angie -t`). It
loads and validates the file (YAML syntax, unknown fields, and semantic
checks), then exits: `0` and `ok` when valid, `1` and the reason when not.

```sh
./guardiand -config guardian.yaml -t
# config guardian.yaml: ok
# ...or, on a bad config:
# config guardian.yaml: FAILED
# config guardian.yaml: store.backend must be memory, bbolt or redis, got "etcd"
```

## base_difficulty and max_difficulty

`base_difficulty` is the **floor** every clean client pays; `max_difficulty`
is the **ceiling**. They are not a choice between two modes: a request's
suspicion score decides where in `[base, max]` it lands.

A difficulty of `N` requires `4 * N` leading zero **bits** in the SHA-256, so
a full step (+1) is 16x the work, and the scale takes **quarter steps**: each
+0.25 is exactly one bit, doubling the expected work. `5.25` is twice as hard
as `5`, `5.5` four times, giving fine-grained control between the huge full
steps. Values off the quarter grid (like `4.3`) are rejected at load.

Which value fires:

- **`mode: always` (the default):** every unvouched request, regardless of
  HTTP method or User-Agent,
  pays exactly `base_difficulty`, once, then rides a `token_ttl` cookie.
- **A WAF signature hit:** one full step over base (`base + 1`, i.e. +4 bits
  = 16x, capped at `max`).
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

### Measured solve times and recommended values

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
- **`max_difficulty: 6`** (the default) for anomaly escalation. `6.5` and up
  is effectively a soft deny: a minute of hashing on a phone. Values above 7
  mostly punish real visitors on slow devices.
- Watch `guardian_challenge_solve_seconds` in Prometheus (or the average on
  the dashboard) after changing values: it is the real-world solve time of
  *your* visitors' devices.

::: tip PoW is not a flood defense
PoW only taxes clients that solve the puzzle. A client that farms challenges
without solving them is throttled (60 issuances per IP per minute) and
escalated (see challenge farming above), but a raw flood that never even
follows the challenge redirect is **not** PoW's problem. Put Angie's own rate
limiting in front: see
[Rate limiting](/guide/angie#rate-limiting-volumetric-ddos).
:::

## Loopback and trusted proxies

The sidecar trusts the `X-Guardian-*` headers Angie sets on the subrequest
(client IP, host, cookie). Keep `listen` on loopback so no client can reach it
directly and forge them. To bind a non-loopback address (Angie on another
host), isolate the listener to Angie (private network, firewall, or mTLS) and
set `trusted_proxy: true`, otherwise `guardiand` refuses to start.

## The signing key

`signing_key_file` holds the persistent Ed25519 key that signs PoW JWTs. It is
generated on first run if missing and **never** regenerated on restart, so
restarts don't log clients out and replicas can share it. Retired keys (from
`POST /admin/rotate-key`) are archived in `previous_key_dir` and still
accepted for verification until their tokens expire. Rotation requires a
non-empty `previous_key_dir`; replicas must share both paths and automatically
refresh their verification set when another replica rotates.

## Hot reload

Config edits do not need a restart. After changing `guardian.yaml`, either
signal the daemon or call the admin API:

```bash
# Validate first, then reload (same pattern as nginx/angie -t && reload).
guardiand -config /etc/guardian/guardian.yaml -t
kill -HUP $(pidof guardiand)          # or: systemctl reload guardiand

# Equivalent over the admin API:
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8072/admin/reload
```

Domains, allow/denylists, thresholds, PoW difficulty and TTLs, WAF rules and
model file sets, GeoIP databases, reputation feeds and `log_level` all apply
immediately. Behavioural state survives the reload: active blocks, counters
and issued tokens live in the store, not in the config. A config that fails
validation is rejected and the running config stays active, so a bad edit
cannot take the daemon down.

Not reloadable (fixed at startup, logged as a warning when changed):
`listen`, `admin.listen`, `trusted_proxy`, the `store` block,
`signing_key_file`, `previous_key_dir` and the admin token setup.

WAF rules files, anomaly model artifacts, `.mmdb` databases and file-based
reputation feeds are also watched on disk and reload on change by themselves;
you only need SIGHUP/`/admin/reload` for edits to `guardian.yaml` itself.

## Next steps

- Every field, type, and default: [Configuration Options](/reference/configuration)
- Verified crawlers, GeoIP scoping, and reputation feeds:
  [Bots, GeoIP & Reputation](/guide/bots-ip-intel)
- Full annotated example: [Examples](/examples)
- Suspicion-based challenges: [Train the Anomaly Model](/guide/anomaly)
