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
    pow: { enabled: true, base_difficulty: 5.25 }   # token_ttl inherits 4h
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
any setting to a URI prefix with a `paths` map. Overlays merge in three
levels (defaults, then the domain, then the path), the most specific key wins,
and matching is against the percent-decoded path:

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

See [per-path overrides](/reference/configuration#per-path-overrides-domains-host-paths)
in the reference for the exact matching and inheritance rules.

## Signature rules (waf.keywords)

The signature WAF matches keyword and regex rules against the request line and
headers. Getting from the shipped starter file to a running configuration
takes three explicit steps; none of them happen automatically:

1. **Install a rules file.** The release archive (and the repo) ships
   `deploy/rules-common.yaml`, a commented starter set (dotfile probes,
   path traversal, SQLi heuristics, scanner UAs). The
   [production install recipe](/guide/production#systemd) copies it to
   `/etc/guardian/rules.d/common.yaml`; nothing is auto-discovered from that
   directory, it is just the conventional location.
2. **Point the config at it** and enable matching:

   ```yaml
   defaults:
     waf:
       keywords:
         enabled: true
         rules_file: /etc/guardian/rules.d/common.yaml
   ```
3. **Validate**: `guardiand -config guardian.yaml -t`. A `rules_file` that
   does not exist while `enabled: true` fails fast, at preflight and at
   startup, rather than silently matching nothing.

Inside a rules file, each rule has an `id`, an `action`
(`deny` | `challenge` | `block`), optional `targets` (`path`, `query`, `ua`,
`header:<name>`; default `[path, query]`), optional `methods`, and `keywords`
(case-insensitive literals) and/or `regexes` (Go RE2, linear-time). Rules are
evaluated **in file order and the first match wins**, so put narrow or
terminal rules before broad challenge rules. The `id` does double duty: a hit
is logged and counted as `waf:<id>`, and it is the exact, case-sensitive
selector for per-scope exclusions (below). The starter file documents
every field; the [reference](/reference/configuration#waf-keywords) lists the
exact matching semantics.

Like every `waf` setting, `defaults.waf.keywords` is inherited by **every
domain and path overlay** that does not override it, so the file above applies
to your whole estate, including unknown Hosts that fall back to `defaults`.
Scoping works three ways:

- Point a domain (or path overlay) at a **different file** with its own
  `rules_file`, e.g. an API set without challenge-action heuristics (which
  degrade to deny where PoW is off).
- Turn matching off for a scope with `enabled: false`.
- Disable **individual rules** for a scope with `disabled_rule_ids`, without
  copying the file.

### Per-scope rule exclusions (`disabled_rule_ids`)

A shared rules file rarely fits every host exactly: the starter set's
`wp-probe` rule is right on non-WordPress hosts and wrong on a real WordPress
domain. Instead of maintaining a diverging copy of the file for one exception,
list the rule's exact `id` in that scope's `disabled_rule_ids`:

```yaml
defaults:
  waf:
    keywords:
      enabled: true
      rules_file: /etc/guardian/rules.d/common.yaml

domains:
  wordpress.example.com:
    waf:
      keywords:
        disabled_rule_ids: [ wp-probe ]
```

A disabled rule is removed from evaluation for that resolved scope only; the
remaining rules keep their file order, so the next matching rule still decides
the request. Like every list in the overlay model, the field replaces
wholesale: an omitted `disabled_rule_ids` inherits the parent's resolved list,
an explicit `[]` clears inherited exclusions, and a non-empty list replaces
the inherited one (re-list inherited IDs to keep them). The effective sets are
precompiled at startup/reload, so exclusions add no per-request work.

Validation is deliberately strict, so a typo can never silently leave a
dangerous rule enabled: empty, whitespace-only or duplicate entries, an
exclusion list with no effective `rules_file` (even while `enabled: false`),
and any ID absent from the scope's effective rules file are all rejected at
`guardiand -t`, startup and reload, with the error naming the scope, the file
and the unknown ID.

The [examples page](/examples#signature-rules-one-starter-file-scoped-per-domain)
has a complete copyable config combining a shared file, per-domain exclusions,
a domain-specific file and a fully disabled scope, and
[`GET /admin/config`](/reference/admin-api#get-admin-config) shows every
scope's effective `rules_file` and exclusions together.

Rules files hot-reload two ways: they are watched on disk (edits apply within
seconds, no signal needed), and a SIGHUP/`/admin/reload` re-reads
`guardian.yaml` including any changed `rules_file` paths. A file that fails to
parse, or exceeds the 8 MiB bound, keeps the previous rules active; only a
cold start hard-fails on a bad file. A watched update that removes or renames
a rule ID some scope still excludes is rejected the same way, so a renamed
formerly-disabled rule can never become active silently. To intentionally
delete a disabled rule, first remove its ID from `guardian.yaml` and reload
successfully, then remove the rule from the watched file.

## Validating a config

Validate a config without starting the daemon with `-t` (like `angie -t`). It
loads and validates the file (YAML syntax, unknown fields, and semantic
checks) plus every startup-required local artifact: WAF rules, anomaly models,
GeoIP databases, and file-based reputation feeds. Listener `host:port` syntax
and the non-loopback admin-token requirement are checked here too, so a config
cannot pass preflight and then fail that policy during restart. It then exits:
`0` and `ok`
when valid, `1` and the reason when not. Remote URL feeds remain non-blocking.

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
  pays exactly `base_difficulty`, once, then rides a `token_ttl` cookie. The
  token lifetime must be at least one second and at most seven days.
- **A WAF signature hit:** one full step over base (`base + 1`, i.e. +4 bits
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
- **`max_difficulty: 6`** (the default) for all escalation. `6.5` and up
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
accepted only for bounded, pre-rotation token lifetimes (at most seven days).
Expired archives may remain on disk, but they are omitted from the active
verification set after that horizon.
Rotation requires a non-empty `previous_key_dir`; replicas must share both
paths and automatically refresh their verification set when another replica
rotates.

## Hot reload

Config edits do not need a restart. After changing `guardian.yaml`, either
signal the daemon or call the admin API:

```bash
# Validate config and all startup-required local artifacts first, then reload.
guardiand -config /etc/guardian/guardian.yaml -t
kill -HUP $(pidof guardiand)          # or: systemctl reload guardiand

# Equivalent over the admin API:
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8072/admin/reload
```

Domains, allow/denylists, thresholds, PoW difficulty and TTLs, WAF rules and
model file sets, GeoIP databases, reputation feeds and `log_level` all apply
immediately. Behavioural state survives the reload: active blocks, counters,
issued/spent challenge records, and bot verdicts live in the store; signed
tokens remain client cookies. A config that fails
validation is rejected and the running config stays active, so a bad edit
cannot take the daemon down.

Not reloadable (fixed at startup; a reload that changes one is rejected):
`listen`, `admin.listen`, `trusted_proxy`, the `store` block,
`signing_key_file`, `previous_key_dir`, `admin.recent_size`, and the admin
token/dashboard setup.

WAF rules files, anomaly model artifacts, `.mmdb` databases and file-based
reputation feeds are also watched on disk and reload on change by themselves;
you only need SIGHUP/`/admin/reload` for edits to `guardian.yaml` itself. Reads
are bounded to prevent an accidental or compromised artifact publisher from
exhausting daemon memory: `guardian.yaml` 4 MiB, WAF rules 8 MiB, and anomaly
models plus reputation feeds/caches 64 MiB each. An oversized hot update is
rejected while the last-good artifact remains active.

## Next steps

- Every field, type, and default: [Configuration Options](/reference/configuration)
- Verified crawlers, GeoIP scoping, and reputation feeds:
  [Bots, GeoIP & Reputation](/guide/bots-ip-intel)
- Full annotated example: [Examples](/examples)
- Suspicion-based challenges: [Train the Anomaly Model](/guide/anomaly)
