# Attack Mode

Guardian's per-client defenses (PoW escalation, the behavioural scoreboard,
anomaly scoring) react to individual bad actors. Attack mode reacts to
**aggregate** conditions: a distributed flood where each client stays under
the per-client thresholds, or a surge of new clients that would saturate the
store. When aggregate signals cross a threshold, Guardian raises PoW
difficulty fleet-wide, can force challenges on every unvouched request, and
switches challenge issuance to a store-free path so the flood stops writing to
the store.

It is off unless configured. The whole feature lives under the top-level
`attack_mode:` key and is hot-reloadable.

## The posture

There are three levels: **normal**, **elevated**, and **attack**. A background
aggregator measures a small set of signals over a sliding window (5s buckets)
and moves the posture with hysteresis and a minimum dwell time, so it cannot
flap on threshold-straddling load.

| Signal | Enters elevated | Enters attack |
|---|---|---|
| challenge issuance rate | `> challenge_rate` | `> attack_challenge_rate` **and** solve ratio `< min_solve_ratio` |
| global request rate | `> request_rate` (omit to disable) | n/a |
| store error ratio | `> store_error_ratio` | `> 3 x store_error_ratio` |
| store slow-op ratio | `> store_slow_ratio` | n/a |

The solve-ratio qualifier is what separates a **flash crowd** (real browsers,
almost all challenges solved) from a **bot flood** (issuance high, almost
nothing solved). A legitimate traffic spike stays at most elevated; only a
low-solve flood reaches attack.

The store signals are the "we are drowning" catch-all: if the flood shape is
unforeseen but the store is visibly struggling, the posture rises and the
store-free issuance path kicks in *before* the store collapses and forces
[fail-open](/guide/threat-model#fail-open-by-design).

Exit is one step at a time, and only after every entry signal has stayed below
half its threshold for `min_dwell`.

## Effects

Each effect is independently configurable and, except the difficulty raise,
applies only at level **attack**.

### Fleet-wide difficulty raise

The raise shifts a domain's whole `[base, max]` difficulty window up by a fixed
number of bits (configured on the 1..8 quarter-step scale: each 0.25 = 1 bit),
clamped to `difficulty_cap`. Elevated adds `elevated_difficulty_raise` (default
0.5 = +2 bits); attack adds `attack_difficulty_raise` (default 1.0 = +4 bits).
Per-IP escalation and anomaly scaling still operate, inside the shifted window.

That numeric bit window applies to the default SHA-256 algorithm. An Argon2id
domain never wraps its memory-hard computation in a leading-zero search:
elevated posture selects `argon2id.max_iterations`, and attack posture selects
`argon2id.attack_iterations_cap`. See [proof-of-work algorithms](/guide/pow-algorithms).

::: tip Existing tokens are never invalidated
The raise applies only to **new** challenges. A visitor who already solved and
holds a token keeps passing at the difficulty they solved for. Raising the
verification floor would re-challenge every current visitor at once, a
stampede at the worst possible moment, so Guardian deliberately does not.
:::

### Force challenges (`force_always`, default on)

At attack, a domain running `pow.mode: suspicion` behaves as `always`: every
unvouched request is challenged, not just anomaly-flagged ones. Elevated keeps
suspicion mode, so a brief spike never walls a suspicion-mode site.

### Stateless issuance (`stateless_issuance`, default on)

Normally each issued challenge writes an issuance record to the store. On the
reference machine, that path sustains ~152k/s with `pebble` async, ~56k/s with
`buntdb` async, or ~35k/s with `pebble` fsync-per-write (see
[load testing](/guide/load-testing)). Under attack, Guardian issues
**stateless** challenges instead: an HMAC-signed, self-authenticating ID
(`s1.` for SHA-256, `s2.` for Argon2id) that carries its own state, so issuance
performs no store write. Single-spend moves to redeem time, keyed by the solved
challenge and
written only after the client has actually paid the proof of work, so the only
store write an attacker can induce costs them real compute first.

This format is also Guardian's availability fallback outside Attack: if the
ordinary stateful issuance write fails, the visitor receives a stateless
challenge instead of a `503`. The fallback is counted as both
`issued_stateless` and `issued_stateless_fallback`, so an unexpected store
outage remains visible even though challenge service stays available.

Redemption accepts both stateless formats, so a challenge issued moments before
or after a posture or algorithm flip still redeems and a rolling fleet restart
is safe.
Instances sharing the signing key verify each other's stateless challenges:
file-backed issuers refresh the shared key set before signing, still-live
retired secrets keep challenges redeemable during a rolling rotation, and JWT
verification also refreshes before accepting cached or signature-valid tokens,
so a peer's retired key cannot be kept alive by an old-key cache hit.

The shared store CAS is the fleet-wide single-spend authority. If that write
fails, Guardian mints the token fail-open and records the challenge in a
bounded local replay cache: the same replica rejects a replay, but another
replica cannot see that local claim until the shared store recovers. Monitor
`spent_cas_failed`; strict cross-replica replay prevention requires an
available shared store.

### Scoreboard tightening (`scoreboard_factor`, default 1.0)

At attack, behavioural thresholds are multiplied by this factor (0 < f <= 1),
so fewer bad events place a block sooner.

## Load-shedding (`max_inflight`, default 0 = off)

Independently of the posture, `max_inflight` bounds concurrent auth
evaluations. The shed path performs no store or DNS I/O, but it still applies
the local terminal checks that normally precede token acceptance: static
deny/block state, deny reputation/GeoIP policy, verified-bot spoof policy,
honeypots, and WAF rules. A clean token holder passes only after those
checks clear and the in-process block mirror can prove the client is not
blocked without consulting the store. Otherwise the request gets a fast `503`
with `Retry-After`; WAF/deny hits keep their deny response.

The mirror qualification matters operationally: a seeded, complete
authoritative mirror can fast-pass a clean token, but an unseeded or
capacity-incomplete mirror (or a `read_through` mirror such as Redis in `auto`
mode) cannot prove a miss without a store read, so Guardian sheds instead of
risking a token bypassing a block held only in the store. That is the middle
ground between fail-open (continuing into the vhost's original handler) and
silently weakening policy under pressure. Set the bound to a few times your
core count and test it with your chosen mirror mode.

::: tip Fast 403 optimization under volumetric attack
When handling massive volumetric 403/deny floods, operators can uncomment `return 403;` inside `location @guardian_denied` in `angie-guardian.conf` to serve a bare 403 immediately from Angie memory without proxying `/denied` to the sidecar. See [Angie integration](/guide/angie#volumetric-403-floods-and-the-fast-403-optimization).
:::

## Fleet coordination

The detector is per-instance: each replica measures its own share of traffic.
With `share_posture: true` (default) each instance publishes its level as an
expiring per-replica vote once per tick and adopts the maximum of its local
level and every live peer vote, so replicas move together and one quiet
replica cannot overwrite a higher vote from an attacking peer. Votes live in a
dedicated map, embedded key range or two fixed Redis sorted sets (a tick never
scans challenge, counter, bot-verification or block keys), the bounded
coordination runs off the hot path, and a store outage degrades it to
local-only (the store failure is itself a trigger).

Thresholds are therefore **per instance**. With N replicas behind a balancer,
each sees roughly 1/N of the traffic; size `challenge_rate` and
`attack_challenge_rate` to your per-instance share of the fleet rate, not the
fleet total.

## Configuration

```yaml
attack_mode:
  enabled: true
  window: 30s                 # sliding window, 5s buckets (10s..10m)
  min_dwell: 60s              # minimum time at a level before decaying (>= window)
  share_posture: true
  signals:
    challenge_rate: 200/s
    attack_challenge_rate: 1000/s   # >= challenge_rate
    min_solve_ratio: 0.2
    # request_rate is omitted, which disables it. A rate cannot be written as
    # "0/s" (a zero count is rejected); omit a signal from the block to disable
    # it. A fully-omitted signals block gets all the defaults instead.
    store_error_ratio: 0.05
    store_slow_ratio: 0.25
  effects:
    elevated_difficulty_raise: 0.5  # quarter steps (+2 bits)
    attack_difficulty_raise: 1.0    # (+4 bits)
    difficulty_cap: 7.0             # 28 bits
    force_always: true
    stateless_issuance: true
    scoreboard_factor: 1.0
    max_inflight: 0                 # load-shed bound; 0 = off
```

The compile-time challenge issuance rate limit is also now configurable, as
`pow.issuance_rate_limit` (default `60/min`, inherited by domains and path
overlays).

See [Configuration Options → attack_mode](/reference/configuration#attack-mode)
for every field and constraint.

## Observability

`GET /admin/attack` reports the level, since, reason, pin state, current window
signal rates and active effects. `POST /admin/attack` with
`{"level": "normal|elevated|attack|auto"}` pins or unpins the posture; `auto`
returns to automatic detection, and pinning `normal` is a kill switch for that
instance. A pin ignores peer adoption and immediately clears that instance's
automatic shared vote; pin every replica when you need a fleet-wide manual
override. The dashboard shows a banner whenever the posture is above normal.

Metrics: `guardian_attack_mode` (0/1/2), `guardian_attack_extra_bits`,
`guardian_attack_mode_transitions_total{to,reason}`,
`guardian_attack_mode_signal{signal}`, and `guardian_shed_total{outcome}`.
Alert on `guardian_attack_mode >= 1`.

## Rollout

Enable with the defaults and watch `guardian_attack_mode_signal` for a week to
learn your real ceilings before tightening. Entering attack does not invalidate
tokens, so the first time it trips, current visitors keep browsing while new
clients pay more. The feature is fully off when the section is absent.

Before relying on it during a live event, measure the deployment with the
[DDoS drill](/guide/ddos-drill). During an incident, use the bounded pin,
verification, and rollback sequence in the
[DDoS incident runbook](/guide/ddos-incident-runbook).
