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

Normally each issued challenge writes an issuance record to the store, and
embedded bbolt's single fsync'd writer tops out around 4.5k/s (see
[load testing](/guide/load-testing)). Under attack, Guardian issues
**stateless** challenges instead: an HMAC-signed, self-authenticating ID
(`s1.` prefix) that carries its own state, so issuance performs no store
write. Measured, that lifts the bbolt issuance ceiling to ~44k/s, an order
of magnitude. Single-spend moves to redeem time, keyed by the solved challenge and
written only after the client has actually paid the proof of work, so the only
store write an attacker can induce costs them real compute first.

Redemption accepts both the stateless and the classic formats forever, so a
challenge issued moments before or after a posture flip still redeems, and a
rolling fleet restart is safe. Instances that share the signing key verify
each other's stateless challenges.

### Scoreboard tightening (`scoreboard_factor`, default 1.0)

At attack, behavioural thresholds are multiplied by this factor (0 < f <= 1),
so fewer bad events place a block sooner.

## Load-shedding (`max_inflight`, default 0 = off)

Independently of the posture, `max_inflight` bounds concurrent auth
evaluations. When the daemon is saturated past that bound, a client holding a
valid token still passes (a cheap stateless signature check, no store I/O) and
everyone else gets a fast `503` with `Retry-After`. This is the middle ground
between fail-open (dump the flood on the backend) and fail-closed (take the
site down): under overload the backend sees only vouched traffic. Set it to a
few times your core count.

## Fleet coordination

The detector is per-instance: each replica measures its own share of traffic.
With `share_posture: true` (default) each instance publishes its level through
the shared store once per tick and adopts the maximum of its local level and
any peer's, so replicas move together. This is one store op per tick, off the
hot path; if the store is down the detection degrades to local-only (and the
store failure is itself a trigger).

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
returns to automatic detection, and pinning `normal` is a kill switch. The
dashboard shows a banner whenever the posture is above normal.

Metrics: `guardian_attack_mode` (0/1/2), `guardian_attack_extra_bits`,
`guardian_attack_mode_transitions_total{to,reason}`,
`guardian_attack_mode_signal{signal}`, and `guardian_shed_total{outcome}`.
Alert on `guardian_attack_mode >= 1`.

## Rollout

Enable with the defaults and watch `guardian_attack_mode_signal` for a week to
learn your real ceilings before tightening. Entering attack does not invalidate
tokens, so the first time it trips, current visitors keep browsing while new
clients pay more. The feature is fully off when the section is absent.
