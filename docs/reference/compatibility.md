# Compatibility & Versioning

Guardian follows [semantic versioning](https://semver.org/). This page states
exactly what a version number promises, so you can upgrade with confidence and
know what a major bump may change.

::: warning Pre-1.0
Until 1.0, any release may change any of the surfaces below. The policy here
describes what will hold **from 1.0 onward**; it is published now so the naming
is settled before the freeze.
:::

## What a stable (1.x) release guarantees

Within a `1.x` line, these do not change in a breaking way — new fields,
routes, metrics and values may be *added*, but existing ones keep working:

- **The `guardian.yaml` schema.** Field names, nesting, types and the meaning
  of values are stable. A config that loads on `1.0` loads on any `1.x`.
- **The admin API.** Route paths, methods, and the JSON request/response
  shapes of the `/admin/*`, `/metrics` and `/healthz` endpoints.
- **Prometheus metric names and labels.** Renaming a metric or a label breaks
  every dashboard and alert built on it, so these are frozen. New metrics and
  new label values may appear; existing series keep their identity.
- **The PoW token format and signing.** A token minted by one `1.x` verifies
  on any other `1.x` sharing the key, so a rolling upgrade never logs clients
  out. Signing-key and rotation file layout is stable.
- **The on-disk / store key format.** A `1.(x+1)` daemon reads a store
  (bbolt file or redis/valkey keyspace) written by `1.x`: blocks, spent
  challenges and cached verdicts survive the upgrade. Store key prefixes
  (`block:`, `challenge:`, `chesc:`, `botdns:`) are part of this contract.
- **Angie integration.** The `X-Guardian-*` header contract and the
  `deploy/angie-guardian.conf` snippet semantics (auth subrequest, the 401/403
  divert, the fail-open bypass) stay compatible.
- **CLI flags** of `guardiand` and the signal contract (`SIGHUP` reload,
  `SIGINT`/`SIGTERM` shutdown, sd_notify).

## What is *not* covered

These may change in any release, including a patch:

- **Detection behaviour and defaults.** Rule sets, anomaly scoring, default
  difficulties and thresholds are tuned over time. Your explicit config is
  honoured; the *unspecified* defaults may shift to improve protection. Pin the
  values you care about.
- **Log line wording and structure.** Logs are for humans and ad-hoc tooling,
  not a stable API. Use `/metrics` and the admin API for anything you
  automate.
- **The starter `rules-common.yaml`.** It's a template to copy and tune, not a
  frozen interface.
- **Internal Go packages.** Guardian is a daemon, not a library; import paths
  under `core/…` carry no compatibility promise.
- **The dashboard HTML/JS and the challenge interstitial markup.**

## What a major (2.0) release may change

A breaking change to anything in the guaranteed list ships only in a major
version, with an upgrade note. Where practical, a removed or renamed config
field is honoured as a deprecated alias for one major cycle with a startup
warning, rather than failing to load outright.

## Upgrading

- **Patch / minor (`1.x.y` → `1.x.z` or `1.x` → `1.(x+1)`):** drop-in. Replace
  the binary or image and restart (or `systemctl reload` for a config-only
  change). The store, keys and issued tokens carry over.
- **Multi-instance:** upgrade replicas one at a time. Because the token and
  store formats are stable within `1.x`, mixed-version replicas interoperate
  during the rollout.
- **Major (`1.x` → `2.0`):** read the release notes first; there will be an
  explicit migration section.

## Notes on the naming (settled at 1.0)

A deliberate pass over the config surface before the freeze kept it as-is: it
is uniform `snake_case`, TTLs are consistently `*_ttl`, feature toggles are
consistently `enabled`, and the grouping (`waf.*`, `pow.*`, `geo.*`,
`store.*`, `admin.*`) matches how operators reason about it. Two names were
weighed and deliberately kept: `pow` (short, and the term of art) over a
spelled-out `proof_of_work`, and `ip_behaviour` (British spelling, consistent
with the rest of the prose) — renaming either would churn a stable, clear name
for no real gain.
