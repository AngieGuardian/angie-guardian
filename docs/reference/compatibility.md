# Compatibility & Versioning

Guardian follows [semantic versioning](https://semver.org/). This page states
exactly what a version number promises, so you can upgrade with confidence and
know what a major bump may change.

Version numbers use `MAJOR.MINOR.PATCH`: patch releases contain compatible
fixes, minor releases may add compatible functionality, and major releases may
contain breaking changes. The guarantees below apply from 1.0 onward.

## What the 1.x line guarantees

Within a `1.x` line, these do not change in a breaking way (new fields,
routes, metrics and values may be *added*, but existing ones keep working):

- **The `guardian.yaml` schema.** Field names, nesting, types and the meaning
  of values are stable. A config that loads on `1.0` loads on any `1.x`.
- **The admin API.** Route paths, methods, and the JSON request/response
  shapes of the `/admin/*`, `/metrics`, `/healthz` and `/readyz` endpoints.
  `/healthz` is liveness only and never consults the store; `/readyz` is the
  one that reports store readiness.
- **Prometheus metric names and labels.** Renaming a metric or a label breaks
  every dashboard and alert built on it, so these are frozen. New metrics and
  new label values may appear; existing series keep their identity.
  Every `store_*` series carries a `backend` label, so they can be grouped by
  backend without joining against another metric.
- **The PoW token format and signing.** A token minted by one `1.x` verifies
  on any other `1.x` sharing the key, so a rolling upgrade never logs clients
  out. Signing-key and rotation file layout is stable.
- **The on-disk / store key format.** A `1.(x+1)` daemon reads a store
  (buntdb/pebble data or redis/valkey keyspace) written by `1.x`: blocks, spent
  challenges and cached verdicts survive the upgrade. Store key prefixes
  (`block:`, `challenge:`, `chesc:`, `botdns:`) are part of this contract.
- **Angie integration.** The `X-Guardian-*` header contract and the semantics
  of [`deploy/angie-guardian.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian.conf)
  plus
  [`deploy/angie-guardian-location.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian-location.conf)
  (auth subrequest, the 401/403 divert, and fail-open continuation of the
  original content handler) stay compatible.
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

## What a major release may change

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
