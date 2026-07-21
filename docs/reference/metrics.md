# Metrics

Everything guardiand exports on `GET /metrics` (the [admin
listener](/reference/admin-api), no token needed), in the Prometheus text
format under the `guardian_` namespace. The standard Go runtime and process
collectors are registered too, so GC, goroutine and RSS panels come for free.

Import `deploy/grafana-dashboard.json` for a ready-made dashboard over these
series.

## Decisions

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_decisions_total` | counter | `action`, `reason`, `domain` | Every pipeline decision. |
| `guardian_evaluate_seconds` | histogram | | End-to-end `Evaluate()` latency, i.e. the auth hot path minus HTTP overhead. |

Label values are bounded by construction:

- `action` is `allow`, `challenge` or `deny`.
- `reason` is the decision reason collapsed to its leading category
  (`waf:dotfile-probe` counts as `waf`), one of: `default`, `allowlist`,
  `denylist`, `verified_bot`, `bot_spoof`, `geo`, `reputation`,
  `behaviour_block`, `waf`, `honeypot`, `anomaly`, `pow`.
- `domain` is the normalized key of a configured domain, or `default` for any
  other Host. The raw Host header is client-controlled and unbounded, so it is
  never used as a label value directly.

## Proof of work

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_challenges_total` | counter | `outcome` | Challenge lifecycle events: `issued`, `solved`, `failed` (wrong nonce, expired, or replayed), `escalated` (issued above base difficulty to a [challenge farmer](/guide/configuration#base-difficulty-and-max-difficulty)), plus the stateless outcomes described below. |
| `guardian_challenge_solve_seconds` | histogram | | Client-reported solve time, for tuning `base_difficulty`. |
| `guardian_anomaly_score` | histogram | `domain` | Distribution of scores for requests that reach the anomaly stage, for tuning `challenge_at` / `deny_at`. Earlier terminal decisions and requests with valid PoW tokens are not observed. |

## Blocking and bots

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_blocks_placed_total` | counter | `reason` | Behavioural IP blocks placed, by reason category. |
| `guardian_bot_verifications_total` | counter | `bot`, `result` | [Verified-bot](/reference/configuration#verified-bots) rDNS checks by bot name and result: `verified`, `spoof` (definitively failed, an impostor), or `error` (transient DNS failure, falls through unverified). |

## IP reputation feeds

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_feed_entries` | gauge | `feed` | Loaded entries per [reputation feed](/reference/configuration#reputation). A feed stuck at `0` never loaded. |
| `guardian_feed_refresh_total` | counter | `feed`, `status` | Refresh attempts, `status` is `ok` or `error`. A failed refresh keeps the last good list. |

## Store

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_store_ops_total` | counter | `op`, `status` | Store operations by op (`get`, `set`, `cas`, `incr`, `delete`, `scan`, `block_index_scan`, `posture_set`, `posture_delete`, `posture_max`) and status (`ok` or `error`). A rising `error` rate on a Redis/Valkey backend usually means connectivity trouble; a failing stage abstains while later stages continue. |
| `guardian_store_op_seconds` | histogram | `op` | Store operation latency. On a durable embedded backend with `store.sync: true`, watch `set` and `cas`: they pay an fsync. |

## Block enforcement offload

See the [Block Enforcement Offload](/guide/block-offload) guide.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_block_lookups_total` | counter | `source`, `outcome` | Block lookups by `source` (`mirror`, `store`) and `outcome` (`hit`, `miss`). A healthy authoritative mirror serves almost everything from `mirror`, keeping `store` near zero. |
| `guardian_offload_entries` | gauge | `sink` | Active block entries held per sink (`mirror`, `nftables`). |
| `guardian_offload_ops_total` | counter | `sink`, `op`, `status` | Offload operations by `op` (`add`, `remove`) and `status` (`ok`, `error`, `dropped`). `dropped` means a full mirror or sink queue; enforcement falls back, nothing is lost. |
| `guardian_offload_reconcile_total` | counter | `status` | Reconcile scans, `ok` or `error`. |
| `guardian_offload_reconcile_skipped_total` | counter | `reason` | External-sink replace-all repairs skipped because the indexed snapshot was incomplete (`incomplete_snapshot`) or a concurrent block event made it stale (`concurrent_event`). |
| `guardian_offload_healthy` | gauge | `sink` | `1` = sink enforcing, `0` = degraded to in-daemon enforcement. Alert on `nftables` at `0`. |

## Attack mode

See the [Attack Mode](/guide/attack-mode) guide.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_attack_mode` | gauge | | Current posture: 0 normal, 1 elevated, 2 attack. Alert on `>= 1`. |
| `guardian_attack_extra_bits` | gauge | | Active fleet-wide PoW difficulty raise, in bits. |
| `guardian_attack_mode_transitions_total` | counter | `to`, `reason` | Posture transitions by target level and reason. |
| `guardian_attack_mode_signal` | gauge | `signal` | Current window value per signal (`challenge_rate`, `request_rate`, `solve_ratio`, `store_error_ratio`, `store_slow_ratio`). |
| `guardian_shed_total` | counter | `outcome` | Load-shed decisions under saturation: `pass_token` (a clean token holder admitted after all local terminal checks and an authoritative mirror miss) or `shed` (503'd). |

Stateless behavior adds three outcomes on `guardian_challenges_total`:

- `issued_stateless`: a store-free challenge, counted in addition to `issued`,
  so `issued` remains the full issuance rate and this is its stateless subset.
- `issued_stateless_fallback`: the ordinary stateful issuance write failed and
  Guardian preserved availability by issuing statelessly. It is also included
  in `issued_stateless`.
- `spent_cas_failed`: a stateless token was minted fail-open because the shared
  single-spend write failed. Same-replica replay remains locally guarded, but
  fleet-wide single-spend requires the shared store.

## Useful queries

```
# Deny/challenge rate by category, per domain:
sum by (reason, domain) (rate(guardian_decisions_total{action!="allow"}[5m]))

# Auth hot-path latency, p99:
histogram_quantile(0.99, rate(guardian_evaluate_seconds_bucket[5m]))

# How long do real clients take to solve the PoW?
histogram_quantile(0.90, rate(guardian_challenge_solve_seconds_bucket[15m]))

# Challenge farming pressure (escalated issuance share):
rate(guardian_challenges_total{outcome="escalated"}[15m])
  / ignoring(outcome) rate(guardian_challenges_total{outcome="issued"}[15m])
```

For a "right now" rollup without a Prometheus server, use
[`GET /admin/stats`](/reference/admin-api#get-admin-stats).
