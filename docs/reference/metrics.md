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
| `guardian_challenges_total` | counter | `outcome` | Challenge lifecycle events: `issued`, `solved`, `failed` (wrong nonce, expired, or replayed), and `escalated` (issued above base difficulty to a [challenge farmer](/guide/configuration#base-difficulty-and-max-difficulty)). |
| `guardian_challenge_solve_seconds` | histogram | | Client-reported solve time, for tuning `base_difficulty`. |
| `guardian_anomaly_score` | histogram | `domain` | Distribution of anomaly scores, for tuning `challenge_at` / `deny_at`. |

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
| `guardian_store_ops_total` | counter | `op`, `status` | Store operations by op (`get`, `set`, `cas`, `incr`, `delete`, `scan`) and status (`ok` or `error`). A rising `error` rate on a Redis/Valkey backend usually means connectivity trouble; the pipeline fails open. |
| `guardian_store_op_seconds` | histogram | `op` | Store operation latency. On bbolt, watch `set` and `cas`: they pay an fsync. |

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
