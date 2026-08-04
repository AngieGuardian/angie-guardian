# Metrics

Everything guardiand exports on `GET /metrics` (the [admin
listener](/reference/admin-api); no token needed unless
[`admin.metrics_auth`](/reference/configuration#admin) is set), in the Prometheus text
format under the `guardian_` namespace. The standard Go runtime and process
collectors are registered too, so GC, goroutine and RSS panels come for free.

Import `deploy/grafana-dashboard.json` for a ready-made dashboard over these
series.

## Decisions

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_decisions_total` | counter | `action`, `reason`, `domain` | Every pipeline decision. A WAF allow rule increments `action="allow", reason="waf"`; its rule ID does not enter the bounded label. |
| `guardian_evaluate_seconds` | histogram | | End-to-end `Evaluate()` latency, i.e. the auth hot path minus HTTP overhead. |

Label values are bounded by construction:

- `action` is `allow`, `challenge`, `refuse` or `deny`. `refuse` means Guardian
  withheld a challenge after classifying the request as unable to complete it
  (typically an anonymous favicon fetch, an `<img>`, or an API client), so it is
  neither a block nor a puzzle anyone was asked to solve; alerts that count
  challenges should exclude it, or an unsatisfiable refusal reads as a
  challenge storm.

  The `reason` still names the policy that asked for the challenge. Only a
  token-failure reason is replaced (by `pow:unchallengeable`), so a WAF rule,
  the anomaly scorer, GeoIP or a reputation feed that selects a request
  classified as unable to solve a puzzle is recorded as `refuse` while keeping
  `waf`, `anomaly`, `geo` or `reputation`. Reason-based dashboards therefore
  keep counting it.
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
| `guardian_challenges_total` | counter | `outcome` | Challenge lifecycle events: `issued`, `solved`, `failed` (wrong nonce, expired, replayed, bound to a different IP, or an internal error; the per-reason split is `guardian_challenge_failures_total` below, and the per-attempt detail is [`/admin/decisions?action=redeem_fail`](/reference/admin-api#decisions)), `escalated` (issued above base difficulty to a [challenge farmer](/guide/configuration#base-difficulty-and-max-difficulty)), `farm_detected` (issued to a farmer whose escalation is pinned at the ceiling; also reported as a `challenge_farm` behaviour event, blocking past its [threshold](/reference/configuration#waf-ip-behaviour), default `80/h`), `subresource_refused` (a challenge request whose `Sec-Fetch-Dest` names a subresource, which cannot run the interstitial: refused with a `403` rather than issued a challenge it would be scored for abandoning), `accept_heuristic_refused` (a challenge request carrying no Fetch metadata whose `Accept` names neither `text/html` nor `text/*`, so it is very unlikely to be a navigation: refused with a plain `403` for the same reason, `no-store` like every other refusal (a cacheable variant was measured and dropped, since it did not reduce the repeated requests on the path it was aimed at). A behavioural heuristic rather than proof, since `*/*` formally accepts HTML, so it is consulted only when `Sec-Fetch-Dest` and `Sec-Fetch-Mode` say nothing; the browser's own favicon service is what this exists for. Unlike the rest, it also applies over plain HTTP, and see [Troubleshooting](/guide/troubleshooting#legitimate-visitors-get-challenged-or-blocked) for the compatibility tradeoff that comes with it), `frame_unscored` (a framed navigation whose Fetch metadata cannot establish that the interstitial will render: still issued a challenge and still escalated, on a separate counter, but never reported as `challenge_farm`, since blocking on it would let any page drive arbitrary visitors into a block by framing a protected URL. Ambiguous by construction, so it also covers your own embedded SSO callbacks, whose redirect chain reports `cross-site`; see [Troubleshooting](/guide/troubleshooting#legitimate-visitors-get-challenged-or-blocked) before reading a rate here as an attack), `solve_time_implausible` (a redemption whose client-reported `elapsed_ms` exceeded the daemon's own issue-to-redeem measurement plus a clock-skew allowance, so it could not be true: the solve still succeeds, the reported time is discarded rather than averaged into `guardian_challenge_solve_seconds`), plus the stateless outcomes described below. |
| `guardian_challenge_failures_total` | counter | `reason` | The per-reason split behind `guardian_challenges_total{outcome="failed"}`, which it sums to by construction. A closed set: `bad_solution` (nonce misses the difficulty; at volume, a bot posting junk, scored and blocked on its own), `binding_mismatch` (the client's IP changed between issue and redeem, usually a VPN or mobile handover), `unknown_challenge` (expired, replayed or forged ID), `too_fast` / `nojs_disabled` (no-JS path), `internal_error` (Guardian's own store or key trouble, alerted as `GuardianRedeemInternalErrors`; see [Troubleshooting](/guide/troubleshooting#a-solved-challenge-is-rejected-challenge-verification-failed)). Deliberately a sibling counter rather than a `reason` label on `challenges_total`: adding a label there would reset the identity of every outcome series in existing dashboards and alerts. |
| `guardian_challenge_solve_seconds` | histogram | `domain` | Client-reported solve time, for tuning `base_difficulty`. Hashing only: no-JS redemptions hashed nothing and are never observed, and a reported value that could not be true (longer than the daemon's own issue-to-redeem measurement, plus a clock-skew allowance) is dropped and counted as `solve_time_implausible` instead. Unauthenticated: a client can under-report. For per-request attribution (which host, path, IP and User-Agent paid what, at which difficulty) read [`/admin/decisions?action=solve`](/reference/admin-api#decisions). |
| `guardian_anomaly_score` | histogram | `domain` | Distribution of scores for requests that reach the anomaly stage, for tuning `challenge_at` / `deny_at`. Earlier terminal decisions and requests with valid PoW tokens are not observed. |
| `guardian_anomaly_baseline_selections_total` | counter | `domain`, `level` | Selected baseline specificity: `exact`, `route`, `method`, domain-wide fallback, or `missing`. |
| `guardian_anomaly_baseline_misses_total` | counter | `domain` | Alert-friendly mirror of the `missing` selection level: requests that reached an enabled anomaly stage but had no domain baseline, so that stage made no decision. |
| `guardian_anomaly_model_trained_timestamp_seconds` | gauge | `model` | Unix time the loaded model artifact was trained, set on load and every hot swap. A stalling value means retraining or promotion is silently failing; `deploy/alerts.yaml` ships `GuardianAnomalyModelStale` (warns after 14 days, two missed weekly runs). |

## Blocking and bots

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_blocks_placed_total` | counter | `reason` | Behavioural IP blocks placed, by reason category (threshold blocks carry their event type, e.g. `rule_match`, `pow_fail` or `challenge_farm`). |
| `guardian_bot_verifications_total` | counter | `bot`, `result` | [Verified-bot](/reference/configuration#verified-bots) rDNS checks by bot name and result: `verified`, `spoof` (definitively failed, an impostor), or `error` (transient DNS failure, falls through unverified). |

## IP reputation feeds

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_feed_entries` | gauge | `feed` | Loaded entries per [reputation feed](/reference/configuration#reputation). A feed stuck at `0` never loaded. |
| `guardian_feed_refresh_total` | counter | `feed`, `status` | Refresh attempts, `status` is `ok` or `error`. A failed refresh keeps the last good list. |

## Store

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardian_store_ops_total` | counter | `backend`, `op`, `status` | Store operations by op (`get`, `set`, `cas`, `incr`, `delete`, `scan`, `block_index_scan`, `posture_set`, `posture_delete`, `posture_max`) and status (`ok` or `error`). A rising `error` rate on a Redis/Valkey backend usually means connectivity trouble; a failing stage abstains while later stages continue. |
| `guardian_store_op_seconds` | histogram | `backend`, `op` | Store operation latency. On a durable embedded backend with `store.sync: true`, watch `set` and `cas`: they pay an fsync. |
| `guardian_store_up` | gauge | `backend` | `1` = the store answered the last write/read-back probe, `0` = Guardian is failing open. **The single most important series to alert on**: at `0` the process is still serving every request while single-spend, scoreboards and blocks have quietly stopped working, and `/healthz` stays green. `deploy/alerts.yaml` ships the rule. |
| `guardian_store_probe_total` | counter | `backend`, `status` | Completed store health probes by `status` (`ok`, `error`). A staleness event (a wedged probe loop) drives `guardian_store_up` to `0` without incrementing this, since no probe finished. |
| `guardian_store_clock_skew_seconds` | gauge | `backend` | Store server clock minus local clock, probed on remote backends (redis/valkey) each health round. Skew beyond a counter window (60s) silently voids deadline-based counter flushes; the daemon logs a warning above 10s. Embedded backends share the process clock and never emit it. |

Every `store_*` series carries `backend`, so a mixed fleet (or one part-way
through a backend migration) can group by it directly rather than joining
against another metric. `store.backend` is startup-only, so the value is
constant for the process: it adds one label value per target, not a multiplier
on the series count.

Probe traffic runs against the raw store, so it never appears in
`guardian_store_ops_total` or `guardian_store_op_seconds`.

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
| `guardian_unproxied_rejects_total` | counter | | Guard requests rejected by [`require_proxied`](/reference/configuration) for missing `X-Guardian-*` headers. Nonzero means something reaches the guard port without going through Angie. |

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
# Non-allow decision rate by category, per domain (denies, challenges, refusals):
sum by (reason, domain) (rate(guardian_decisions_total{action!="allow"}[5m]))

# Auth hot-path latency, p99:
histogram_quantile(0.99, rate(guardian_evaluate_seconds_bucket[5m]))

# How long do real clients take to solve the PoW?
histogram_quantile(0.90, sum by (le) (rate(guardian_challenge_solve_seconds_bucket[15m])))

# ...and which domain is asking too much of its visitors:
histogram_quantile(0.90,
  sum by (le, domain) (rate(guardian_challenge_solve_seconds_bucket[15m])))

# Challenge farming pressure (escalated issuance share):
rate(guardian_challenges_total{outcome="escalated"}[15m])
  / ignoring(outcome) rate(guardian_challenges_total{outcome="issued"}[15m])
```

For a "right now" rollup without a Prometheus server, use
[`GET /admin/stats`](/reference/admin-api#get-admin-stats).
